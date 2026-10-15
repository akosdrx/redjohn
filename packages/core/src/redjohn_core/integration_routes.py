"""Authenticated local integration endpoints, separate from frozen v1 DTOs."""

from __future__ import annotations

from contextlib import asynccontextmanager, nullcontext
from typing import Any

from fastapi import Request, Response
from pydantic import BaseModel, ConfigDict, SecretStr

from .errors import RJError, conflict, validation
from .integration_contracts import (
    CatalogModelDTO,
    CodexLoginDTO,
    CodexStatusDTO,
    MemoryConfigDTO,
    NativeToolsDTO,
    NvdConfigDTO,
    ProviderCatalogDTO,
    ProviderCheckDTO,
    ProviderConnectionDTO,
    ProviderListDTO,
)
from .integrations import IntegrationStore
from .memory_config import generate_server_config, memory_public, save_memory
from .model_gateway import gateway_from_settings
from .models import ServiceState, ServiceStatus
from .provider_catalog import read_catalog, refresh_catalog


class ProviderInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = None
    label: str = ""
    provider: str
    model: str
    base_url: str = ""
    api_key: SecretStr | None = None


class ProviderModelsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = None
    base_url: str
    api_key: SecretStr | None = None


class NvdInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    api_key: SecretStr


class MemoryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    openviking_url: str
    openviking_account: str
    openviking_user: str
    openviking_processing_mode: str = ""
    service_api_key: SecretStr | None = None


class MemoryModelsInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    language_base_url: str
    language_model: str
    language_api_key: SecretStr | None = None
    embedding_base_url: str
    embedding_model: str
    embedding_dimension: int = 1536
    embedding_api_key: SecretStr | None = None


class MemorySetupInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Memory language = a saved provider connection + model (routed through the
    # in-engine proxy). Memory embedding = an external OpenAI-compatible endpoint
    # (many LLM providers, e.g. Anthropic, do not serve embeddings, so it is a
    # separate credential).
    provider_connection_id: str
    model: str
    embedding_base_url: str
    embedding_model: str
    embedding_dimension: int = 1536
    embedding_api_key: SecretStr | None = None


def values(body: BaseModel) -> dict[str, Any]:
    return {
        k: v.get_secret_value() if isinstance(v, SecretStr) else v
        for k, v in body.model_dump().items()
        if v is not None
    }


async def ensure_idle(engine: Any) -> None:
    for status in ("starting", "running", "stopping"):
        items, _ = await engine.store.list_runs(cursor=None, limit=1, status=status)
        if items:
            raise conflict("Stop active pentests before changing the model or memory connection.")


def auth_server(engine: Any) -> Any:
    from .codex_gateway import CodexAppServer

    if engine._codex_auth is None:
        engine._codex_auth = CodexAppServer(engine.settings)
    return engine._codex_auth


@asynccontextmanager
async def memory_reconfiguration(engine: Any):
    """Cancel long first-launch downloads before accepting explicit settings.

    The configuration lock serializes request mutations; cancellation prevents
    automatic setup from later overwriting an operator's newly saved choices.
    Cached images/model files remain available for the next attempt.
    """
    restart = engine._auto_memory_enabled
    await engine.cancel_memory_bootstrap()
    try:
        yield
    finally:
        if restart:
            engine.start_memory_bootstrap()


def install_integration_routes(router: Any) -> None:
    from .nvd_settings import public_nvd, save_nvd

    @router.get("/integrations/nvd", response_model=NvdConfigDTO)
    async def nvd_get(request: Request) -> dict[str, Any]:
        return public_nvd(get_engine(request).settings)

    @router.put("/integrations/nvd", response_model=NvdConfigDTO)
    async def nvd_save(request: Request, body: NvdInput) -> dict[str, Any]:
        engine = get_engine(request)
        async with engine.configuration_lock:
            result = save_nvd(engine.settings, body.api_key.get_secret_value())
            from .mcp_defaults import NVD_MCP_ID, VULN_INTEL_MCP_ID

            await engine.mcp_manager.disconnect(NVD_MCP_ID)
            await engine.mcp_manager.disconnect(VULN_INTEL_MCP_ID)
            return result

    @router.delete("/integrations/nvd", response_model=NvdConfigDTO)
    async def nvd_remove(request: Request) -> dict[str, Any]:
        engine = get_engine(request)
        async with engine.configuration_lock:
            result = save_nvd(engine.settings, None)
            from .mcp_defaults import NVD_MCP_ID, VULN_INTEL_MCP_ID

            await engine.mcp_manager.disconnect(NVD_MCP_ID)
            await engine.mcp_manager.disconnect(VULN_INTEL_MCP_ID)
            return result

    from .api import get_engine

    @router.get("/integrations/tools", response_model=NativeToolsDTO)
    async def tools_get(request: Request) -> dict[str, Any]:
        import asyncio

        from .tool_catalog import public_tools

        return await asyncio.to_thread(public_tools, get_engine(request).settings)

    @router.post("/integrations/tools/provision", response_model=NativeToolsDTO)
    async def tools_provision(request: Request) -> dict[str, Any]:
        import asyncio

        from .tool_catalog import public_tools
        from .tool_provisioner import provision

        engine = get_engine(request)
        # Download + verify the lightweight scanners into the profile tools dir,
        # then return the refreshed inventory. Network I/O runs off the loop.
        await asyncio.to_thread(provision, engine.settings)
        return await asyncio.to_thread(public_tools, engine.settings)

    @router.post("/integrations/tools/{tool_id}/check", response_model=ProviderCheckDTO)
    async def tool_check(request: Request, tool_id: str) -> dict[str, Any]:
        import asyncio

        from .tool_checks import check_native_tool

        engine = get_engine(request)
        if tool_id == "nist-nvd":
            from .errors import unavailable
            from .mcp_defaults import NVD_MCP_ID

            await engine.mcp_manager.register_defaults()
            connection = await engine.mcp_manager.reconnect(NVD_MCP_ID)
            if connection.status != ServiceState.LIVE:
                raise unavailable("NVD MCP could not start. Check the bundled tools runtime.")
            return {"state": "live", "detail": f"NVD MCP connected; {len(connection.tools)} tools available."}
        return await asyncio.to_thread(check_native_tool, tool_id)

    @router.get("/integrations/catalog", response_model=ProviderCatalogDTO)
    async def catalog(request: Request) -> dict[str, Any]:
        return read_catalog(get_engine(request).settings)

    @router.post("/integrations/catalog/refresh", response_model=ProviderCatalogDTO)
    async def catalog_refresh(request: Request) -> dict[str, Any]:
        return await refresh_catalog(get_engine(request).settings)

    @router.get("/integrations/providers", response_model=ProviderListDTO)
    async def providers(request: Request) -> dict[str, Any]:
        engine = get_engine(request)
        return IntegrationStore(engine.settings).public() | {
            "runtime_provider": engine.settings.model_provider,
            "runtime_model": engine.settings.model_name,
        }

    @router.post("/integrations/providers", status_code=201, response_model=ProviderConnectionDTO)
    async def provider_save(request: Request, body: ProviderInput) -> dict[str, Any]:
        engine = get_engine(request)
        async with engine.configuration_lock:
            store = IntegrationStore(engine.settings)
            data = store.read()
            had_active = bool(data.get("active_provider"))
            reconfigures = body.id and body.id in (
                data.get("active_provider"),
                data.get("memory", {}).get("provider_connection_id"),
            )
            if reconfigures:
                await ensure_idle(engine)
            async with memory_reconfiguration(engine) if reconfigures else nullcontext():
                item = store.save_provider(values(body))
                # A first saved connection becomes the active one, so a saved
                # provider is actually used instead of the engine silently
                # falling back to the Anthropic default. Honor "stop runs before
                # changing the model" (only when idle) and never auto-select
                # Codex, which needs an explicit, auth-checked activation.
                if not had_active and item["provider"] != "codex":
                    try:
                        await ensure_idle(engine)
                        store.activate(item["id"])
                    except RJError:
                        pass  # a run is active: leave it saved-but-inactive
                if store.read().get("active_provider") == item["id"]:
                    new = engine.settings.model_copy(update=store.provider_settings(item["id"]))
                    engine.gateway = gateway_from_settings(new)
                    engine.settings = new
            return item

    @router.post("/integrations/provider-models", response_model=list[CatalogModelDTO])
    async def provider_models(request: Request, body: ProviderModelsInput) -> list[dict[str, Any]]:
        import httpx

        from .errors import unavailable
        from .integrations import validate_endpoint

        store = IntegrationStore(get_engine(request).settings)
        base = validate_endpoint(body.base_url)
        key = body.api_key.get_secret_value() if body.api_key else None
        if body.id and not key:
            saved = store.provider(body.id)
            if saved["provider"] != "custom" or saved["base_url"] != base:
                raise validation("Re-enter the API key when changing its destination.")
            key = store.decrypt(saved.get("secret"))
        try:
            async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
                async with client.stream(
                    "GET", base + "/models", headers={"Authorization": "Bearer " + key} if key else {}
                ) as response:
                    response.raise_for_status()
                    content = bytearray()
                    async for chunk in response.aiter_bytes():
                        content.extend(chunk)
                        if len(content) > 4 * 1024 * 1024:
                            raise ValueError("model list too large")
            import json

            models = json.loads(content)["data"]
            if not isinstance(models, list) or len(models) > 10000:
                raise ValueError("invalid model list")
            return [
                {"id": item["id"], "name": item.get("name") or item.get("display_name") or item["id"]}
                for item in models
                if isinstance(item, dict) and isinstance(item.get("id"), str)
            ]
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
            raise unavailable("Cannot load models from this endpoint. Check its URL and API key.") from exc

    @router.post("/integrations/providers/{identifier}/activate", response_model=ProviderListDTO)
    async def provider_activate(request: Request, identifier: str) -> dict[str, Any]:
        engine = get_engine(request)
        async with engine.configuration_lock:
            await ensure_idle(engine)
            store = IntegrationStore(engine.settings)
            new = engine.settings.model_copy(update=store.provider_settings(identifier))
            if new.model_provider == "codex" and not (await auth_server(engine).status())["authenticated"]:
                raise validation("Sign in to Codex before selecting this connection.")
            gateway = gateway_from_settings(new)
            async with memory_reconfiguration(engine):
                store.activate(identifier)
                engine.settings = new
                engine.gateway = gateway
            return store.public()

    @router.delete("/integrations/providers/{identifier}", status_code=204)
    async def provider_delete(request: Request, identifier: str) -> Response:
        engine = get_engine(request)
        async with engine.configuration_lock:
            IntegrationStore(engine.settings).delete(identifier)
        return Response(status_code=204)

    @router.post("/integrations/providers/{identifier}/check", response_model=ProviderCheckDTO)
    async def provider_check(request: Request, identifier: str) -> dict[str, Any]:
        engine = get_engine(request)
        settings = engine.settings.model_copy(
            update=IntegrationStore(engine.settings).provider_settings(identifier)
        )
        gateway = gateway_from_settings(settings)
        result = await gateway.complete(
            agent=None,
            run=None,
            step=0,
            tools=[],
            messages=[{"role": "user", "content": "Reply with OK."}],
            max_output_tokens=128,
        )
        if not result.content.strip() or result.tool_calls:
            raise validation("The provider did not return a usable text response.")
        return {"state": "live", "detail": "Authenticated model request succeeded.", "usage": result.usage}

    @router.get("/integrations/codex", response_model=CodexStatusDTO)
    async def codex_status(request: Request) -> dict[str, Any]:
        engine = get_engine(request)
        async with engine.configuration_lock:
            return await auth_server(engine).status()

    @router.post("/integrations/codex/login", response_model=CodexLoginDTO)
    async def codex_login(request: Request) -> dict[str, Any]:
        engine = get_engine(request)
        async with engine.configuration_lock:
            return await auth_server(engine).login_start()

    @router.delete("/integrations/codex/login", status_code=204)
    async def codex_logout(request: Request) -> Response:
        engine = get_engine(request)
        async with engine.configuration_lock:
            await ensure_idle(engine)
            await auth_server(engine).logout()
        return Response(status_code=204)

    @router.get("/integrations/memory", response_model=MemoryConfigDTO)
    async def memory(request: Request) -> dict[str, Any]:
        return memory_public(get_engine(request).settings)

    @router.put("/integrations/memory", response_model=MemoryConfigDTO)
    async def memory_save(request: Request, body: MemoryInput) -> dict[str, Any]:
        engine = get_engine(request)
        async with engine.configuration_lock:
            await ensure_idle(engine)
            async with memory_reconfiguration(engine):
                result = save_memory(engine.settings, values(body))
                if engine._memory_client is not None:
                    await engine._memory_client.close()
                    engine._memory_client = None
            return result

    @router.post("/integrations/memory/server-config", response_model=MemoryConfigDTO)
    async def memory_server_config(request: Request, body: MemoryModelsInput) -> dict[str, Any]:
        engine = get_engine(request)
        async with engine.configuration_lock:
            await ensure_idle(engine)
            async with memory_reconfiguration(engine):
                return generate_server_config(engine.settings, values(body))

    @router.post("/integrations/memory/check", response_model=ServiceStatus)
    async def memory_check(request: Request) -> dict[str, Any]:
        return (await get_engine(request).openviking_status()).model_dump(mode="json")

    @router.post("/integrations/memory/auto-start", status_code=202, response_model=ServiceStatus)
    async def memory_auto_start(request: Request) -> dict[str, Any]:
        engine = get_engine(request)
        # Synthetic fixture engines cannot download models merely because a
        # desktop integration test attaches to their profile lock.
        async with engine.configuration_lock:
            if engine.settings.model_provider != "fixture":
                engine.start_memory_bootstrap()
            return (await engine.openviking_status()).model_dump(mode="json")

    @router.post("/integrations/memory/setup", status_code=202, response_model=MemoryConfigDTO)
    async def memory_setup(request: Request, body: MemorySetupInput) -> dict[str, Any]:
        import secrets

        from .integrations import atomic_private_json
        from .memory_config import memory_proxy_url

        engine = get_engine(request)
        async with engine.configuration_lock:
            await ensure_idle(engine)
            store = IntegrationStore(engine.settings)
            if not body.provider_connection_id or not body.model.strip() or len(body.model) > 200:
                raise validation("Choose a saved provider connection and its memory model.")
            provider = store.provider(body.provider_connection_id)
            if (
                provider["provider"] == "codex"
                and not (await auth_server(engine).status())["authenticated"]
            ):
                raise validation("Sign in in Providers before saving the OpenViking model.")
            await engine.cancel_memory_bootstrap()
            data = store.read()
            memory = data.setdefault("memory", {})
            memory.update(
                {
                    "mode": "provider",
                    "provider_connection_id": body.provider_connection_id,
                    "selected_model": body.model.strip(),
                }
            )
            # Model changes keep the existing managed tenant identity. Only an
            # explicit switch from an external service clears its association.
            managed_url = f"http://127.0.0.1:{memory.get('managed_port')}"
            if memory.get("openviking_url") != managed_url:
                memory["openviking_url"] = None
                engine.settings.openviking_url = None
                engine.settings.openviking_api_key = None
            key = store.decrypt(memory.get("model_proxy_secret")) or secrets.token_urlsafe(32)
            memory["model_proxy_secret"] = store.encrypt(key)
            atomic_private_json(store.path, data)
            # Language routes through the in-engine proxy to the active provider;
            # embeddings go straight to the external endpoint the user supplied.
            generate_server_config(
                engine.settings,
                {
                    "language_base_url": memory_proxy_url(engine.settings),
                    "language_model": memory["selected_model"],
                    "language_api_key": key,
                    "embedding_base_url": body.embedding_base_url,
                    "embedding_model": body.embedding_model,
                    "embedding_dimension": body.embedding_dimension,
                    "embedding_api_key": body.embedding_api_key.get_secret_value()
                    if body.embedding_api_key
                    else None,
                },
            )
            engine.start_memory_bootstrap()
            return memory_public(engine.settings)

    @router.post("/integrations/memory/start", response_model=MemoryConfigDTO)
    async def memory_start(request: Request) -> dict[str, Any]:
        import asyncio

        from .errors import unavailable
        from .managed_memory import ManagedMemoryRuntime, start_memory

        engine = get_engine(request)
        async with engine.configuration_lock:
            if not memory_public(engine.settings)["model_config_applied"]:
                await ensure_idle(engine)
            await engine.cancel_memory_bootstrap()
            if engine._managed_memory is None:

                def progress(detail: str) -> None:
                    engine._memory_startup_status = ServiceStatus(
                        service="openviking", state=ServiceState.STARTING, detail=detail
                    )

                engine._managed_memory = ManagedMemoryRuntime(engine.settings, progress)
            previous_identity = (
                engine.settings.openviking_url,
                engine.settings.openviking_api_key,
                engine.settings.openviking_account,
                engine.settings.openviking_user,
                engine.settings.openviking_processing_mode,
            )
            try:
                async with asyncio.timeout(55):
                    result = await start_memory(engine.settings, runtime=engine._managed_memory)
            except TimeoutError as exc:
                raise unavailable(
                    "Local OpenViking startup timed out. Check its local service logs, then retry."
                ) from exc
            finally:
                engine._memory_startup_status = None
                if engine._auto_memory_enabled:
                    engine.start_memory_bootstrap()
            new_identity = (
                engine.settings.openviking_url,
                engine.settings.openviking_api_key,
                engine.settings.openviking_account,
                engine.settings.openviking_user,
                engine.settings.openviking_processing_mode,
            )
            if engine._memory_client is not None and previous_identity != new_identity:
                await engine._memory_client.close()
                engine._memory_client = None
            return result
