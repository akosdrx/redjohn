"""Embedded OpenViking service runtime and zero-key local embedder fallback."""

from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import logging
import math
import re
import time
from pathlib import Path
from typing import Any, cast

from redjohn.memory.openviking.config import ensure_openviking_configured


logger = logging.getLogger(__name__)

_TOKEN_RE = re.compile(r"[a-zA-Z0-9_./:-]{2,}")
_PLACEHOLDER_API_KEYS = frozenset({"local-no-key", "local-key", "grok-subscription"})
_SERVICE_LOCK = asyncio.Lock()
_SERVICE_INSTANCE: Any = None
_PATCHED_LOCAL_EMBEDDER = False
_PATCHED_RESILIENT_VLM = False


def _extractive_vlm_fallback(prompt: str = "", messages: list[dict[str, Any]] | None = None) -> str:
    """Fast extractive summary when the remote VLM endpoint is unreachable or unconfigured."""
    text = prompt or ""
    if not text and messages:
        parts = []
        for msg in messages:
            content = msg.get("content") if isinstance(msg, dict) else ""
            if isinstance(content, str):
                parts.append(content)
        text = "\n".join(parts)
    cleaned_lines = [
        line.strip()
        for line in text.splitlines()
        if line.strip()
        and not line.strip().lower().startswith(
            ("you are", "task:", "instructions:", "output format:", "return ", "respond ")
        )
    ]
    # Documents read top-down: the first content lines carry the substance,
    # trailing lines are usually instruction boilerplate.
    summary = (
        " ".join(cleaned_lines[:6]) if cleaned_lines else "Indexed OpenViking pentest memory node."
    )
    return summary[:360]


def install_resilient_vlm_fallback() -> None:
    """Wrap VLMFactory.create so offline/unconfigured VLM models never block SemanticQueue."""
    global _PATCHED_RESILIENT_VLM  # noqa: PLW0603
    if _PATCHED_RESILIENT_VLM:
        return

    try:
        import litellm

        litellm.suppress_debug_info = True
    except Exception:
        pass
    logging.getLogger("LiteLLM").setLevel(logging.ERROR)
    logging.getLogger("LiteLLM Router").setLevel(logging.ERROR)
    logging.getLogger("LiteLLM Proxy").setLevel(logging.ERROR)

    try:
        from openviking.models.vlm import VLMFactory
        from openviking.models.vlm.base import VLMBase

        if not hasattr(VLMFactory, "_create_provider"):
            logger.warning("openviking VLMFactory API changed; resilient VLM wrapper not installed")
            return

        class _ResilientVLM(VLMBase):  # type: ignore[misc]
            """Single-attempt VLM wrapper with circuit breaker and extractive fallback."""

            def __init__(self, inner: VLMBase) -> None:
                super().__init__(inner.config)
                self.inner = inner
                api_key = str(inner.config.get("api_key") or "").strip()
                api_base = str(inner.config.get("api_base") or "").strip()
                self._opened_at: float | None = None
                # Placeholder keys from the local inference path mean "unconfigured":
                # start with the breaker open instead of burning a doomed API call.
                self._circuit_open = not bool(
                    (api_key and api_key not in _PLACEHOLDER_API_KEYS) or api_base
                )

            def _trip(self) -> None:
                self._circuit_open = True
                self._opened_at = time.monotonic()

            def _breaker_allows(self) -> bool:
                if not self._circuit_open:
                    return True
                if self._opened_at is not None and time.monotonic() - self._opened_at > 300.0:
                    # Half-open: allow one probe call after the cooldown; a fresh
                    # failure trips the breaker again.
                    self._circuit_open = False
                    self._opened_at = None
                    return True
                return False

            def __getattr__(self, name: str) -> Any:
                return getattr(self.inner, name)

            def get_completion(
                self,
                prompt: str = "",
                thinking: bool | None = None,
                tools: list[dict[str, Any]] | None = None,
                tool_choice: str | None = None,
                messages: list[dict[str, Any]] | None = None,
                **kwargs: Any,
            ) -> Any:
                if not self._breaker_allows():
                    return _extractive_vlm_fallback(prompt, messages)
                try:
                    return self.inner.get_completion(
                        prompt=prompt,
                        thinking=thinking,
                        tools=tools,
                        tool_choice=tool_choice,
                        messages=messages,
                        **kwargs,
                    )
                except Exception:
                    self._trip()
                    return _extractive_vlm_fallback(prompt, messages)

            async def get_completion_async(
                self,
                prompt: str = "",
                thinking: bool | None = None,
                tools: list[dict[str, Any]] | None = None,
                tool_choice: str | None = None,
                messages: list[dict[str, Any]] | None = None,
                max_tokens: int | None = None,
                **kwargs: Any,
            ) -> Any:
                if not self._breaker_allows():
                    return _extractive_vlm_fallback(prompt, messages)
                try:
                    return await asyncio.wait_for(
                        self.inner.get_completion_async(
                            prompt=prompt,
                            thinking=thinking,
                            tools=tools,
                            tool_choice=tool_choice,
                            messages=messages,
                            max_tokens=max_tokens,
                            **kwargs,
                        ),
                        timeout=6.0,
                    )
                except Exception:
                    self._trip()
                    return _extractive_vlm_fallback(prompt, messages)

            def get_vision_completion(
                self,
                prompt: str = "",
                images: list[Any] | None = None,
                thinking: bool | None = None,
                tools: list[dict[str, Any]] | None = None,
                tool_choice: str | None = None,
                messages: list[dict[str, Any]] | None = None,
                **kwargs: Any,
            ) -> Any:
                if not self._breaker_allows():
                    return _extractive_vlm_fallback(prompt, messages)
                try:
                    return self.inner.get_vision_completion(
                        prompt=prompt,
                        images=images,
                        thinking=thinking,
                        tools=tools,
                        tool_choice=tool_choice,
                        messages=messages,
                        **kwargs,
                    )
                except Exception:
                    self._trip()
                    return _extractive_vlm_fallback(prompt, messages)

            async def get_vision_completion_async(
                self,
                prompt: str = "",
                images: list[Any] | None = None,
                thinking: bool | None = None,
                tools: list[dict[str, Any]] | None = None,
                tool_choice: str | None = None,
                messages: list[dict[str, Any]] | None = None,
                **kwargs: Any,
            ) -> Any:
                if not self._breaker_allows():
                    return _extractive_vlm_fallback(prompt, messages)
                try:
                    return await asyncio.wait_for(
                        self.inner.get_vision_completion_async(
                            prompt=prompt,
                            images=images,
                            thinking=thinking,
                            tools=tools,
                            tool_choice=tool_choice,
                            messages=messages,
                            **kwargs,
                        ),
                        timeout=6.0,
                    )
                except Exception:
                    self._trip()
                    return _extractive_vlm_fallback(prompt, messages)

        def _create_resilient(config: dict[str, Any]) -> VLMBase:
            return _ResilientVLM(VLMFactory._create_provider(config))

        VLMFactory.create = staticmethod(_create_resilient)
        _PATCHED_RESILIENT_VLM = True
    except Exception:
        logger.warning("Could not install resilient VLM wrapper", exc_info=True)


def compute_deterministic_embedding(text: str, dimension: int = 512) -> list[float]:
    """Compute an L2-normalized dense vector using signed word + char-ngram feature hashing."""
    vec = [0.0] * dimension
    cleaned = (text or "").lower().strip()
    if not cleaned:
        vec[0] = 1.0
        return vec

    tokens = _TOKEN_RE.findall(cleaned)
    features: list[tuple[str, float]] = []
    for tok in tokens:
        features.append((f"w:{tok}", 2.0))
        if len(tok) >= 4:
            for i in range(len(tok) - 2):
                features.append((f"c3:{tok[i : i + 3]}", 0.75))
    for idx in range(len(tokens) - 1):
        features.append((f"bg:{tokens[idx]}_{tokens[idx + 1]}", 1.5))

    if not features:
        features.append((cleaned[:64], 1.0))

    for feat, weight in features:
        digest = hashlib.blake2b(feat.encode("utf-8", errors="ignore"), digest_size=8).digest()
        h_val = int.from_bytes(digest, "little")
        bucket = h_val % dimension
        sign = 1.0 if ((h_val >> 32) & 1) == 0 else -1.0
        vec[bucket] += sign * weight

    norm = math.sqrt(sum(v * v for v in vec))
    if norm > 0:
        vec = [v / norm for v in vec]
    else:
        vec[0] = 1.0
    return vec


def install_local_embedder_fallback() -> None:
    """Allow OpenViking's ``provider='local'`` embedder to run without llama-cpp-python."""
    global _PATCHED_LOCAL_EMBEDDER  # noqa: PLW0603
    install_resilient_vlm_fallback()
    if _PATCHED_LOCAL_EMBEDDER:
        return
    if importlib.util.find_spec("llama_cpp") is not None:
        _PATCHED_LOCAL_EMBEDDER = True
        return

    try:
        import openviking.models.embedder as embedder_pkg
        from openviking.models.embedder import local_embedders
        from openviking.models.embedder.base import DenseEmbedderBase, EmbedResult

        if not hasattr(local_embedders, "LocalDenseEmbedder"):
            logger.warning(
                "openviking local embedder API changed; fallback embedder not installed"
            )
            return

        class _BuiltinLocalDenseEmbedder(DenseEmbedderBase):  # type: ignore[misc]
            """Zero-dependency local dense embedder for OpenViking VikingDB."""

            def __init__(
                self,
                model_name: str = local_embedders.DEFAULT_LOCAL_DENSE_MODEL,
                model_path: str | None = None,
                cache_dir: str | None = None,
                dimension: int | None = None,
                query_instruction: str | None = None,
                config: dict[str, Any] | None = None,
            ) -> None:
                runtime_config = dict(config or {})
                runtime_config.setdefault("provider", "local")
                super().__init__(model_name, runtime_config)
                self.model_spec = local_embedders.get_local_model_spec(model_name)
                self.model_path = model_path
                self.cache_dir = cache_dir or local_embedders.DEFAULT_LOCAL_MODEL_CACHE_DIR
                self.query_instruction = query_instruction
                self._dimension = dimension or self.model_spec.dimension

            def embed(self, text: str, is_query: bool = False) -> EmbedResult:
                del is_query
                vec = compute_deterministic_embedding(text, self._dimension)
                return EmbedResult(dense_vector=vec)

            def get_dimension(self) -> int:
                return int(self._dimension)

            def close(self) -> None:
                return None

        local_embedders.LocalDenseEmbedder = _BuiltinLocalDenseEmbedder
        embedder_pkg.LocalDenseEmbedder = _BuiltinLocalDenseEmbedder

        from openviking_cli.utils.config.embedding_config import EmbeddingConfig

        orig_get_embedder = EmbeddingConfig.get_embedder

        class _ResilientDenseEmbedder(DenseEmbedderBase):  # type: ignore[misc]
            """Falls back to deterministic local vectors when the API embedder fails."""

            def __init__(self, inner: Any) -> None:
                super().__init__(
                    getattr(inner, "model_name", "resilient-embedder"),
                    getattr(inner, "config", {}) or {},
                )
                self.inner = inner
                self._opened_at: float | None = None
                self._circuit_open = isinstance(inner, _BuiltinLocalDenseEmbedder)
                # Assume an API-backed collection may already hold real vectors:
                # deterministic hash vectors must never mix into it.
                self._api_vectors_possible = not self._circuit_open

            def _trip(self) -> None:
                self._circuit_open = True
                self._opened_at = time.monotonic()

            def _breaker_allows(self) -> bool:
                if not self._circuit_open:
                    return True
                if self._opened_at is not None and time.monotonic() - self._opened_at > 300.0:
                    self._circuit_open = False
                    self._opened_at = None
                    return True
                return False

            def _fallback_embed_result(self, text: str) -> EmbedResult:
                return EmbedResult(
                    dense_vector=compute_deterministic_embedding(text, self.get_dimension())
                )

            def __getattr__(self, name: str) -> Any:
                return getattr(self.inner, name)

            def get_dimension(self) -> int:
                try:
                    return int(self.inner.get_dimension())
                except Exception:
                    return 512

            def embed(self, text: str, is_query: bool = False) -> EmbedResult:
                if not self._breaker_allows():
                    if not is_query and self._api_vectors_possible:
                        raise RuntimeError("openviking_embedder_fallback_would_mix_vectors")
                    return self._fallback_embed_result(text)
                try:
                    result = self.inner.embed(text, is_query=is_query)
                    if not is_query:
                        self._api_vectors_possible = True
                    return result
                except Exception:
                    self._trip()
                    if not is_query and self._api_vectors_possible:
                        logger.warning(
                            "OpenViking API embedder failed after use; refusing to mix "
                            "deterministic fallback vectors into the live collection"
                        )
                        raise
                    return self._fallback_embed_result(text)

            def embed_batch(self, texts: list[str], is_query: bool = False) -> list[EmbedResult]:
                if not self._breaker_allows():
                    if not is_query and self._api_vectors_possible:
                        raise RuntimeError("openviking_embedder_fallback_would_mix_vectors")
                    return [self._fallback_embed_result(t) for t in texts]
                try:
                    results = self.inner.embed_batch(texts, is_query=is_query)
                    if not is_query:
                        self._api_vectors_possible = True
                    return cast("list[EmbedResult]", results)
                except Exception:
                    self._trip()
                    if not is_query and self._api_vectors_possible:
                        logger.warning(
                            "OpenViking API embedder failed after use; refusing to mix "
                            "deterministic fallback vectors into the live collection"
                        )
                        raise
                    return [self._fallback_embed_result(t) for t in texts]

            def close(self) -> None:
                try:
                    self.inner.close()
                except Exception:
                    pass

        def _resilient_get_embedder(self_cfg: Any) -> Any:
            emb = orig_get_embedder(self_cfg)
            if isinstance(emb, _ResilientDenseEmbedder):
                return emb
            return _ResilientDenseEmbedder(emb)

        EmbeddingConfig.get_embedder = _resilient_get_embedder
        _PATCHED_LOCAL_EMBEDDER = True
    except Exception:
        logger.warning("Could not install local embedder fallback", exc_info=True)


def bind_default_mcp_identity() -> Any:
    """Bind the default ROOT RequestContext for stdio / direct OpenViking calls."""
    from openviking.server.identity import RequestContext, Role
    from openviking.server.mcp_endpoint import _mcp_ctx
    from openviking_cli.session.user_id import UserIdentifier

    ctx = RequestContext(user=UserIdentifier("default", "redjohn"), role=Role.ROOT)
    _mcp_ctx.set(ctx)
    return ctx


async def get_or_init_openviking_service() -> Any:
    """Initialize and return the singleton OpenVikingService bound to RedJohn's workspace."""
    global _SERVICE_INSTANCE  # noqa: PLW0603
    install_local_embedder_fallback()
    bind_default_mcp_identity()

    async with _SERVICE_LOCK:
        if _SERVICE_INSTANCE is not None:
            return _SERVICE_INSTANCE

        conf_path = ensure_openviking_configured()
        raw_conf = {}
        try:
            import json

            raw_conf = json.loads(conf_path.read_text(encoding="utf-8"))
        except Exception:
            raw_conf = {}

        workspace = (
            raw_conf.get("storage", {}).get("workspace")
            or str(Path("~/.redjohn/openviking/data").expanduser().resolve())
        )

        import shutil

        from openviking.server.dependencies import set_service
        from openviking.service.core import OpenVikingService
        from openviking.storage.collection_schemas import EmbeddingRebuildRequiredError
        from openviking_cli.session.user_id import UserIdentifier

        service = OpenVikingService(
            path=str(workspace),
            user=UserIdentifier("default", "redjohn"),
        )
        try:
            await service.initialize()
        except EmbeddingRebuildRequiredError:
            logger.info("Rebuilding OpenViking vectordb for updated embedding dimension")
            try:
                await service.close()
            except Exception:
                pass
            shutil.rmtree(Path(workspace) / "vectordb", ignore_errors=True)
            service = OpenVikingService(
                path=str(workspace),
                user=UserIdentifier("default", "redjohn"),
            )
            await service.initialize()
        except BaseException:
            try:
                await service.close()
            except Exception:
                pass
            raise
        set_service(service)
        _SERVICE_INSTANCE = service
        return service


async def close_openviking_service() -> None:
    """Cleanly shut down the in-process OpenVikingService and its background workers."""
    global _SERVICE_INSTANCE  # noqa: PLW0603
    async with _SERVICE_LOCK:
        service = _SERVICE_INSTANCE
        _SERVICE_INSTANCE = None
        if service is not None:
            try:
                await service.close()
            except Exception:
                logger.debug("Error closing OpenVikingService", exc_info=True)
