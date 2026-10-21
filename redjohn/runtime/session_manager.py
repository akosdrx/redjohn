"""Per-scan sandbox session lifecycle."""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import io
import logging
import os
import sys
import tarfile
import time
import weakref
from pathlib import Path
from typing import TYPE_CHECKING, Any

from agents.sandbox.entries import BaseEntry, LocalDir
from agents.sandbox.manifest import Environment, Manifest

from redjohn.config import load_settings
from redjohn.runtime.backends import backend_supports_bind_mounts, get_backend
from redjohn.runtime.caido_bootstrap import bootstrap_caido
from redjohn.runtime.caido_handle import CaidoBootstrapHandle
from redjohn.runtime.deferred_session import DeferredSandboxClient, DeferredSandboxSession


if TYPE_CHECKING:
    from collections.abc import Awaitable

    from agents.sandbox.session import BaseSandboxSession

    from redjohn.runtime.status import StatusSink


logger = logging.getLogger(__name__)

# Callers and waiters retain their lock while it is in use. Once the last
# operation finishes, the weak registry releases it without evicting live locks
# or accumulating one entry for every historical scan ID.
_SESSION_LOCKS: weakref.WeakValueDictionary[str, asyncio.Lock] = weakref.WeakValueDictionary()
_SESSION_STARTING: set[str] = set()
_SESSION_DISCARDING: set[str] = set()
_CLEANUP_TASKS: dict[str, asyncio.Task[None]] = {}
_DEFAULT_MAX_SESSIONS = 64
_CLEANUP_TIMEOUT_SECONDS = 120.0
_PROVISION_TIMEOUT_SECONDS = 180.0


class SessionCapacityError(RuntimeError):
    """Admission failed; existing or provisioning sessions remain owned."""


def _session_limit() -> int:
    value = int(os.environ.get("REDJOHN_MAX_CACHED_SESSIONS", str(_DEFAULT_MAX_SESSIONS)))
    if not 1 <= value <= 1024:
        raise ValueError("REDJOHN_MAX_CACHED_SESSIONS must be between 1 and 1024")
    return value


# In-container Caido sidecar port (matches the image's caido-cli bind).
_CONTAINER_CAIDO_PORT = 48080


_SESSION_CACHE: dict[str, dict[str, Any]] = {}

# Manifest root inside the container; entry keys hang off this path.
_WORKSPACE_ROOT = "/workspace"

_PROTECTED_METADATA_NAMES = (".git", ".agents", ".codex")

# Extra files travel as one tar archive: a single upload plus one extraction
# inside the sandbox, instead of several round trips per file.
_EXTRA_FILE_ARCHIVE_REL = ".redjohn-extra-files.tar"
_EXTRA_FILE_ARCHIVE = f"{_WORKSPACE_ROOT}/{_EXTRA_FILE_ARCHIVE_REL}"
_EXTRA_FILE_EXTRACT_TIMEOUT_S = 120
_EXTRA_FILE_MODE = 0o644


def _host_identity_env() -> dict[str, str]:
    # Read the platform through a local so it is not narrowed to whichever OS is
    # type-checking: comparing sys.platform directly makes one of these branches
    # statically dead, and which one flips between Linux and macOS.
    platform_name: str = sys.platform
    if platform_name != "linux":
        return {}
    # Bind-mount ownership only needs mapping on Linux, where the container uid
    # must match the host's.
    return {"REDJOHN_HOST_UID": str(os.getuid()), "REDJOHN_HOST_GID": str(os.getgid())}


def build_bind_mounts(
    local_sources: list[dict[str, Any]], *, protected_host_paths: tuple[Path, ...] = ()
) -> list[dict[str, Any]]:
    bind_mounts: list[dict[str, Any]] = []
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        rel = _extra_file_rel_path(f"{_WORKSPACE_ROOT}/{ws_subdir}")
        if rel is None:
            logger.warning(
                "Skipping bind mount with an unsafe workspace subdirectory: %s",
                ws_subdir,
            )
            continue
        resolved = Path(host_path).expanduser().resolve()
        target = f"{_WORKSPACE_ROOT}/{rel}"
        protected = tuple(path.resolve() for path in protected_host_paths)
        read_only = bool(src.get("read_only")) or any(
            resolved.is_relative_to(path) for path in protected
        )
        bind_mounts.append({"source": str(resolved), "target": target, "read_only": read_only})
        if src.get("protect_metadata") and not read_only:
            bind_mounts.extend(_metadata_mounts(resolved, target))
        if not read_only:
            for path in protected:
                if path.exists() and path.is_relative_to(resolved):
                    relative = path.relative_to(resolved).as_posix()
                    bind_mounts.append(
                        {
                            "source": str(path),
                            "target": f"{target}/{relative}",
                            "read_only": True,
                        }
                    )
    return bind_mounts


def build_manifest_entries(local_sources: list[dict[str, Any]]) -> dict[str | Path, BaseEntry]:
    entries: dict[str | Path, BaseEntry] = {}
    for src in local_sources:
        ws_subdir = src.get("workspace_subdir") or ""
        host_path = src.get("source_path") or ""
        if not ws_subdir or not host_path:
            continue
        rel = _extra_file_rel_path(f"{_WORKSPACE_ROOT}/{ws_subdir}")
        if rel is None:
            logger.warning(
                "Skipping manifest entry with an unsafe workspace subdirectory: %s",
                ws_subdir,
            )
            continue
        entries[rel] = LocalDir(src=Path(host_path).expanduser().resolve())
    return entries


def _extra_file_rel_path(workspace_path: str) -> str | None:
    """Validate an extra-file target path and return it relative to /workspace.

    Only absolute paths under the workspace root are accepted; anything else
    (including ``..`` traversal segments) is rejected so callers cannot place
    orchestrator-provided content outside the sandbox workspace.
    """
    prefix = f"{_WORKSPACE_ROOT}/"
    if not workspace_path.startswith(prefix):
        return None
    rel = workspace_path[len(prefix) :].strip("/")
    if not rel or any(part in ("", ".", "..") for part in rel.split("/")):
        return None
    # Control characters would let a path break out of the single line it is
    # rendered on in the agent task, so the path is rejected rather than escaped.
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in rel):
        return None
    return rel


def _source_root_rels(local_sources: list[dict[str, Any]] | None) -> list[str]:
    """Workspace-relative roots the local sources occupy (e.g. ``["repo"]``)."""
    if not local_sources:
        return []
    return [
        str(src.get("workspace_subdir") or "").strip("/")
        for src in local_sources
        if src.get("workspace_subdir") and src.get("source_path")
    ]


def _collides_with_source_root(rel: str, source_roots: list[str]) -> bool:
    """True when an extra-file path would land on or inside a source tree.

    An exact match would replace the whole source tree with one file (a
    manifest ``entries`` key collision); a path nested under a source root
    would race the source upload; a path that is an ancestor of a source root
    would shadow the directory the source materializes into.
    """
    for root in source_roots:
        if not root:
            continue
        if rel == root or rel.startswith(f"{root}/") or root.startswith(f"{rel}/"):
            return True
    return False


def _extra_file_content(extra_file: dict[str, Any]) -> bytes | None:
    content = extra_file.get("content")
    if isinstance(content, bytes | bytearray):
        return bytes(content)
    if isinstance(content, str):
        return content.encode("utf-8")
    return None


def build_extra_file_archive(
    extra_files: list[dict[str, Any]],
    local_sources: list[dict[str, Any]] | None = None,
) -> bytes | None:
    """Pack extra files into one tar archive rooted at ``/workspace``.

    Each item is ``{"workspace_path": "/workspace/<rel>", "content": bytes|str}``
    and becomes a regular-file member at ``<rel>``. Extracting the archive as
    the sandbox user (see ``stage_extra_files``) leaves every file owned by
    that user, so the agent can edit it and create siblings. Invalid items —
    including paths that collide with a ``local_sources`` tree or with an
    earlier extra file — are skipped with a warning. Returns ``None`` when no
    valid file remains.
    """
    source_roots = _source_root_rels(local_sources)
    placed: list[str] = [_EXTRA_FILE_ARCHIVE_REL]
    buffer = io.BytesIO()
    mtime = int(time.time())
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for extra_file in extra_files:
            rel, content = _validated_extra_file(extra_file, source_roots + placed)
            if rel is None or content is None:
                continue
            placed.append(rel)
            info = tarfile.TarInfo(name=rel)
            info.size = len(content)
            info.mode = _EXTRA_FILE_MODE
            info.mtime = mtime
            archive.addfile(info, io.BytesIO(content))
    if len(placed) == 1:
        return None
    return buffer.getvalue()


def _validated_extra_file(
    extra_file: dict[str, Any], taken: list[str]
) -> tuple[str | None, bytes | None]:
    rel = _extra_file_rel_path(str(extra_file.get("workspace_path") or ""))
    content = _extra_file_content(extra_file)
    if rel is None or content is None:
        logger.warning(
            "Skipping invalid extra file entry (workspace_path=%r)",
            extra_file.get("workspace_path"),
        )
        return None, None
    if _collides_with_source_root(rel, taken):
        logger.warning(
            "Skipping extra file colliding with a local source tree or an "
            "earlier extra file (workspace_path=%r)",
            extra_file.get("workspace_path"),
        )
        return None, None
    return rel, content


async def stage_extra_files(session: BaseSandboxSession, archive: bytes) -> None:
    """Upload ``archive`` and unpack it under ``/workspace`` as the sandbox user.

    ``--no-same-owner`` keeps ownership with the extracting user even where
    the session runs as root, so the agent user can always write the files.
    """
    await session.write(Path(_EXTRA_FILE_ARCHIVE), io.BytesIO(archive))
    result = await session.exec(
        "sh",
        "-c",
        'tar --no-same-owner -xf "$1" -C "$2" && rm -f -- "$1"',
        "sh",
        _EXTRA_FILE_ARCHIVE,
        _WORKSPACE_ROOT,
        timeout=_EXTRA_FILE_EXTRACT_TIMEOUT_S,
    )
    if not result.ok():
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"unpacking extra files in the sandbox failed (exit {result.exit_code}): {stderr}"
        )


def _metadata_mounts(tree: Path, target: str) -> list[dict[str, Any]]:
    mounts: list[dict[str, Any]] = []
    for name in _PROTECTED_METADATA_NAMES:
        metadata = tree / name
        if not metadata.is_dir() and not metadata.is_file():
            continue
        if not metadata.resolve().is_relative_to(tree):
            continue
        mounts.append({"source": str(metadata), "target": f"{target}/{name}", "read_only": True})
        gitdir = _gitdir_from_pointer(metadata) if metadata.is_file() else None
        if gitdir is not None and gitdir.exists() and gitdir.is_relative_to(tree):
            relative = gitdir.relative_to(tree).as_posix()
            mounts.append(
                {"source": str(gitdir), "target": f"{target}/{relative}", "read_only": True}
            )
    return mounts


def _gitdir_from_pointer(git_file: Path) -> Path | None:
    try:
        content = git_file.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    for line in content.splitlines():
        prefix, _, value = line.partition(":")
        if prefix.strip() == "gitdir" and value.strip():
            candidate = Path(value.strip()).expanduser()
            if not candidate.is_absolute():
                candidate = git_file.parent / candidate
            return candidate.resolve()
    return None


async def _resolve_extra_file_archive(
    extra_files: list[dict[str, Any]] | Awaitable[list[dict[str, Any]] | None] | None,
    local_sources: list[dict[str, Any]],
) -> bytes | None:
    files = await extra_files if inspect.isawaitable(extra_files) else extra_files
    return build_extra_file_archive(files, local_sources) if files else None


async def create_or_reuse(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    extra_files: list[dict[str, Any]] | Awaitable[list[dict[str, Any]] | None] | None = None,
    status_sink: StatusSink | None = None,
    defer: bool = False,
    protected_host_paths: tuple[Path, ...] = (),
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one."""
    lock = _SESSION_LOCKS.setdefault(scan_id, asyncio.Lock())
    async with lock:
        if scan_id in _SESSION_DISCARDING:
            raise SessionCapacityError("sandbox_cancelled_provisioning_still_owned")
        if scan_id not in _SESSION_CACHE:
            if (
                len(_SESSION_CACHE) + len(_SESSION_STARTING) + len(_SESSION_DISCARDING)
                >= _session_limit()
            ):
                raise SessionCapacityError("sandbox_session_capacity_exhausted")
            _SESSION_STARTING.add(scan_id)
        try:
            return await _create_or_reuse_locked(
                scan_id,
                image=image,
                local_sources=local_sources,
                extra_files=extra_files,
                status_sink=status_sink,
                defer=defer,
                protected_host_paths=protected_host_paths,
            )
        finally:
            _SESSION_STARTING.discard(scan_id)


async def _create_or_reuse_locked(
    scan_id: str,
    *,
    image: str,
    local_sources: list[dict[str, Any]],
    extra_files: list[dict[str, Any]] | Awaitable[list[dict[str, Any]] | None] | None = None,
    status_sink: StatusSink | None = None,
    defer: bool = False,
    protected_host_paths: tuple[Path, ...] = (),
) -> dict[str, Any]:
    """Return the existing session bundle for ``scan_id`` or create a new one.

    Each ``local_sources`` entry exposes its host ``source_path`` at
    ``/workspace/<workspace_subdir>`` inside the container.

    Each ``extra_files`` entry (``{"workspace_path": "/workspace/<rel>",
    "content": bytes | str}``) lands as a regular, agent-writable file at its
    ``workspace_path`` on every backend: the files are uploaded as one archive
    and unpacked inside the sandbox right after bring-up. ``extra_files`` may
    also be an awaitable resolving to that list: provisioning starts at once and
    the files are awaited only when the sandbox is ready to receive them.
    """

    def report(phase: str) -> None:
        if status_sink is not None:
            status_sink(phase)

    cached = _SESSION_CACHE.get(scan_id)
    if cached is not None:
        if cached.get("_teardown_state") is not None:
            raise RuntimeError("sandbox_cleanup_incomplete_requires_retry")
        expected = {str(path.resolve()) for path in protected_host_paths}
        if expected - set(cached.get("protected_host_paths", ())):
            raise RuntimeError("sandbox_protection_changed_requires_fresh_session")
        logger.info("Reusing existing sandbox session for scan %s", scan_id)
        return cached

    backend_name = load_settings().runtime.backend
    backend = get_backend(backend_name)

    if backend_supports_bind_mounts(backend_name):
        bind_mounts = build_bind_mounts(local_sources, protected_host_paths=protected_host_paths)
        entries: dict[str | Path, BaseEntry] = {}
    else:
        bind_mounts = []
        entries = build_manifest_entries(local_sources)

    # Caido runs as an in-container sidecar; HTTP(S) traffic from any
    # process started via ``session.exec`` (the SDK's Shell tool, etc.)
    # picks up these env vars automatically. ``NO_PROXY`` keeps the
    # agent-browser CDP daemon's localhost traffic from looping back
    # through Caido.
    container_caido_url = f"http://127.0.0.1:{_CONTAINER_CAIDO_PORT}"
    manifest = Manifest(
        entries=entries,
        environment=Environment(
            value={
                "PYTHONUNBUFFERED": "1",
                "HOST_GATEWAY": "host.docker.internal",
                **_host_identity_env(),
                "http_proxy": container_caido_url,
                "https_proxy": container_caido_url,
                "ALL_PROXY": container_caido_url,
                "NO_PROXY": "localhost,127.0.0.1",
            },
        ),
    )

    logger.info(
        "Creating sandbox session for scan %s (backend=%s, image=%s)",
        scan_id,
        backend_name,
        image,
    )

    async def _bring_up() -> tuple[Any, Any]:
        report("Starting sandbox container")
        client, session = await _create_or_discard(
            backend(
                image=image,
                manifest=manifest,
                exposed_ports=(_CONTAINER_CAIDO_PORT,),
                bind_mounts=bind_mounts,
            ),
            scan_id=scan_id,
        )
        try:
            extra_file_archive = await _resolve_extra_file_archive(extra_files, local_sources)
            if extra_file_archive is not None:
                report("Placing workspace files")
                await stage_extra_files(session, extra_file_archive)
        except BaseException:
            await _discard_session(client, session, scan_id=scan_id)
            raise
        return client, session

    async def _caido_url(session: Any) -> str:
        report("Setting up the proxy")
        caido_endpoint = await session.resolve_exposed_port(_CONTAINER_CAIDO_PORT)
        scheme = "https" if caido_endpoint.tls else "http"
        host_caido_url = f"{scheme}://{caido_endpoint.host}:{caido_endpoint.port}"
        logger.debug("Caido host endpoint resolved: %s", host_caido_url)
        return host_caido_url

    def _caido(session: Any, host_caido_url: str) -> Any:
        effective_container_url = host_caido_url if backend_name == "local" else container_caido_url
        return bootstrap_caido(
            session,
            host_url=host_caido_url,
            container_url=effective_container_url,
        )

    if defer:
        bring_up = asyncio.create_task(_bring_up(), name=f"sandbox-bring-up-{scan_id}")
        deferred = DeferredSandboxSession(
            bring_up,
            manifest=manifest,
            exposed_ports=(_CONTAINER_CAIDO_PORT,),
        )

        async def _caido_when_up() -> Any:
            session = await deferred.resolve()
            return await _caido(session, await _caido_url(session))

        bundle = {
            "client": DeferredSandboxClient(deferred),
            "session": deferred,
            "caido_client": CaidoBootstrapHandle(
                asyncio.create_task(_caido_when_up(), name=f"caido-bootstrap-{scan_id}")
            ),
            "protected_host_paths": tuple(str(path.resolve()) for path in protected_host_paths),
        }
        _SESSION_CACHE[scan_id] = bundle
        logger.info("Sandbox session for scan %s deferred and cached", scan_id)
        return bundle

    client, session = await _bring_up()
    try:
        host_caido_url = await _caido_url(session)
        caido_client = CaidoBootstrapHandle(
            asyncio.create_task(_caido(session, host_caido_url), name=f"caido-bootstrap-{scan_id}")
        )
    except BaseException:
        await _discard_session(client, session, scan_id=scan_id)
        raise

    bundle = {
        "client": client,
        "session": session,
        "caido_client": caido_client,
        "protected_host_paths": tuple(str(path.resolve()) for path in protected_host_paths),
    }
    _SESSION_CACHE[scan_id] = bundle
    logger.info("Sandbox session for scan %s ready and cached", scan_id)
    return bundle


_DISCARD_TASKS: set[asyncio.Task[None]] = set()


async def _create_or_discard(
    create: Awaitable[tuple[Any, Any]], *, scan_id: str
) -> tuple[Any, Any]:
    pending = asyncio.ensure_future(create)
    try:
        async with asyncio.timeout(_PROVISION_TIMEOUT_SECONDS):
            return await asyncio.shield(pending)
    except (asyncio.CancelledError, TimeoutError):
        _SESSION_DISCARDING.add(scan_id)
        discard = asyncio.create_task(_discard_when_created(pending, scan_id=scan_id))
        _DISCARD_TASKS.add(discard)
        discard.add_done_callback(_DISCARD_TASKS.discard)
        raise


async def _discard_when_created(create: asyncio.Future[tuple[Any, Any]], *, scan_id: str) -> None:
    try:
        with contextlib.suppress(BaseException):
            client, session = await create
            await _discard_session(client, session, scan_id=scan_id)
    finally:
        _SESSION_DISCARDING.discard(scan_id)


async def _discard_session(client: Any, session: Any, *, scan_id: str) -> None:
    """Retain ownership even if deleting a half-created session fails."""
    bundle = {"client": client, "session": session, "caido_client": None}
    try:
        async with asyncio.timeout(_CLEANUP_TIMEOUT_SECONDS):
            await _delete_bundle(scan_id, bundle)
    except BaseException as error:
        bundle.setdefault("_teardown_state", "delete_failed")
        _SESSION_CACHE[scan_id] = bundle
        if isinstance(error, asyncio.CancelledError):
            raise
        logger.warning("Half-started sandbox cleanup failed; ownership retained", exc_info=True)


async def cleanup(scan_id: str) -> None:
    """Serialize teardown with creation and keep failed resources retryable.

    A cancelled caller does not interrupt its resource deletion. The owned task
    has a finite deadline and remains observable until it completes. No session
    is expired or evicted merely because it has been alive for a long time.
    """
    if scan_id not in _SESSION_CACHE and scan_id not in _SESSION_LOCKS:
        return
    pending = _CLEANUP_TASKS.get(scan_id)
    if pending is None:
        lock = _SESSION_LOCKS.setdefault(scan_id, asyncio.Lock())
        pending = asyncio.create_task(_cleanup_owned(scan_id, lock), name="redjohn-session-cleanup")
        _CLEANUP_TASKS[scan_id] = pending

        def finished(task: asyncio.Task[None]) -> None:
            if _CLEANUP_TASKS.get(scan_id) is task:
                _CLEANUP_TASKS.pop(scan_id, None)
            if not task.cancelled():
                task.exception()

        pending.add_done_callback(finished)
    await asyncio.shield(pending)


async def _cleanup_owned(scan_id: str, lock: asyncio.Lock) -> None:
    async with lock:
        bundle = _SESSION_CACHE.get(scan_id)
        if bundle is None:
            return
        try:
            async with asyncio.timeout(_CLEANUP_TIMEOUT_SECONDS):
                await _delete_bundle(scan_id, bundle)
        except BaseException:
            # A partial delete cannot be returned as a healthy reused session.
            # Keep ownership and permit an explicit cleanup retry.
            if bundle.get("_teardown_state") != "deleted":
                bundle["_teardown_state"] = "delete_failed"
            raise
        if _SESSION_CACHE.get(scan_id) is bundle:
            _SESSION_CACHE.pop(scan_id)


async def _delete_bundle(scan_id: str, bundle: dict[str, Any]) -> None:
    bundle.setdefault("_teardown_state", "deleting")

    caido_client = bundle.get("caido_client")
    if caido_client is not None:
        try:
            await caido_client.aclose()
        except Exception:
            logger.debug("cleanup(%s): caido_client.aclose() raised", scan_id, exc_info=True)

    client = bundle["client"]
    if bundle["_teardown_state"] != "deleted":
        await client.delete(bundle["session"])
        bundle["_teardown_state"] = "deleted"
        logger.info("Cleaned up sandbox session for scan %s", scan_id)

    docker_client = getattr(client, "docker_client", None)
    if docker_client is not None:
        docker_client.close()


def lifecycle_snapshot() -> dict[str, int]:
    """Bounded aggregate telemetry; no scan IDs or session credentials."""
    return {
        "active_sessions": len(_SESSION_CACHE),
        "provisioning": len(_SESSION_STARTING),
        "locks": len(_SESSION_LOCKS),
        "cleanup_tasks": len(_CLEANUP_TASKS),
        "discard_tasks": len(_DISCARD_TASKS),
        "discarding_sessions": len(_SESSION_DISCARDING),
        "cleanup_failed": sum(
            bundle.get("_teardown_state") is not None for bundle in _SESSION_CACHE.values()
        ),
        "max_sessions": _session_limit(),
    }
