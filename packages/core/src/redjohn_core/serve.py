"""Engine entrypoint: ``python -m redjohn_core.serve [--host H] [--port N] [--profile P]``.

Binds loopback by default. The bearer token lives in ``<profile>/token``
(0600) and is never printed or put in a URL.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys
from contextlib import asynccontextmanager
from typing import Any

from .api import create_app
from .engine import Engine
from .locking import EngineAlreadyRunning
from .settings import DEFAULT_HOST, DEFAULT_PORT, Settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redjohn_core.serve")
    parser.add_argument("--host", default=None)
    parser.add_argument("--port", type=int, default=None)
    parser.add_argument("--profile", default=None)
    args = parser.parse_args(argv)

    if args.profile:
        settings = Settings.load(environ={**os.environ, "REDJOHN_PROFILE": args.profile})
    else:
        settings = Settings.load()
    host = args.host or settings.bind_host or DEFAULT_HOST
    port = args.port or settings.port or DEFAULT_PORT
    object.__setattr__(settings, "bind_host", host)
    object.__setattr__(settings, "port", port)
    # Resolve native tools from the writable per-profile directory, where the
    # lightweight scanners are downloaded on demand (nothing is bundled into the
    # app). An explicit RJ_TOOLS_DIR still overrides this for dev/testing.
    os.environ.setdefault("RJ_TOOLS_DIR", str(settings.profile_dir / "tools"))

    async def _serve() -> int:
        try:
            engine = await Engine.create(
                settings,
                auto_memory=os.environ.get("RJ_MEMORY_AUTO_START", "1") == "1"
                and settings.model_provider != "fixture",
            )
        except EngineAlreadyRunning as exc:
            print(f"redjohn-core: {exc}", file=sys.stderr)
            return 2
        import uvicorn

        application = create_app(engine)
        previous_lifespan = application.router.lifespan_context
        shutdown_started = False

        async def shutdown_engine() -> None:
            nonlocal shutdown_started
            if not shutdown_started:
                shutdown_started = True
                await engine.shutdown()

        @asynccontextmanager
        async def lifespan(app: Any):
            # Uvicorn re-raises captured SIGTERM after its ASGI lifespan exits.
            # Release SQLite, tool processes and the profile lock before that
            # happens; an outer serve() finally is too late for SIGTERM.
            async with previous_lifespan(app) as state:
                try:
                    yield state
                finally:
                    await shutdown_engine()

        application.router.lifespan_context = lifespan
        config = uvicorn.Config(
            application, host=host, port=port, log_level=settings.log_level.lower(),
            # Leave time for engine lifespan cleanup before desktop's 8s
            # escalation, even if a client leaves an idle request open.
            timeout_graceful_shutdown=3,
        )
        server = uvicorn.Server(config)
        print(f"redjohn-core listening on http://{host}:{port} "
              f"(profile={settings.data_profile}; token in {settings.token_path})",
              file=sys.stderr)
        try:
            await server.serve()
        finally:
            # Also cover startup failures before ASGI lifespan was entered.
            await shutdown_engine()
        return 0

    try:
        return asyncio.run(_serve())
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
