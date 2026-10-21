"""Real owned-local HTTP / SQLite cache integration; no external provider claim."""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

from redjohn.tools.cve.cache import CveCache


async def test_real_local_http_refresh_is_singleflight_and_cached(tmp_path):
    """Owned real HTTP + SQLite; no public provider availability claim."""
    requests = []

    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            body = b'{"source":"owned-local-fixture","revision":1}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    cache = CveCache(tmp_path / "cache.sqlite3")
    try:
        async with httpx.AsyncClient(trust_env=False) as client:

            async def fetch():
                response = await client.get(f"http://127.0.0.1:{server.server_port}/advisory")
                response.raise_for_status()
                return response.json()

            results = await asyncio.gather(
                *(cache.get_or_refresh("owned-advisory", fetch, 60) for _ in range(12))
            )
            assert all(value[0]["revision"] == 1 for value in results)
            assert (await cache.get_or_refresh("owned-advisory", fetch, 60))[1] is True
        assert requests == ["/advisory"]
        assert cache.stats()["inflight"] == 0
    finally:
        await asyncio.to_thread(server.shutdown)
        server.server_close()
        worker.join(timeout=2)
