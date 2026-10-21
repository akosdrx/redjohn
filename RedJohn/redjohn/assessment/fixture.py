"""Harmless local SPA/API regression fixture; does not emulate or prove RCE."""

from __future__ import annotations

import json
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from socketserver import TCPServer
from typing import TYPE_CHECKING, Literal, Self, TypedDict
from urllib.parse import urlsplit


if TYPE_CHECKING:
    from collections.abc import Callable


class FixtureCookie(TypedDict):
    name: str
    value: str
    domain: str
    path: str
    expires: int
    httpOnly: bool
    secure: bool
    sameSite: Literal["Lax"]


class FixtureStorageState(TypedDict):
    cookies: list[FixtureCookie]
    origins: list[dict[str, object]]


PAGE = b"""<!doctype html><html><title>RedJohn local fixture</title><body>
<div id="ready">local fixture</div><a href="/logout">Do not follow</a>
<form action="/api/update" method="post"><input name="name"></form>
<form action="/api/upload" method="post" enctype="multipart/form-data">
<input name="file" type="file"></form>
<script>
window.history.replaceState({}, '', '/spa/dashboard');
fetch('/api/me').then(r=>r.json()).then(x=>document.body.dataset.actor=x.actor);
fetch('/api/search?q=one&q=two&encoded=%2f');
let x=new XMLHttpRequest();x.open('GET','/api/items');x.send();
fetch('/api/json',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify({q:'marker'})});
fetch('/api/xml',{method:'POST',headers:{'Content-Type':'application/xml'},body:'<q>marker</q>'});
let link=document.createElement('a');link.href='/api/dynamic';link.textContent='Dynamic';
document.body.append(link);
</script></body></html>"""


class _LiteralLoopbackHTTPServer(ThreadingHTTPServer):
    """Bind the owned numeric address without initializing a global resolver.

    HTTPServer.server_bind reverse-resolves its address with getfqdn, retaining
    a process-global resolver socket on macOS. A literal-loopback fixture needs
    neither a hostname lookup nor that lifetime outside its own server socket.
    """

    def server_bind(self) -> None:
        TCPServer.server_bind(self)
        self.server_name = str(self.server_address[0])
        self.server_port = int(self.server_address[1])


class FixtureServer:
    def __init__(self) -> None:
        self.counts: Counter[str] = Counter()
        self.fixed = False
        self._get_observer: Callable[[BaseHTTPRequestHandler], None] | None = None
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                if fixture._get_observer is not None:
                    fixture._get_observer(self)
                path = urlsplit(self.path).path
                fixture.counts[path] += 1
                if path == "/rate-limit":
                    self.send_response(429)
                    self.send_header("Retry-After", "1")
                    self.end_headers()
                    return
                if path == "/expired":
                    self.send_response(401)
                    self.end_headers()
                    return
                if path == "/denied":
                    self.send_response(403)
                    self.end_headers()
                    return
                if path == "/offscope":
                    self.send_response(302)
                    self.send_header(
                        "Location", f"http://localhost:{fixture.server.server_port}/forbidden"
                    )
                    self.end_headers()
                    return
                body = (
                    PAGE
                    if path in {"/", "/spa/dashboard"}
                    else json.dumps(
                        {
                            "actor": self.headers.get("Cookie", "anonymous").removeprefix(
                                "fixture_actor="
                            ),
                            "path": self.path,
                        }
                    ).encode()
                )
                self.send_response(200)
                self.send_header(
                    "Content-Type",
                    "text/html" if path in {"/", "/spa/dashboard"} else "application/json",
                )
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-RedJohn-Fixture", "fixed" if fixture.fixed else "initial")
                if fixture.fixed:
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("Content-Security-Policy", "default-src 'self'")
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self) -> None:
                fixture.counts["unexpected_post"] += 1
                self.send_response(405)
                self.end_headers()

            def log_message(self, _format: str, *_args: object) -> None:
                pass

        self.server = _LiteralLoopbackHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def origin(self) -> str:
        return f"http://127.0.0.1:{self.server.server_port}"

    def actor_state(self, actor: str) -> FixtureStorageState:
        return {
            "cookies": [
                {
                    "name": "fixture_actor",
                    "value": actor,
                    "domain": "127.0.0.1",
                    "path": "/",
                    "expires": -1,
                    "httpOnly": True,
                    "secure": False,
                    "sameSite": "Lax",
                }
            ],
            "origins": [],
        }

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
