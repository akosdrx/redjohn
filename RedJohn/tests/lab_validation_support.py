"""Owned constant HTTP fixture for the public runtime's native E2E."""

from __future__ import annotations

import asyncio
import json
import sys

from redjohn.assessment.lab_contract import OwnedFixtureBinding
from redjohn.assessment.models import JobSpec, Surface


TARGET = """import json,sys,time
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from socketserver import TCPServer
fixed=FIXED_VALUE
mode=MODE_VALUE
requests=0
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  global requests
  if self.path!='/regression':
   self.send_response(404);self.end_headers();return
  requests+=1
  print(json.dumps({'request':self.path}),flush=True)
  if mode=='slow_after_capture' and requests>1: time.sleep(4)
  oversized=mode=='oversized_after_capture' and requests>1
  body=b'x'*70000 if oversized else b'owned-header-fixture'
  self.send_response(200)
  if fixed: self.send_header('X-Content-Type-Options','nosniff')
  self.send_header('Content-Length',str(len(body)))
  self.end_headers()
  try: self.wfile.write(body)
  except OSError: pass
 def log_message(self,*args): pass
class Server(ThreadingHTTPServer):
 allow_reuse_address=True
 daemon_threads=True
 def server_bind(self):
  TCPServer.server_bind(self)
  self.server_name='127.0.0.1';self.server_port=int(self.server_address[1])
server=Server(('127.0.0.1',int(sys.argv[1])),Handler)
print(json.dumps({'port':server.server_port}),flush=True)
server.serve_forever()
"""


class OwnedHeaderFixture:
    def __init__(self, *, fixed=False, port=0, mode="normal"):
        self.fixed, self.port, self.mode = fixed, port, mode
        self.process = None
        self._seen_requests = []

    async def __aenter__(self):
        source = TARGET.replace("FIXED_VALUE", repr(self.fixed)).replace(
            "MODE_VALUE", repr(self.mode)
        )
        self.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            "-S",
            "-c",
            source,
            str(self.port),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert self.process.stdout is not None
        ready = json.loads(await asyncio.wait_for(self.process.stdout.readline(), 5))
        self.port = ready["port"]
        self.url = f"http://127.0.0.1:{self.port}/regression"
        self.source = source.encode()
        self.binding = OwnedFixtureBinding(
            self.process,
            fixture_ref="owned-header-fixture",
            asset_ref="owned-http-asset",
            url=self.url,
            phase="fixed_control" if self.fixed else "candidate",
            source=source.encode(),
            deployment_ref="fixed-source" if self.fixed else "candidate-source",
        )
        return self

    def bind_asset(self, asset_id):
        self.binding = OwnedFixtureBinding(
            self.process,
            fixture_ref="owned-header-fixture",
            asset_ref=asset_id,
            url=self.url,
            phase="fixed_control" if self.fixed else "candidate",
            source=self.source,
            deployment_ref="fixed-source" if self.fixed else "candidate-source",
        )

    async def wait_requests(self, count):
        assert self.process is not None and self.process.stdout is not None
        async with asyncio.timeout(5):
            while len(self._seen_requests) < count:
                self._seen_requests.append(json.loads(await self.process.stdout.readline()))

    async def __aexit__(self, *_args):
        if self.process is not None and self.process.returncode is None:
            self.process.terminate()
            try:
                await asyncio.wait_for(self.process.wait(), 3)
            except TimeoutError:
                self.process.kill()
                await self.process.wait()
        if self.process is not None:
            remaining, _stderr = await self.process.communicate()
            self.requests = self._seen_requests + [
                json.loads(line) for line in remaining.splitlines()
            ]


async def candidate(store, policy, scheduler, fixture):
    surface = Surface(fixture.url, session_revision="7", workflow_state="owned_fixture_ready")
    surface_id = store.upsert_surface(policy.engagement_id, surface)
    spec = JobSpec(surface_id, "headers", "headers_audit", policy_revision=policy.revision)
    store.submit(policy, [spec])
    await scheduler.run_batch(max_jobs=1)
    finding = next(
        x
        for x in store.findings(policy.engagement_id)
        if x["payload"]["title"] == "Missing x-content-type-options"
    )
    return finding["id"], surface_id
