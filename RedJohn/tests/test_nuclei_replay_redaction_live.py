"""Real pinned-engine regressions for protocol-word secrets and scalar POST JSON."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from http.server import BaseHTTPRequestHandler

import pytest
import yaml

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.tools.hunt.nuclei import NucleiAdapter, NucleiOptions, bundle_digest
from tests.test_nuclei_post_live import post_fixture_lock
from tests.test_replay_body_contract import post_fixture


@pytest.mark.parametrize(
    "body,auth_token,reflected_number",
    [
        (b"1", "redjohn-private-replay-auth", None),
        (b"true", "redjohn-private-replay-auth", None),
        (b'{"secret":"stdout"}', "redjohn-private-replay-auth", None),
        (b'{"secret":"ordinary-value"}', "stdout", None),
        (b'{"pin":1234}', "redjohn-private-replay-auth", "1234"),
    ],
    ids=[
        "numeric_json",
        "boolean_json",
        "body_protocol_word",
        "auth_protocol_word",
        "numeric_extractor_reflection",
    ],
)
async def test_actual_nuclei_private_protocol_words_never_become_false_negative(
    tmp_path, body, auth_token, reflected_number
):
    seen = []
    state = {"marker": True}

    class ReplayObserver(BaseHTTPRequestHandler):
        def do_POST(self):
            received = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            authenticated = self.headers.get("Authorization") == "Bearer " + auth_token
            seen.append((received == body, authenticated))
            response = b"redjohn-fixture-marker" if state["marker"] else b"fixed-control"
            if reflected_number is not None:
                response += (" pin=" + reflected_number).encode()
            self.send_response(200 if received == body and authenticated else 401)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = ReplayObserver
        url = fixture.origin + "/approved-replay"
        policy, surface, data = post_fixture("application/json", body)
        policy = replace(policy, allowed_origins=(fixture.origin,), allowed_replay_urls=(url,))
        surface = replace(surface, url=url)
        data["entries"][0]["origin"] = fixture.origin
        data["entries"][0]["allowed_requests"][0]["url"] = url
        data["entries"][0]["headers"]["Authorization"] = "Bearer " + auth_token
        binding = AuthReplayVault.from_mapping(data, policy).authorize(surface)
        lock = post_fixture_lock(tmp_path / "templates", "application/json")
        if reflected_number is not None:
            path = tmp_path / "templates" / "post.yaml"
            template = yaml.safe_load(path.read_bytes())
            template["http"][0]["extractors"] = [
                {"type": "regex", "group": 1, "regex": [r"pin=([0-9]+)"]}
            ]
            raw_template = yaml.safe_dump(template).encode()
            path.write_bytes(raw_template)
            files = {"post.yaml": hashlib.sha256(raw_template).hexdigest()}
            lock = replace(lock, files=files, bundle_sha256=bundle_digest(files))
        async with NativeFixtureSession(policy, tmp_path / "worker", lock) as session:
            for marker in (True, False):
                state["marker"] = marker
                responses, evidence = [], []
                proxy = BrowserEgressProxy(
                    policy,
                    tls_config=BrowserTLSConfig(fixture.ca_file),
                    request_replay=binding.rewrite_request,
                    on_response=lambda url, status, _headers, responses=responses: responses.append(
                        {"url": url, "status": status}
                    ),
                )
                await proxy.start()
                session.bind_proxy(proxy.url)
                adapter = NucleiAdapter(
                    session,
                    lock,
                    proxy_url=proxy.url,
                    response_observations=lambda responses=responses: tuple(responses),
                    auth_replay=binding,
                    evidence_sink=lambda raw, evidence=evidence: (
                        evidence.append(raw) or "private-safe-evidence"
                    ),
                )
                try:
                    result = await adapter.run(
                        url,
                        NucleiOptions(timeout_seconds=15, request_timeout=5),
                        policy=policy,
                    )
                    assert result["execution_status"] == "succeeded", result
                    assert result["coverage_status"] == "completed", result
                    assert len(result["findings"]) == int(marker), result
                    assert result["no_finding_observed"] is (not marker)
                    assert result["telemetry"]["http_requests"] == 1
                    assert proxy.forwarded_requests == 1
                    assert len(evidence) == 1 and "stdout" in evidence[0]
                    if marker:
                        record = json.loads(evidence[0]["stdout"].strip())
                        assert record["matcher-status"] is True
                        if reflected_number is not None:
                            assert record["extracted-results"] == ["[redacted]"]
                finally:
                    await adapter.cleanup()
                    session.bind_proxy(None)
                    await proxy.close()
        assert seen == [(True, True), (True, True)]
