"""Real pinned Nuclei + verified HTTPS + host-only JSON/form/multipart replay.

The owned fixture performs no mutation. Missing installed engine capability is
reported as skipped; the separate contract tests use no real scan.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlencode

import yaml

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.models import Surface
from redjohn.assessment.native_session import NativeFixtureSession
from redjohn.assessment.policy import EngagementPolicy
from redjohn.assessment.tls_fixture import TLSFixtureServer
from redjohn.tools.hunt.nuclei import (
    HOST_REPLAY_BODY,
    NucleiAdapter,
    NucleiLock,
    NucleiOptions,
    TemplateSelection,
    bundle_digest,
)
from tests.test_nuclei_live import existing_live_lock


def post_fixture_lock(
    root: Path,
    content_type: str,
    path: str = "/approved-replay",
    *,
    binary_lock: NucleiLock | None = None,
) -> NucleiLock:
    """Own reviewed public-only template; usable by remote scheduler E2E too."""
    base = binary_lock or existing_live_lock()
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    raw = yaml.safe_dump(
        {
            "id": "redjohn-fixture-post",
            "info": {
                "name": "Owned harmless authenticated POST fixture",
                "author": "RedJohn",
                "severity": "info",
            },
            "http": [
                {
                    "method": "POST",
                    "path": ["{{RootURL}}" + path],
                    "headers": {"Content-Type": content_type},
                    "body": HOST_REPLAY_BODY,
                    "matchers": [{"type": "word", "words": ["redjohn-fixture-marker"]}],
                }
            ],
        },
        sort_keys=False,
    ).encode()
    (root / "post.yaml").write_bytes(raw)
    files = {"post.yaml": hashlib.sha256(raw).hexdigest()}
    return replace(
        base,
        bundle_root=str(root),
        bundle_version="redjohn-owned-post-fixture-v1",
        bundle_sha256=bundle_digest(files),
        bundle_source="RedJohn owned harmless POST integration fixture",
        bundle_license="Apache-2.0",
        files=files,
        templates=(
            TemplateSelection(
                "post.yaml",
                "redjohn-fixture-post",
                ("isolated-lab",),
                effect="authenticated-replay",
            ),
        ),
    )


def replay_body_cases(private_value: str) -> tuple[tuple[str, str, bytes], ...]:
    """Real byte payloads, including Unicode and a binary multipart upload."""
    boundary = "redjohn_owned_fixture_boundary_1"
    return (
        (
            "json",
            "application/json",
            json.dumps({"fixture_value": private_value, "label": "árvíztűrő"}).encode(),
        ),
        (
            "form",
            "application/x-www-form-urlencoded",
            urlencode({"fixture_value": private_value, "label": "árvíztűrő"}).encode(),
        ),
        (
            "multipart",
            "multipart/form-data; boundary=" + boundary,
            (
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="fixture_value"\r\n\r\n'
                f"{private_value}\r\n"
                f"--{boundary}\r\n"
                'Content-Disposition: form-data; name="upload"; filename="fixture.bin"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + b"redjohn-binary\x00\x01\xff\r\n"
            + f"--{boundary}--\r\n".encode(),
        ),
    )


async def test_actual_nuclei_https_post_json_form_multipart_and_fixed_controls(
    tmp_path: Path,
):
    from base64 import b64encode  # noqa: PLC0415

    binary_lock = existing_live_lock()
    credential = secrets.token_urlsafe(32)
    private_value = secrets.token_urlsafe(32)
    state = {"body": b"", "content_type": "", "marker": True}
    observed: list[dict] = []
    measurements: list[dict] = []
    raw_evidence: list[dict] = []

    class ReplayHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            authorized = self.headers.get("Authorization") == "Bearer " + credential
            correct_body = body == state["body"]
            correct_type = self.headers.get("Content-Type") == state["content_type"]
            observed.append(
                {
                    "method": "POST",
                    "path": self.path,
                    "authorized": authorized,
                    "body_matches": correct_body,
                    "content_type_matches": correct_type,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                }
            )
            status = 200 if authorized and correct_body and correct_type else 401
            response = (
                b"redjohn-fixture-marker" if status == 200 and state["marker"] else b"fixed-control"
            )
            self.send_response(status)
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)

        def log_message(self, *_args):
            pass

    with TLSFixtureServer() as fixture:
        fixture.server.RequestHandlerClass = ReplayHandler
        url = fixture.origin + "/approved-replay"
        policy = EngagementPolicy(
            "post-live",
            "owner",
            (fixture.origin,),
            profile="isolated-lab",
            egress_mode="local-fixture",
            actor_ids=("anonymous", "alice"),
            allowed_replay_urls=(url,),
        )
        for kind, content_type, body in replay_body_cases(private_value):
            state.update(body=body, content_type=content_type, marker=True)
            digest = hashlib.sha256(body).hexdigest()
            surface = Surface(
                url,
                method="POST",
                content_type=content_type,
                body_sha256=digest,
                actor_id="alice",
                tenant_id="tenant-a",
                session_revision="7",
                request_ref="actual-post-" + kind,
            )
            vault = AuthReplayVault.from_mapping(
                {
                    "version": 2,
                    "entries": [
                        {
                            "engagement_id": policy.engagement_id,
                            "owner_id": policy.owner_id,
                            "actor_id": "alice",
                            "tenant_id": "tenant-a",
                            "session_revision": "7",
                            "policy_revision": policy.revision,
                            "expires_at": time.time() + 300,
                            "origin": fixture.origin,
                            "allowed_requests": [
                                {
                                    "url": url,
                                    "method": "POST",
                                    "request_ref": surface.request_ref,
                                    "content_type": content_type,
                                    "body_base64": b64encode(body).decode(),
                                    "body_sha256": digest,
                                    "replay_safety": "operator-approved",
                                }
                            ],
                            "headers": {"Authorization": "Bearer " + credential},
                            "cookies": [],
                        }
                    ],
                },
                policy,
            )
            binding = vault.authorize(surface)
            lock = post_fixture_lock(
                tmp_path / (kind + "-templates"), content_type, binary_lock=binary_lock
            )
            lock.validate()
            async with NativeFixtureSession(policy, tmp_path / (kind + "-worker"), lock) as session:
                for marker in (True, False):
                    state["marker"] = marker
                    responses: list[dict] = []
                    proxy = BrowserEgressProxy(
                        policy,
                        tls_config=BrowserTLSConfig(upstream_ca_file=fixture.ca_file),
                        request_replay=binding.rewrite_request,
                        on_response=lambda url, status, headers, responses=responses: (
                            responses.append({"url": url, "status": status, "headers": headers})
                        ),
                    )
                    await proxy.start()
                    session.bind_proxy(proxy.url)
                    started = time.monotonic()
                    before = len(observed)
                    try:
                        adapter = NucleiAdapter(
                            session,
                            lock,
                            proxy_url=proxy.url,
                            response_observations=lambda responses=responses: tuple(responses),
                            auth_replay=binding,
                            evidence_sink=lambda raw: raw_evidence.append(raw) or "post-raw-ref",
                        )
                        result = await adapter.run(
                            url, NucleiOptions(timeout_seconds=30), policy=policy
                        )
                    finally:
                        session.bind_proxy(None)
                        await proxy.close()
                    assert result["execution_status"] == "succeeded", result
                    assert result["coverage_status"] == "completed", result
                    assert len(result["findings"]) == int(marker), result
                    assert result["no_finding_observed"] is not marker
                    assert len(observed) - before == 1
                    assert all(
                        row["authorized"] and row["body_matches"] and row["content_type_matches"]
                        for row in observed[before:]
                    )
                    measurements.append(
                        {
                            "kind": kind,
                            "control": "marker" if marker else "fixed",
                            "duration_seconds": time.monotonic() - started,
                            "http_requests": len(observed) - before,
                            "body_bytes": len(body),
                            "body_sha256": digest,
                            "response_statuses": [row["status"] for row in responses],
                            "execution_status": result["execution_status"],
                            "coverage_status": result["coverage_status"],
                            "finding_count": len(result["findings"]),
                            "no_finding_observed": result["no_finding_observed"],
                        }
                    )
            assert credential not in json.dumps(raw_evidence)
            assert private_value not in json.dumps(raw_evidence)
            assert all(
                secret not in path.read_bytes()
                for path in (tmp_path / (kind + "-worker")).rglob("*")
                if path.is_file()
                for secret in (credential.encode(), private_value.encode(), body)
            )
        assert len(observed) == 6
    if output := os.environ.get("REDJOHN_POST_E2E_MEASUREMENTS"):
        Path(output).write_text(
            json.dumps(
                {
                    "binary_version": binary_lock.binary_version,
                    "binary_sha256": binary_lock.binary_sha256,
                    "cases": measurements,
                    "http_requests": len(observed),
                    "model_calls": 0,
                },
                indent=2,
            )
            + "\n"
        )
