"""Actual Chromium/native engines with equivalent MIME wire representations.

Owned applications parse MIME independently with Python's email parser. Engine,
browser, TLS, refresh and Interactsh I/O remain real; no tool replies are mocked.
"""

from __future__ import annotations

import html
import json
import os
from email.message import Message
from pathlib import Path
from typing import ClassVar, override

import pytest
from jinja2 import TemplateError
from jinja2.sandbox import SandboxedEnvironment

from tests import test_authenticated_schema_oast_live as adapters
from tests import test_browser_token_pipeline as nuclei


def media(value):
    message = Message()
    message["Content-Type"] = value
    return message.get_content_type(), message.get_boundary()


def extended_page(body, *, adapter):
    if adapter:
        body = body.replace(
            b"headers['Content-Type']='application/json';",
            b"headers['Content-Type']='Application/JSON ; Charset=\"UTF-8\"';",
        ).replace(
            b"body=new URLSearchParams(fields).toString();"
            b"headers['Content-Type']='application/x-www-form-urlencoded';",
            b"body=new URLSearchParams(fields);",
        )
        body = body.replace(
            b"fetch('/input',{method:'POST'",
            b"if(body instanceof FormData){const r=new Request(location.origin+'/input',"
            b"{method:'POST',body});"
            b"const b=r.headers.get('Content-Type').split('boundary=')[1];"
            b"body=await r.arrayBuffer();"
            b"headers['Content-Type']='Multipart/Form-Data; BOUNDARY=\"'+b+'\"';}"
            b"fetch('/input',{method:'POST'",
        )
        # The original fixture uses a top-level script. Await only when serializing
        # Chromium's real FormData, under an asynchronous function scope.
        body = body.replace(b"<script>", b"<script>(async()=>{")
        body = body.replace(b"</script>", b"})();</script>")
    else:
        body = (
            body.replace(
                b"{'Content-Type':'application/json'}",
                b"{'Content-Type':'Application/JSON ; Charset=\"UTF-8\"'}",
            )
            .replace(
                b"new URLSearchParams(fields).toString(),\n    "
                b"{'Content-Type':'application/x-www-form-urlencoded'}",
                b"new URLSearchParams(fields)",
            )
            .replace(
                b"await post('/replay/multipart', multipart);",
                b"const r=new Request(location.origin+'/replay/multipart',"
                b"{method:'POST',body:multipart});"
                b"const b=r.headers.get('Content-Type').split('boundary=')[1];"
                b"await post('/replay/multipart',await r.arrayBuffer(),"
                b"{'Content-Type':'Multipart/Form-Data; BOUNDARY=\"'+b+'\"'});",
            )
        )
    return body


class MIMEInputFixture(adapters.AuthenticatedInputFixture):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        fixture = self
        base = self.server.RequestHandlerClass
        engine = SandboxedEnvironment()

        class Handler(base):
            def reply(self, code, data, content_type="text/plain"):
                if self.command == "GET" and self.path == "/start" and code == 200:
                    data = extended_page(
                        data.encode() if isinstance(data, str) else data, adapter=True
                    )
                super().reply(code, data, content_type)

            @override
            def do_POST(self):
                if self.path != "/input":
                    super().do_POST()
                    return
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                content_type = self.headers.get("Content-Type", "")
                fields = fixture.fields(body, content_type)
                valid = (
                    self.authorized()
                    and media(content_type)[0] == adapters.MEDIA[fixture.kind]
                    and fields.get("csrf") == fixture.csrf[fixture.revision]
                    and fields.get("private") == fixture.private_value
                )
                if fixture.kind == "multipart":
                    valid &= (
                        fields.get("upload") == adapters.UPLOAD
                        and fields.get("filename") == "fixture.bin"
                    )
                fixture.posts.append(
                    {
                        "path": self.path,
                        "valid": valid,
                        "revision": fixture.revision,
                        "body": body,
                        "content_type": content_type,
                        "value": fields.get("value"),
                    }
                )
                if not valid or fixture.fault in {"401", "truncated401"}:
                    self.reply(401, "actor expired")
                    return
                if fixture.fault in {"403", "429"}:
                    self.reply(int(fixture.fault), "owned rejection")
                    return
                value = fields["value"]
                if fixture.tool == "schemathesis":
                    self.reply(
                        200,
                        json.dumps({"id": int(value) if fixture.fixed else str(value)}),
                        "application/json",
                    )
                elif fixture.tool == "tinja":
                    try:
                        rendered = (
                            html.escape(str(value))
                            if fixture.fixed
                            else engine.from_string(str(value)).render()
                        )
                        self.reply(
                            200,
                            "<html><body><pre>template:" + rendered + "</pre></body></html>",
                            "text/html",
                        )
                    except TemplateError:
                        self.reply(500, "owned template error")
                else:
                    if str(value).startswith("http://"):
                        fixture.callbacks.append(value)
                        if not fixture.fixed and not fixture.late:
                            fixture.deliver_callback(value)
                    self.reply(200, "owned callback control")

        self.server.RequestHandlerClass = Handler


class MIMETokenFixture(nuclei.BrowserTokenHTTPSFixture):
    instances: ClassVar[list[MIMETokenFixture]] = []

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.wire_types = []
        self.instances.append(self)
        fixture, base = self, self.server.RequestHandlerClass

        class Handler(base):
            def _reply(self, status, body, content_type="text/plain"):
                if self.command == "GET" and self.path == "/start" and status == 200:
                    body = extended_page(body, adapter=False)
                super()._reply(status, body, content_type)

            @override
            def do_POST(self):
                if self.path.startswith("/replay/"):
                    fixture.wire_types.append((self.path, self.headers.get("Content-Type", "")))
                super().do_POST()

        self.server.RequestHandlerClass = Handler

    def body_matches(self, path, content_type, body):
        kind, boundary = media(content_type)
        normalized = kind + ("; boundary=" + boundary if boundary else "")
        return super().body_matches(path, normalized, body)


def use_mime_fixture(monkeypatch):
    monkeypatch.setattr(adapters, "AuthenticatedInputFixture", MIMEInputFixture)
    publish = adapters.publish_measurement
    monkeypatch.setattr(
        adapters, "publish_measurement", lambda name, payload: publish("mime-" + name, payload)
    )


@pytest.mark.parametrize("remote", [False, True], ids=["loopback", "remote"])
@pytest.mark.parametrize("fixed", [False, True], ids=["positive", "fixed"])
@pytest.mark.parametrize("kind", list(adapters.MEDIA))
@pytest.mark.parametrize("tool", list(adapters.CAPABILITIES))
async def test_actual_mime_post_preserves_wire_and_scanner_verdict(
    tmp_path, monkeypatch, tool, kind, fixed, remote
):
    use_mime_fixture(monkeypatch)
    await adapters.test_actual_authenticated_post_formats_and_durable_restart(
        tmp_path, tool, kind, fixed, remote
    )
    vault = json.loads((tmp_path / "private/vault.json").read_text())
    requests = [r for e in vault["entries"] for r in e["allowed_requests"] if r["method"] == "POST"]
    assert len(requests) == 1 and requests[0]["body_contract_version"] == 2
    content_type = requests[0]["content_type"]
    if kind == "json":
        assert content_type == 'Application/JSON ; Charset="UTF-8"'
    elif kind == "form":
        assert content_type == "application/x-www-form-urlencoded;charset=UTF-8"
    else:
        assert content_type.startswith('Multipart/Form-Data; BOUNDARY="')


@pytest.mark.parametrize("tool", list(adapters.CAPABILITIES))
@pytest.mark.parametrize("kind", list(adapters.MEDIA))
async def test_actual_mime_refresh_recaptures_rotated_body_without_restart(
    tmp_path, monkeypatch, tool, kind
):
    use_mime_fixture(monkeypatch)
    await adapters.test_actual_refresh_recapture_and_adapter_in_same_scheduler(tmp_path, tool, kind)


async def test_actual_mime_chromium_nuclei_refresh_and_independent_cli_restarts(
    tmp_path, monkeypatch
):
    MIMETokenFixture.instances.clear()
    monkeypatch.setattr(nuclei, "BrowserTokenHTTPSFixture", MIMETokenFixture)
    factory = nuclei.post_fixture_lock

    def canonical_template(directory, content_type, *args, **kwargs):
        # Public templates retain their existing canonical host-body placeholder;
        # the binding restores the exact approved wire header on the host.
        return factory(
            directory,
            media(content_type)[0] if not content_type.startswith("multipart/") else content_type,
            *args,
            **kwargs,
        )

    monkeypatch.setattr(nuclei, "post_fixture_lock", canonical_template)
    if directory := os.environ.get("REDJOHN_MIME_RESTART_MEASUREMENTS"):
        monkeypatch.setenv(
            "REDJOHN_BROWSER_TOKEN_MEASUREMENTS", str(Path(directory).parent / "nuclei-mime.json")
        )
    await nuclei.test_actual_chromium_post_capture_body_token_refresh_and_nuclei_restart(tmp_path)
    assert len(MIMETokenFixture.instances) == 1
    values = MIMETokenFixture.instances[0].wire_types
    assert any(c == 'Application/JSON ; Charset="UTF-8"' for _, c in values)
    assert any(c == "application/x-www-form-urlencoded;charset=UTF-8" for _, c in values)
    assert any(c.startswith('Multipart/Form-Data; BOUNDARY="') for _, c in values)
