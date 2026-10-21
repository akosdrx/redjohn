"""Real Chromium -> persistent CLI -> Nuclei -> refresh, with explicit v3 bytes.

Only the owned application and its operator rules vary. No scanner, browser,
network namespace or production replay implementation is replaced by a double.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import ClassVar
from xml.etree import ElementTree as ET

import pytest

from tests import test_browser_token_pipeline as pipeline


VARIANTS = {
    "vendor-json-utf16": ("application/vnd.redjohn+json", "utf-16", "json", "/csrf"),
    "xml-latin1": ("application/xml", "iso-8859-1", "xml", "/request/csrf"),
}


@pytest.mark.parametrize("variant", list(VARIANTS))
async def test_actual_v3_chromium_capture_nuclei_refresh_restart_and_fixed_controls(
    tmp_path, monkeypatch, variant
):
    media, codec, location, selector = VARIANTS[variant]
    wire_type = media + "; charset=" + codec
    original_binding = pipeline._token_binding
    original_write = pipeline._private_json

    def token_binding(kind):
        if kind != "json":
            return original_binding(kind)
        return [
            {
                "location": location,
                "selector": selector,
                "occurrence": 0,
                "source": {"kind": "header", "name": "X-CSRF-Token"},
            }
        ]

    def private_json(path, value):
        if "rules" in value:
            for rule in value["rules"]:
                if rule["url"].endswith("/replay/json"):
                    rule.update(content_type=media, body_contract_version=3)
        original_write(path, value)

    class ExtendedFixture(pipeline.BrowserTokenHTTPSFixture):
        instances: ClassVar[list] = []

        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.wire_records = []
            self.instances.append(self)
            base = self.server.RequestHandlerClass

            class Handler(base):
                def _reply(self, status, body, content_type="text/plain"):
                    if self.command == "GET" and self.path == "/start" and status == 200:
                        old = (
                            b"await post('/replay/json', JSON.stringify(fields), "
                            b"{'Content-Type':'application/json'});"
                        )
                        assert body.count(old) == 1
                        if codec == "utf-16":
                            script = (
                                "const text=JSON.stringify({...fields,label:'café'});"
                                "const bytes=new Uint8Array(2+text.length*2);"
                                "bytes[0]=255;bytes[1]=254;"
                                "const view=new DataView(bytes.buffer);"
                                "for(let i=0;i<text.length;i++)"
                                "view.setUint16(2+i*2,text.charCodeAt(i),true);"
                            )
                        else:
                            script = (
                                'const text=\'<?xml version="1.0" encoding="iso-8859-1"?>\''
                                "+'<request><fixture_value>'+fields.fixture_value+'</fixture_value>'"
                                "+'<csrf>'+fields.csrf+'</csrf><label>café</label></request>';"
                                "const bytes=Uint8Array.from(text,c=>c.charCodeAt(0));"
                            )
                        script += (
                            "await post('/replay/json',bytes,{'Content-Type':"
                            + json.dumps(wire_type)
                            + "});"
                        )
                        body = body.replace(old, script.encode())
                    super()._reply(status, body, content_type)

            self.server.RequestHandlerClass = Handler

        def body_matches(self, path, content_type, body):
            if path != "/replay/json":
                return super().body_matches(path, content_type, body)
            self.wire_records.append((content_type, body))
            if content_type != wire_type:
                return False
            try:
                if location == "json":
                    data = json.loads(body.decode(codec))
                    assert body.startswith(b"\xff\xfe")
                else:
                    # Exact bounded bytes from the owned fixture, already
                    # validated by the production no-DTD XML replay contract.
                    tree = ET.fromstring(body)  # noqa: S314 - independent owned-fixture parser
                    data = {node.tag: node.text for node in tree}
                    assert b"caf\xe9" in body
                return data == {
                    "fixture_value": self.private_value,
                    "csrf": self.tokens[self.revision],
                    "label": "café",
                }
            except (ValueError, UnicodeError, ET.ParseError):
                return False

    monkeypatch.setattr(pipeline, "BrowserTokenHTTPSFixture", ExtendedFixture)
    monkeypatch.setattr(pipeline, "_token_binding", token_binding)
    monkeypatch.setattr(pipeline, "_private_json", private_json)
    if directory := os.environ.get("REDJOHN_EXTENDED_WIRE_MEASUREMENTS"):
        Path(directory).mkdir(parents=True, exist_ok=True)
        monkeypatch.setenv(
            "REDJOHN_BROWSER_TOKEN_MEASUREMENTS", str(Path(directory) / (variant + ".json"))
        )
    await pipeline.test_actual_chromium_post_capture_body_token_refresh_and_nuclei_restart(tmp_path)
    assert len(ExtendedFixture.instances) == 1
    fixture = ExtendedFixture.instances[0]
    assert len(fixture.wire_records) >= 7
    assert all(content_type == wire_type for content_type, _body in fixture.wire_records)
