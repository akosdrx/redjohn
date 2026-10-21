"""Actual pinned specialist engines over private v3 wire bodies and refresh.

Only the owned fixture, reviewed private rules and public projection vary. The
browser, host replay, scheduler, scanners and OAST receiver are real.
"""

import json
from email import policy as email_policy
from email.parser import BytesParser
from xml.etree import ElementTree as ET

import pytest

from tests import test_authenticated_schema_oast_live as pipeline


VARIANTS = {
    "vendor-json-utf16": ("application/vnd.redjohn+json", "utf-16", "json", "/value", "/csrf"),
    "xml-latin1": ("application/xml", "iso-8859-1", "xml", "/r/value", "/r/csrf"),
    "multipart-file-utf16": ("multipart/form-data", "utf-16", "multipart_file", "value", "csrf"),
}


@pytest.fixture
def extended_wire(monkeypatch, variant):
    media, codec, location, value_selector, token_selector = VARIANTS[variant]
    wire_type = media + "; charset=" + codec
    original_fixture = pipeline.AuthenticatedInputFixture
    original_config = pipeline.configuration
    original_json = pipeline._private_json
    original_publish = pipeline.publish_measurement
    instances = []

    class ExtendedFixture(original_fixture):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            instances.append(self)
            base = self.server.RequestHandlerClass

            class Handler(base):
                def reply(self, status, data, content_type="text/plain"):
                    if self.command == "GET" and self.path == "/start" and status == 200:
                        old = (
                            "body=JSON.stringify(fields);"
                            "headers['Content-Type']='application/json';"
                        )
                        assert data.count(old) == 1
                        if location == "json":
                            script = (
                                'const text=\'{"value":"untouched",\'+'
                                "JSON.stringify({...fields,label:'caf\\u00e9'}).slice(1);"
                                "body=new Uint8Array(2+text.length*2);body[0]=255;body[1]=254;"
                                "const view=new DataView(body.buffer);"
                                "for(let i=0;i<text.length;i++)"
                                "view.setUint16(2+i*2,text.charCodeAt(i),true);"
                            )
                        elif location == "xml":
                            script = (
                                'const text=\'<?xml version="1.0" encoding="iso-8859-1"?>\''
                                "+'<r><value>'+fields.value+'</value><csrf>'+fields.csrf+"
                                "'</csrf><private>'+fields.private+'</private><label>caf\\u00e9</label></r>';"
                                "body=Uint8Array.from(text,c=>c.charCodeAt(0));"
                            )
                        else:
                            script = (
                                "const text=String(fields.value);"
                                "const bytes=new Uint8Array(2+text.length*2);"
                                "bytes[0]=255;bytes[1]=254;const view=new DataView(bytes.buffer);"
                                "for(let i=0;i<text.length;i++)"
                                "view.setUint16(2+i*2,text.charCodeAt(i),true);"
                                "body=new FormData();body.append('value',new Blob([bytes],"
                                "{type:'text/plain; charset=utf-16'}),'reviewed.txt');"
                                "body.append('csrf',fields.csrf);body.append('private',fields.private);"
                                "body.append('upload',new Blob([new Uint8Array("
                                + json.dumps(list(pipeline.UPLOAD))
                                + ")],{type:'application/octet-stream'}),'fixture.bin');"
                            )
                        if location != "multipart_file":
                            script += "headers['Content-Type']=" + json.dumps(wire_type) + ";"
                        data = data.replace(old, script)
                    super().reply(status, data, content_type)

            self.server.RequestHandlerClass = Handler

        def fields(self, body, content_type):
            if location == "multipart_file":
                message = BytesParser(policy=email_policy.default).parsebytes(
                    ("Content-Type: " + content_type + "\r\n\r\n").encode() + body
                )
                parts = list(message.iter_parts())
                assert [p.get_param("name", header="content-disposition") for p in parts] == [
                    "value",
                    "csrf",
                    "private",
                    "upload",
                ]
                assert parts[0].get_filename() == "reviewed.txt"
                assert parts[0].get_content_charset() == "utf-16"
                assert parts[3].get_filename() == "fixture.bin"
                assert parts[3].get_payload(decode=True) == pipeline.UPLOAD
                return {
                    parts[i].get_param("name", header="content-disposition"): parts[i]
                    .get_payload(decode=True)
                    .decode("utf-16" if i == 0 else "utf-8")
                    for i in range(3)
                }
            assert content_type == wire_type
            if location == "json":
                assert body.startswith(b"\xff\xfe")
                assert body.decode(codec).startswith('{"value":"untouched",')
                return json.loads(body.decode(codec))
            root = ET.fromstring(body)  # noqa: S314 - independently parsed own, validated fixture
            assert b"caf\xe9" in body
            return {node.tag: node.text for node in root}

    def private_json(path, value):
        if "rules" in value:
            for rule in value["rules"]:
                rule["body_contract_version"] = 3
                rule["body_tokens"][0].update(
                    location="multipart" if location == "multipart_file" else location,
                    selector=token_selector,
                )
        original_json(path, value)

    def configuration(*args, **kwargs):
        policy, config = original_config(*args, **kwargs)
        for rule in config["continuous_replay"]["adapter_rules"]:
            rule.update(input_location=location, input_name=value_selector)
            if location == "json":
                rule["input_occurrence"] = 1
        return policy, config

    monkeypatch.setitem(pipeline.MEDIA, "json", media)
    monkeypatch.setattr(pipeline, "AuthenticatedInputFixture", ExtendedFixture)
    monkeypatch.setattr(pipeline, "configuration", configuration)
    monkeypatch.setattr(pipeline, "_private_json", private_json)
    monkeypatch.setattr(
        pipeline,
        "publish_measurement",
        lambda name, value: original_publish("extended-" + variant + "-" + name, value),
    )
    return instances


@pytest.mark.parametrize("variant", list(VARIANTS))
@pytest.mark.parametrize("tool", list(pipeline.CAPABILITIES))
@pytest.mark.parametrize("fixed", [False, True], ids=["positive", "fixed"])
@pytest.mark.parametrize("remote", [False, True], ids=["loopback", "remote"])
async def test_actual_extended_wire_specialist_positive_fixed_and_durable_restart(
    tmp_path, extended_wire, tool, fixed, remote
):
    await pipeline.test_actual_authenticated_post_formats_and_durable_restart(
        tmp_path, tool, "json", fixed, remote
    )
    assert len(extended_wire) == 1


@pytest.mark.parametrize("variant", list(VARIANTS))
@pytest.mark.parametrize("tool", list(pipeline.CAPABILITIES))
async def test_actual_extended_wire_specialist_refresh_recapture_without_restart(
    tmp_path, extended_wire, tool
):
    await pipeline.test_actual_refresh_recapture_and_adapter_in_same_scheduler(
        tmp_path, tool, "json"
    )
    assert len(extended_wire) == 1 and extended_wire[0].revision == "8"
