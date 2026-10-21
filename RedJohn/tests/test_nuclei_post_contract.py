"""POST template contract tests; these do not claim actual scanner execution."""

from __future__ import annotations

from dataclasses import replace

import pytest
import yaml

from redjohn.tools.hunt.nuclei import (
    HOST_REPLAY_BODY,
    NucleiContractError,
    TemplateSelection,
    validate_template,
)


POST_SELECTION = TemplateSelection(
    "post.yaml", "fixture-post", ("isolated-lab",), effect="authenticated-replay"
)


def post_template(content_type: str = "application/json") -> dict:
    return {
        "id": "fixture-post",
        "info": {"name": "Harmless authenticated POST fixture", "author": "RedJohn"},
        "http": [
            {
                "method": "POST",
                "path": ["{{RootURL}}/approved-replay"],
                "headers": {"Content-Type": content_type},
                "body": HOST_REPLAY_BODY,
                "matchers": [{"type": "word", "words": ["redjohn-fixture-marker"]}],
            }
        ],
    }


@pytest.mark.parametrize(
    "content_type",
    [
        "application/json",
        "application/json; charset=utf-8",
        "application/x-www-form-urlencoded",
        "application/x-www-form-urlencoded; charset=utf-8",
        "multipart/form-data; boundary=redjohn_fixture-1",
        "application/vnd.redjohn+json; charset=utf-16",
        "application/xml; charset=iso-8859-1",
        'application/soap+xml; charset="windows-1252"',
        "application/x-www-form-urlencoded; charset=windows-1250",
    ],
)
def test_post_contract_accepts_only_explicit_public_placeholder(content_type):
    assert (
        validate_template(yaml.safe_dump(post_template(content_type)).encode(), POST_SELECTION) == 1
    )


@pytest.mark.parametrize(
    "change",
    [
        {"body": '{"password":"secret"}'},
        {"body": ""},
        {"body": HOST_REPLAY_BODY + "\n"},
        {"body": "{{read_file('/etc/passwd')}}"},
        {"headers": {"Authorization": "Bearer embedded-secret"}},
        {"headers": {"Content-Type": "application/json", "X-Secret": "embedded"}},
        {"headers": {"content-type": "application/json"}},
        {"headers": {"Content-Type": "text/plain"}},
        {"headers": {"Content-Type": 'multipart/form-data; boundary="quoted"'}},
        {"headers": {"Content-Type": "application/xml; charset=utf-7"}},
        {"headers": {"Content-Type": "application/json; charset=utf-8; charset=utf-16"}},
        {"headers": {"Content-Type": "application/xml; profile=arbitrary"}},
        {"headers": {"Content-Type": "application/xml\r\nAuthorization: injected"}},
        {"raw": ["POST /approved-replay HTTP/1.1"]},
        {"redirects": True},
        {"method": "PUT"},
    ],
)
def test_post_contract_rejects_body_secrets_and_dynamic_or_unreviewed_shape(change):
    value = post_template()
    value["http"][0].update(change)
    with pytest.raises(NucleiContractError):
        validate_template(yaml.safe_dump(value).encode(), POST_SELECTION)


def test_post_contract_requires_accurate_effect_and_nonproduction_profile():
    raw = yaml.safe_dump(post_template()).encode()
    with pytest.raises(NucleiContractError):
        validate_template(raw, replace(POST_SELECTION, effect="read-only"))
    with pytest.raises(NucleiContractError):
        validate_template(raw, replace(POST_SELECTION, profiles=("safe-production",)))
