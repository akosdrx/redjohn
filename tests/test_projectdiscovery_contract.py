"""Input, registry and persistence contracts; no external tool is run here."""

import json
import re
import time
from contextlib import closing
from dataclasses import replace

import pytest

from redjohn.assessment.browser_tls import BrowserTLSConfig
from redjohn.assessment.discovery_tools import (
    DiscoveryToolConfig,
    discovery_argv,
    katana_scope,
    request_identity,
)
from redjohn.assessment.models import JobSpec, Surface
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.registry import CapabilityRegistry
from redjohn.assessment.runtime import AssessmentRuntime
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.vulnx import (
    IntelligenceCache,
    VulnXConfig,
    VulnXIntelligenceAdapter,
    vulnx_argv,
)


def document(tool, binary="/approved/engine"):
    return {
        "binary": {
            "path": str(binary),
            "sha256": "a" * 64,
            "version": {"httpx": "1.12.0", "katana": "1.8.0", "vulnx": "2.0.2"}[tool],
        }
    }


def policy():
    return EngagementPolicy(
        "pd-contract",
        "operator",
        ("https://127.0.0.1:12345",),
        profile="isolated-lab",
        egress_mode="local-fixture",
    )


def intelligence_document(binary="/approved/vulnx"):
    return {
        **document("vulnx", binary),
        "cve_ids": ["CVE-2024-3094"],
        "api_url": "https://127.0.0.1:12346",
        "api_ips": ["127.0.0.1"],
    }


@pytest.mark.parametrize("tool", ["httpx", "katana"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("additional_args", ["-hl"]),
        ("config", "/secret"),
        ("output", "/unapproved/result"),
        ("rate_limit", True),
        ("rate_limit", 11),
        ("request_timeout", 0),
    ],
)
def test_rejects_unreviewed_discovery_settings(tool, field, value):
    with pytest.raises(ValueError):
        DiscoveryToolConfig.from_mapping(tool, {**document(tool), field: value})


@pytest.mark.parametrize(
    "field,value",
    [
        ("depth", True),
        ("depth", 4),
        ("max_pages", 33),
        ("js_crawl", "yes"),
        ("headless", True),
        ("automatic_form_fill", True),
    ],
)
def test_katana_limits_and_no_hidden_browser(field, value):
    with pytest.raises(ValueError):
        DiscoveryToolConfig.from_mapping("katana", {**document("katana"), field: value})


@pytest.mark.parametrize("tool", ["httpx", "katana"])
def test_typed_argv_and_semantic_revision(tool):
    config = DiscoveryToolConfig.from_mapping(tool, document(tool))
    updated = DiscoveryToolConfig.from_mapping(
        tool, {**document(tool), "rate_limit": 1, "request_timeout": 15}
    )
    assert config.revision == updated.revision
    argv = discovery_argv(config, policy().allowed_origins[0] + "/", "http://127.0.0.1:9999")
    assert "-proxy" in argv and "-duc" in argv
    assert not set(argv) & {"-hl", "-hh", "-aff", "-kb", "-sr", "-pdu", "-fr", "-fhr", "-config"}
    if tool == "httpx":
        assert "-nfs" in argv and argv[argv.index("-x") + 1] == "GET"
    else:
        assert "-ob" not in argv and "-eof" in argv and "-dr" in argv
        assert config.revision != replace(config, depth=1).revision


@pytest.mark.parametrize("tool", ["httpx", "katana"])
@pytest.mark.parametrize(
    "surface",
    [
        Surface("https://127.0.0.1:12345/", method="POST"),
        Surface("https://127.0.0.1:12345/", actor_id="alice"),
        Surface("https://127.0.0.1:12345/#frag"),
        Surface("https://127.0.0.1:12345"),
        Surface("https://127.0.0.1:12345/path,/unapproved-file"),
        Surface("https://127.0.0.1:12345/", content_type="application/json"),
    ],
)
def test_discovery_rejects_unsupported_request_context(tool, surface):
    config = DiscoveryToolConfig.from_mapping(tool, document(tool))
    spec = JobSpec(
        "surface", "discovery", tool, tool_version=config.version, template_version=config.revision
    )
    with pytest.raises((ValueError, PolicyDenied)):
        config.validate_input(policy(), surface, spec)


@pytest.mark.parametrize(
    "tool,capability",
    [("httpx", "httpx_probe"), ("katana", "katana_discover"), ("vulnx", "vulnx_intelligence")],
)
async def test_registry_presence_is_lazy_and_configuration_missing_is_blocked(
    tmp_path, monkeypatch, tool, capability
):
    async def forbidden(*_args, **_kwargs):
        raise AssertionError("optional process started during registration/health")

    monkeypatch.setattr("redjohn.assessment.pinned_tools.PinnedToolRunner.execute", forbidden)
    binary = tmp_path / tool
    binary.write_text("presence only")
    binary.chmod(0o700)
    config = intelligence_document(binary) if tool == "vulnx" else document(tool, binary)
    registry = CapabilityRegistry(**{tool + "_config": config})
    row = next(row for row in registry.health() if row["id"] == capability)
    assert row["adapter_implemented"] and row["binary_presence_only"] and not row["live_verified"]
    assert row["binary_path_source"] == "configured"
    binary.unlink()
    assert (
        next(row for row in registry.health() if row["id"] == capability)["status"]
        == "blocked_missing_dependency"
    )
    with closing(AssessmentStore(tmp_path / "state.db")) as store:
        async with AssessmentRuntime(store, policy(), caller="operator") as runtime:
            surface_id = store.upsert_surface(
                policy().engagement_id, Surface(policy().allowed_origins[0] + "/")
            )
            store.submit(policy(), [JobSpec(surface_id, "discovery", capability)])
            await runtime.scheduler.run_batch(max_jobs=1)
            result = store.jobs(policy().engagement_id)[0]["result"]
            assert result["coverage_status"] == "blocked"
            assert result["error"]["code"] == capability + "_configuration_missing"


@pytest.mark.parametrize(
    "field,value",
    [
        ("cve_ids", ["internal.company"]),
        ("cve_ids", ["https://private/asset"]),
        ("cve_ids", ["--output"]),
        ("api_ips", ["0.0.0.0/0"]),
        ("api_url", "https://unreviewed.example"),
        ("api_url", "http://127.0.0.1:12346"),
        ("ttl_seconds", True),
        ("query", "private-product"),
    ],
)
def test_vulnx_rejects_asset_queries_and_implicit_egress(field, value):
    with pytest.raises((ValueError, PolicyDenied)):
        VulnXConfig.from_mapping({**intelligence_document(), field: value})


def test_vulnx_service_scope_does_not_expand_active_target_scope():
    config, original = VulnXConfig.from_mapping(intelligence_document()), policy()
    service = config.service_policy(original)
    service.check_scope_url(config.api_url)
    with pytest.raises(PolicyDenied, match="origin_denied"):
        original.check_scope_url(config.api_url)
    assert original.allowed_origins == ("https://127.0.0.1:12345",)
    assert "CVE-2024-3094" in vulnx_argv(config, "CVE-2024-3094", "http://127.0.0.1:9999")
    with pytest.raises(ValueError, match="unapproved"):
        vulnx_argv(config, "CVE-2000-0000", "http://127.0.0.1:9999")


@pytest.mark.parametrize(
    "url", ["https://api.projectdiscovery.io", "https://api.projectdiscovery.io:443"]
)
def test_public_provider_default_https_port_is_normalized(url):
    config = VulnXConfig.from_mapping(
        {**intelligence_document(), "api_url": url, "api_ips": ["35.211.43.232"]}
    )
    assert config.api_url == "https://api.projectdiscovery.io"


def test_intelligence_cache_is_durable_bounded_and_does_not_delete_evidence(tmp_path):
    path = tmp_path / "state.db"
    with closing(AssessmentStore(path)) as store:
        store.register(policy())
        ref = store.evidence_put(
            policy().engagement_id, {"source": "contract fixture"}, kind="test"
        )
        cache = IntelligenceCache(store, policy().engagement_id)
        for i in range(129):
            cache.put(str(i), {"fetched_at": time.time(), "evidence_ref": ref}, 300)
        assert cache.get("0") is None and cache.get("128")["evidence_ref"] == ref
        assert store.evidence_get(policy().engagement_id, ref)
        with pytest.raises(ValueError, match="record_limit"):
            cache.put("oversize", {"value": "x" * 8192}, 300)
    with closing(AssessmentStore(path)) as store:
        cache = IntelligenceCache(store, policy().engagement_id)
        assert cache.get("128")["evidence_ref"] == ref
        with store.transaction() as db:
            db.execute("UPDATE rj_intelligence_cache SET expires=0")
        assert cache.get("128") is None
        assert store.evidence_get(policy().engagement_id, ref)


def test_vulnx_match_never_becomes_dynamic_finding(tmp_path):
    config = VulnXConfig.from_mapping(intelligence_document())
    with closing(AssessmentStore(tmp_path / "state.db")) as store:
        store.register(policy())
        target_tls = BrowserTLSConfig(upstream_ca_file="/explicit/target-only-ca.pem")
        adapter = VulnXIntelligenceAdapter(config, policy(), store, None, tls_config=target_tls)
        assert adapter.tls_config is target_tls
        public = VulnXConfig.from_mapping(
            {
                **intelligence_document(),
                "api_url": "https://api.projectdiscovery.io",
                "api_ips": ["35.211.43.232"],
            }
        )
        assert (
            VulnXIntelligenceAdapter(
                public, policy(), store, None, tls_config=target_tls
            ).tls_config
            is None
        )
        raw = {
            "stdout": json.dumps(
                {"cve_id": "CVE-2024-3094", "product": "xz", "severity": "critical", "is_kev": True}
            ),
            "exit_code": 0,
        }
        result = adapter.normalize("CVE-2024-3094", raw, 200)
        assert result["applicability"] == "unknown" and not result["dynamic_finding"]
        assert result["data_version"].startswith("unversioned-content:") and result["fetched_at"]
        with pytest.raises(ValueError, match="schema_error"):
            adapter.normalize("CVE-2024-3094", {**raw, "stdout": "{}"}, 200)


async def test_planner_uses_configured_discovery_but_intelligence_is_explicit(tmp_path):
    binaries = {}
    for tool in ("httpx", "katana"):
        binary = tmp_path / tool
        binary.write_text("presence contract; never executed")
        binary.chmod(0o700)
        binaries[tool + "_config"] = document(tool, binary)
    with closing(AssessmentStore(tmp_path / "state.db")) as store:
        async with AssessmentRuntime(store, policy(), caller="operator", **binaries) as runtime:
            store.upsert_surface(policy().engagement_id, Surface(policy().allowed_origins[0] + "/"))
            plan = runtime.control.engine.plan(store, policy())
            choices = {row["spec"]["capability"]: row["spec"] for row in plan["jobs"]}
            assert {"httpx_probe", "katana_discover"} <= set(choices)
            assert "vulnx_intelligence" not in choices
            assert choices["httpx_probe"]["tool_version"] == "1.12.0"
            assert (
                choices["katana_discover"]["template_version"]
                == runtime.registry.execution_versions("katana_discover")["template_version"]
            )


def test_katana_scope_handles_default_ports_without_admitting_other_origins():
    pattern = katana_scope("https://Owned.Example:443/root")
    assert re.match(pattern, "https://owned.example/child")
    assert re.match(pattern, "https://owned.example:443/child")
    assert not re.match(pattern, "https://owned.example:444/child")
    assert not re.match(pattern, "https://owned.example.evil/child")
    assert not re.match(pattern, "http://owned.example/child")


def test_origin_spelling_reconciliation_preserves_request_semantics():
    original = "https://Owned.Example/a%2fb?x=1&x=2&blank="
    assert request_identity(original) == "https://owned.example:443/a%2fb?x=1&x=2&blank="
    assert request_identity(original) != request_identity(original.replace("a%2fb", "a%2Fb"))
    assert request_identity(original) != request_identity(original.replace("x=1&x=2", "x=2&x=1"))
    assert request_identity("https://owned.example/path?") != request_identity(
        "https://owned.example/path"
    )
