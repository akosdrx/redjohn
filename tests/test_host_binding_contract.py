"""Approval, identity and mount contracts; no model, scanner or remote request."""

import json
from dataclasses import replace

import pytest

from redjohn.assessment.host_binding import (
    _configuration_hash,
    prepare_host_assessment,
)
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.runtime.session_manager import build_bind_mounts


def scan_for(url):
    return {
        "targets": [
            {
                "type": "web_application",
                "original": url,
                "details": {"target_url": url},
            }
        ]
    }


@pytest.fixture(autouse=True)
def approval_key(tmp_path, monkeypatch):
    key = tmp_path / "keys/host.key"
    monkeypatch.setenv("REDJOHN_ASSESSMENT_APPROVAL_KEY", str(key))
    monkeypatch.setenv("REDJOHN_RESOURCE_POOL_PATH", str(tmp_path / "pool.sqlite3"))
    return key


async def test_default_host_binding_imports_metadata_only_and_restores_signed_approval(tmp_path):
    scan = scan_for("https://example.invalid/app")
    output = tmp_path / "run"
    prepared = prepare_host_assessment(scan, "bound-scan", output)
    assert prepared is not None
    assert prepared.host.configured.policy.profile == "safe-production"
    assert prepared.host.configured.config["seeds"][0]["capabilities"] == []
    host = await prepared.start()
    deadline = host.configured.policy.deadline
    try:
        assert host.configured.store.jobs("bound-scan") == []
        assert host.configured.runtime.browser.healthcheck()["ready"] is False
        assert prepared.metadata()["control_tool"] == "assessment_control"
    finally:
        await host.close()
    snapshot = output / ".state/assessment-host.json"
    assert snapshot.stat().st_mode & 0o077 == 0
    restored = prepare_host_assessment(scan, "bound-scan", output)
    assert restored is not None
    assert restored.source == "approved_run_snapshot"
    assert restored.fingerprint == prepared.fingerprint
    host = await restored.start()
    try:
        assert host.configured.policy.deadline == deadline
        assert host.configured.store.jobs("bound-scan") == []
    finally:
        await host.close()


async def test_editing_snapshot_and_its_plain_hash_cannot_create_new_approval(tmp_path):
    scan = scan_for("https://example.invalid")
    prepared = prepare_host_assessment(scan, "bound-scan", tmp_path / "run")
    assert prepared is not None
    host = await prepared.start()
    await host.close()
    path = tmp_path / "run/.state/assessment-host.json"
    saved = json.loads(path.read_text())
    saved["configuration"]["policy"]["request_budget"] = 9999
    saved["configuration_sha256"] = _configuration_hash(saved["configuration"])
    path.write_text(json.dumps(saved))
    with pytest.raises(PolicyDenied, match="changed_without_approval"):
        prepare_host_assessment(scan, "bound-scan", tmp_path / "run")


def test_operator_file_is_not_allowed_to_expand_the_selected_scan_scope(tmp_path):
    config = {
        "policy": EngagementPolicy("bound-scan", "operator", ("https://other.invalid",)).to_dict()
    }
    path = tmp_path / "approved.json"
    original = json.dumps(config)
    path.write_text(original)
    with pytest.raises(PolicyDenied, match="assessment_scope_mismatch"):
        prepare_host_assessment(
            scan_for("https://example.invalid"), "bound-scan", tmp_path / "run", config_path=path
        )
    assert path.read_text() == original
    assert not (tmp_path / "run/.state/agents.db").exists()


def test_group_writable_operator_file_is_not_treated_as_host_approval(tmp_path):
    path = tmp_path / "approved.json"
    path.write_text(
        json.dumps(
            {
                "policy": EngagementPolicy(
                    "bound-scan", "operator", ("https://example.invalid",)
                ).to_dict()
            }
        )
    )
    path.chmod(0o660)
    with pytest.raises(PolicyDenied, match="not_owner_approved"):
        prepare_host_assessment(
            scan_for("https://example.invalid"), "bound-scan", tmp_path / "run", config_path=path
        )
    assert path.stat().st_mode & 0o077 == 0o060


def test_private_file_references_stay_out_of_prompt_metadata_and_resume_paths_are_absolute(
    tmp_path, monkeypatch
):
    monkeypatch.chdir(tmp_path)
    config = {
        "policy": EngagementPolicy(
            "bound-scan", "operator", ("https://example.invalid",)
        ).to_dict(),
        "auth_vault_file": "private-secret-vault.json",
    }
    path = tmp_path / "approved.json"
    path.write_text(json.dumps(config))
    prepared = prepare_host_assessment(
        scan_for("https://example.invalid"), "bound-scan", tmp_path / "run", config_path=path
    )
    assert prepared is not None
    assert prepared.host.configured.config["auth_vault_file"] == str(
        tmp_path / "private-secret-vault.json"
    )
    assert "private-secret-vault" not in json.dumps(prepared.metadata())
    assert "auth_vault" not in json.dumps(prepared.metadata())


def test_workspace_without_web_targets_does_not_invent_an_engagement_or_key(tmp_path, approval_key):
    assert prepare_host_assessment({"targets": []}, "workspace", tmp_path / "run") is None
    assert not approval_key.exists()
    assert not (tmp_path / "run").exists()


def test_control_plane_paths_have_readonly_nested_mounts_without_freezing_project_edits(tmp_path):
    project = tmp_path / "project"
    run = project / "redjohn_runs/owned"
    run.mkdir(parents=True)
    mounts = build_bind_mounts(
        [
            {
                "source_path": str(project),
                "workspace_subdir": "app",
                "protect_metadata": False,
            }
        ],
        protected_host_paths=(run,),
    )
    assert mounts[0]["read_only"] is False
    protected = next(row for row in mounts if row["source"] == str(run))
    assert protected["target"] == "/workspace/app/redjohn_runs/owned"
    assert protected["read_only"] is True


async def test_host_binding_requires_reapproval_after_database_policy_changes(tmp_path):
    prepared = prepare_host_assessment(
        scan_for("https://example.invalid"), "bound-scan", tmp_path / "run"
    )
    assert prepared is not None
    host = await prepared.start()
    try:
        updated = replace(host.configured.policy, revision="2", request_budget=42)
        host.configured.store.register(updated)
        result = await host.control.call("system_health", {"policy_revision": "2"})
        assert result["ok"] is False
        assert result["error"]["code"] == "policy_denied"
    finally:
        await host.close()


async def test_metadata_import_does_not_grant_network_execution(tmp_path, monkeypatch):
    def deny_dns(*_args, **_kwargs):
        raise AssertionError("metadata import or blocked submission resolved a target")

    monkeypatch.setattr("socket.getaddrinfo", deny_dns)
    prepared = prepare_host_assessment(
        scan_for("https://example.invalid"), "metadata-only", tmp_path / "run"
    )
    assert prepared is not None
    host = await prepared.start()
    try:
        store, policy = host.configured.store, host.configured.policy
        surface = store.surfaces(policy.engagement_id)[0]
        with pytest.raises(PolicyDenied, match="explicit_ip_allowlist"):
            policy.check_scope_url(surface["url"])
        result = await host.control.call(
            "jobs_submit_batch",
            {
                "policy_revision": policy.revision,
                "jobs": [
                    {"surface_id": surface["id"], "family": "traffic", "capability": "http_observe"}
                ],
            },
        )
        assert result["error"]["code"] == "policy_denied"
        assert store.jobs(policy.engagement_id) == []
        assert host.configured.runtime.browser.healthcheck()["ready"] is False
    finally:
        await host.close()


def test_inventory_authorization_preserves_origin_and_deadline_checks():
    policy = EngagementPolicy("metadata", "operator", ("https://approved.invalid",))
    policy.check_inventory_url("https://approved.invalid/resource")
    with pytest.raises(PolicyDenied, match="origin_denied"):
        policy.check_inventory_url("https://other.invalid/resource")
    with pytest.raises(PolicyDenied, match="campaign_deadline_exceeded"):
        replace(policy, deadline=1).check_inventory_url("https://approved.invalid/resource")
