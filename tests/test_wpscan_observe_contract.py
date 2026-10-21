"""Real file/SQLite fences and MOCK native-protocol tests; no Ruby engine execution."""

import hashlib
import json
from dataclasses import replace

import pytest

from redjohn.assessment.models import AdapterResult
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied
from redjohn.assessment.store import AssessmentStore
from redjohn.assessment.wpscan_component import WPScanComponentSource, WPScanHTMLArtifact
from redjohn.assessment.wpscan_observe import (
    WPScanObserveAdapter,
    WPScanObserveConfig,
    wordpress_observe_job,
)
from redjohn.assessment.wpscan_runtime import (
    EXPECTED_RUNTIME,
    GEM_ARCHIVE_SHAS,
    REQUIRED_LICENSE_SHAS,
    RUBY_ARCHIVE_SHAS,
    RUBY_SOURCE_COMMIT,
    WPScanObservationRunner,
    WPScanRuntime,
    runtime_document,
)


def manifest_document():
    """Synthetic metadata validates schemas, never proves an installed runtime."""
    rows = [
        {"path": "ruby/bin/ruby", "sha256": "1" * 64, "executable": True},
        {"path": "ruby/lib/stdlib.rb", "sha256": "2" * 64, "executable": False},
        {"path": "packages/nokogiri/lib/nokogiri.rb", "sha256": "3" * 64, "executable": False},
        {"path": "native/libruby.so.3.3", "sha256": "4" * 64, "executable": False},
    ]
    rows += [
        {"path": path, "sha256": digest, "executable": False}
        for path, digest in REQUIRED_LICENSE_SHAS.items()
    ]
    return {
        "schema_version": 1,
        "architecture": "x86_64",
        "ruby_source_commit": RUBY_SOURCE_COMMIT,
        "ruby_archive_sha256": RUBY_ARCHIVE_SHAS["x86_64"],
        "gem_archive_sha256": GEM_ARCHIVE_SHAS,
        "runtime": EXPECTED_RUNTIME,
        "files": rows,
        "load_paths": ["ruby/lib", "packages/nokogiri/lib"],
        "expected_features": ["ruby/lib/stdlib.rb", "packages/nokogiri/lib/nokogiri.rb"],
        "license_files": list(REQUIRED_LICENSE_SHAS),
        "linked_libraries": [
            {
                "path": "native/libruby.so.3.3",
                "source_kind": "ruby_archive",
                "package": "ruby",
                "version": "3.3.12",
                "copyright_file": "licenses/ruby/COPYING",
            }
        ],
    }


def parsed_runtime(tmp_path, document=None):
    raw = json.dumps(manifest_document() if document is None else document).encode()
    path = tmp_path / "runtime.json"
    path.write_bytes(raw)
    return WPScanRuntime.from_mapping(
        {
            "root": str(tmp_path / "runtime"),
            "manifest_file": str(path),
            "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        }
    ).load_manifest()


def configured(tmp_path):
    body = b'<meta name="generator" content="WordPress 6.4.3">'
    page = tmp_path / "private-page.html"
    page.write_bytes(body)
    return WPScanObserveConfig(
        WPScanComponentSource(
            tmp_path / "operator-source.rb", tmp_path / "WPScan-LICENSE", "own-systems"
        ),
        WPScanHTMLArtifact(page, hashlib.sha256(body).hexdigest(), "https://metadata.invalid/"),
        parsed_runtime(tmp_path),
    )


def prepared(tmp_path, monkeypatch):
    config = configured(tmp_path)
    # MOCK only the separately tested pinned upstream payload validation. Every
    # authorization, asset, job, lease and persistence check below is real SQLite.
    monkeypatch.setattr(WPScanObserveConfig, "validate_structure", lambda _: None)
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(
        EngagementPolicy(
            "wordpress-observe",
            "operator",
            (),
            target_domains=("source",),
            allowed_source_artifacts=(config.artifact.html_sha256,),
            profile="isolated-lab",
        )
    )
    spec = wordpress_observe_job(config, policy, store)
    store.submit(policy, [spec])
    job = store.claim(policy, "observation-worker", lease_seconds=15)
    assert job is not None
    surface = store.surface(policy.engagement_id, spec.surface_id)
    return config, store, policy, spec, job, surface


def test_actual_sqlite_job_factory_reopen_dedup_never_invents_http_authority(tmp_path, monkeypatch):
    config, store, policy, spec, job, surface = prepared(tmp_path, monkeypatch)
    assert surface.url == "" and surface.resource_kind == "source_artifact"
    assert policy.allowed_origins == () and store.request_usage(policy) == 0
    assert "private-page" not in job["spec"] and "metadata.invalid" not in job["spec"]
    adapter = WPScanObserveAdapter(config, policy, store)
    adapter._job_fence(job, surface, spec)
    assert adapter.runner is None
    assert store.finish(job, AdapterResult("succeeded", "partial"))
    store.close()
    reopened = AssessmentStore(tmp_path / "state.db")
    second = wordpress_observe_job(config, policy, reopened)
    assert second.key == spec.key
    assert len(reopened.submit(policy, [second])) == 1
    assert reopened.claim(policy, "after-restart") is None
    assert (
        reopened.db.execute(
            "SELECT count(*) FROM rj_evidence WHERE kind='approved_wordpress_observation_input'"
        ).fetchone()[0]
        == 1
    )
    reopened.close()


@pytest.mark.parametrize(
    "change", ["cancel", "expired", "attempt", "owner", "spec", "retired", "stop"]
)
def test_current_policy_job_lease_and_exact_spec_are_required(tmp_path, monkeypatch, change):
    config, store, policy, spec, job, surface = prepared(tmp_path, monkeypatch)
    adapter = WPScanObserveAdapter(config, policy, store)
    adapter._job_fence(job, surface, spec)
    if change == "cancel":
        store.cancel(policy.engagement_id, job["id"])
    elif change == "expired":
        with store.transaction() as db:
            db.execute("UPDATE rj_job SET lease_until=0 WHERE id=?", (job["id"],))
    elif change == "attempt":
        job = {**job, "attempt": job["attempt"] + 1}
    elif change == "owner":
        job = {**job, "owner": "different-worker"}
    elif change == "spec":
        spec = replace(spec, timeout_seconds=1)
    elif change == "retired":
        asset = store.inventory.asset(policy, surface.asset_ref)
        store.inventory.set_asset_state(
            policy, surface.asset_ref, state="retired", expected_revision=asset["revision"]
        )
    else:
        store.cancel(policy.engagement_id)
    with pytest.raises(PolicyDenied):
        adapter._job_fence(job, surface, spec)
    assert adapter.runner is None
    store.close()


def test_discovered_artifact_and_web_permission_do_not_grant_execution(tmp_path):
    config = configured(tmp_path)
    store = AssessmentStore(tmp_path / "state.db")
    policy = store.register(
        EngagementPolicy(
            "unapproved",
            "operator",
            ("https://metadata.invalid",),
            target_domains=("web", "source"),
        )
    )
    store.inventory.record_asset(
        policy, kind="source_artifact", locator=config.artifact.html_sha256, source="inferred"
    )
    with pytest.raises(PolicyDenied, match="not_approved"):
        wordpress_observe_job(config, policy, store)
    assert not store.jobs(policy.engagement_id)
    store.close()


@pytest.mark.parametrize(
    "change", ["license", "architecture", "gem", "path", "duplicate", "feature", "list", "library"]
)
def test_runtime_schema_rejects_unreviewed_closure_or_provenance(tmp_path, change):
    document = manifest_document()
    if change == "license":
        document["files"][-1]["sha256"] = "0" * 64
    elif change == "architecture":
        document["architecture"] = "unreviewed"
    elif change == "gem":
        document["gem_archive_sha256"] = {"ferrum": "0" * 64}
    elif change == "path":
        document["files"][1]["path"] = "packages/nokogiri/lib/ferrum/driver.rb"
    elif change == "duplicate":
        document["files"].append(document["files"][0])
    elif change == "feature":
        document["expected_features"] = ["not/manifested.rb"]
    elif change == "list":
        document["load_paths"] = [[], {}]
    else:
        document["linked_libraries"][0]["path"] = []
    with pytest.raises((ValueError, TypeError)):
        parsed_runtime(tmp_path, document)


@pytest.mark.parametrize(
    "raw", [b'{"a":1,"a":2}', b'{"x":1.5}', b'{"x":NaN}', b"[]", b"[" * 30 + b"0" + b"]" * 30]
)
def test_bounded_runtime_json_rejects_ambiguous_keys_types_and_nesting(raw):
    with pytest.raises((ValueError, TypeError)):
        runtime_document(raw)


async def test_missing_original_component_is_blocked_and_never_reported_as_negative(
    tmp_path, monkeypatch
):
    config, store, policy, spec, job, surface = prepared(tmp_path, monkeypatch)
    monkeypatch.undo()
    result = await WPScanObserveAdapter(config, policy, store).run(job, surface, spec)
    assert result.execution_status == "failed" and result.coverage_status == "blocked"
    assert result.findings == () and "no_finding_observed" not in result.summary
    assert store.request_usage(policy) == 0
    store.close()


async def test_copy_guard_denies_before_reading_even_one_runtime_file(tmp_path):
    config = configured(tmp_path)
    calls = []

    def denied():
        calls.append(True)
        raise PolicyDenied("cancelled-before-snapshot")

    runner = WPScanObservationRunner(
        config.runtime, config.component, config.artifact, tmp_path, denied
    )
    with pytest.raises(RuntimeError, match="wpscan_operator_io_requires_owned_async_prepare"):
        runner._snapshot_engine()
    with pytest.raises(PolicyDenied, match="cancelled-before-snapshot"):
        await runner.prepare_offline()
    assert calls == [True] and runner.engine is None


def test_mock_native_feature_protocol_must_match_exact_manifest(tmp_path):
    config = configured(tmp_path)
    runner = WPScanObservationRunner(
        config.runtime, config.component, config.artifact, tmp_path, lambda: None
    )
    runner.expected_runtime_files = {"/private/snapshot/nokogiri.rb"}
    document = {
        "runtime": EXPECTED_RUNTIME,
        "_runtime_files": ["/private/snapshot/nokogiri.rb", "/ambient/injected.rb"],
    }
    with pytest.raises(ValueError, match="load_closure_mismatch"):
        runner.validate_runtime_files(document)
