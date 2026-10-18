"""Classify existing tests without changing their assertions or dependencies.

Only the reviewed native suites below receive real-integration status. All
remaining cases are reported as unit/contract/mixed, never as scanner E2E.
"""

import json
import os
from pathlib import Path

import pytest


REAL_FILES = {
    "test_assessment_browser_https.py",
    "test_assessment_browser_proxy_https.py",
    "test_assessment_egress.py",
    "test_assessment_https_e2e.py",
    "test_assessment_https_pipeline_failures.py",
    "test_authenticated_schema_oast_live.py",
    "test_authenticated_schema_oast_recovery_live.py",
    "test_automatic_session_recovery_pipeline.py",
    "test_browser_token_pipeline.py",
    "test_continuous_refresh_pipeline.py",
    "test_ffuf_cli_live.py",
    "test_ffuf_live.py",
    "test_host_assessment_live.py",
    "test_host_lifecycle_live.py",
    "test_host_resources_live.py",
    "test_host_scheduler_live.py",
    "test_mime_replay_live.py",
    "test_nuclei_auth_live.py",
    "test_nuclei_live.py",
    "test_nuclei_post_live.py",
    "test_nuclei_replay_redaction_live.py",
    "test_os_memory_live.py",
    "test_post_refresh_pipeline.py",
    "test_projectdiscovery_live.py",
    "test_remote_authenticated_pipeline.py",
    "test_resource_crash_recovery_live.py",
    "test_schema_oast_live.py",
    "test_specialists_live.py",
    "test_viewer_assessment.py",
}

REAL_CASES = {
    "test_real_chromium_spa_traffic_identity_repetition_and_cleanup",
    "test_real_chromium_readiness_redirect_limits_and_cancel_cleanup",
    "test_real_chromium_request_admission_and_response_callbacks",
    "test_real_chromium_crash_reports_lost_coverage_and_releases_context",
    "test_real_browser_persistent_pipeline_restart_report_and_explicit_retest",
    "test_real_browser_expired_actor_is_blocked_without_anonymous_fallback",
    "test_real_chromium_sequential_runtimes_release_browser_before_unlock",
    "test_real_missing_chromium_is_blocked_and_cleaned_in_isolated_process",
    "test_actual_chromium_auto_posts_are_exact_private_captures_and_default_stays_readonly",
    "test_actual_chromium_nuclei_restart_after_wall_clock_step",
    "test_actual_schemathesis_stops_admission_after_complete_401",
}
LOCAL_NUCLEI_FILES = {
    "test_nuclei_live.py", "test_nuclei_post_live.py", "test_nuclei_auth_live.py",
    "test_nuclei_replay_redaction_live.py",
}
KERNEL_ONLY_CASES = {
    "test_actual_kernel_memory_max_kills_oversized_tree",
    "test_actual_orphan_is_killed_before_crashed_owner_capacity_is_reclaimed",
}


def pytest_addoption(parser):
    parser.addoption("--ci-suite", choices=("all", "regression", "integration"), default="all")


def pytest_collection_modifyitems(config, items):
    selected, deselected = [], []
    suite = config.getoption("--ci-suite")
    capability_path = os.environ.get("REDJOHN_CI_CAPABILITIES")
    capabilities = json.loads(Path(capability_path).read_text()) if capability_path else None
    for item in items:
        filename = Path(str(item.path)).name
        name = item.originalname or item.name
        real = filename in REAL_FILES or name in REAL_CASES
        doubles = "unittest.mock" in Path(str(item.path)).read_text()
        item.user_properties.append(
            ("evidence_kind", "real_integration" if real else
             "mock_contract" if doubles else "unit_contract_or_mixed")
        )
        if real and capabilities is not None:
            required = (set() if filename in LOCAL_NUCLEI_FILES or filename == "test_host_lifecycle_live.py"
                        else {"cgroup_available"} if name in KERNEL_ONLY_CASES
                        else {"browser_available", "namespace_available"})
            missing = sorted(key for key in required if not capabilities.get(key))
            item.user_properties.append(("required_runner_capabilities", ",".join(sorted(required))))
            if missing:
                item.add_marker(pytest.mark.skip(reason="blocked_runner_capability:" + ",".join(missing)))
        if suite == "all" or (suite == "integration") == real:
            selected.append(item)
        else:
            deselected.append(item)
    items[:] = selected
    config.hook.pytest_deselected(items=deselected)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    # CI requires dependencies/capabilities. Preserve the original skip in
    # JUnit and the separate final gate rejects it; do not rewrite a skip as pass.
    if report.skipped:
        item.user_properties.append(("capability_or_dependency_skip", "true"))
