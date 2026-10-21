"""Classify existing tests without changing their assertions or dependencies.

Only explicit test names in the reviewed manifest receive real-integration
status. A real-looking filename grants nothing; remaining cases are reported
as unit/contract/mixed, never as scanner E2E.
"""

import json
import os
import platform
from pathlib import Path

import pytest

_MANIFEST_PATH = Path(__file__).with_name("pytest-real-integration.json")


def _load_real_integration_manifest() -> dict[str, frozenset[str]]:
    """Explicit test-level allowlist; a filename alone grants nothing."""
    try:
        data = json.loads(_MANIFEST_PATH.read_text())
        return {
            str(filename): frozenset(str(name) for name in names)
            for filename, names in data.items()
            if isinstance(names, list)
        }
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


REAL_TESTS = _load_real_integration_manifest()

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
    "test_actual_nuclei_public_multipart_template_survives_refreshed_boundary",
    "test_actual_schemathesis_stops_admission_after_complete_401",
    "test_real_stdio_unknown_mutation_is_never_replayed",
    "test_real_stdio_cancellation_terminates_worker_and_releases_lease",
    "test_real_sdk_pty_keeps_lease_until_polled_completion_and_closes",
    "test_real_stdio_idle_session_keeps_memory_reservation_and_server_state",
}
LOCAL_NUCLEI_CASES = {
    "test_actual_nuclei_public_multipart_template_survives_refreshed_boundary",
}
LOCAL_NUCLEI_FILES = {
    "test_nuclei_live.py", "test_nuclei_post_live.py", "test_nuclei_auth_live.py",
    "test_nuclei_replay_redaction_live.py",
    "test_nuclei_cli_live.py",
}
LOCAL_PROCESS_FILES = {
    "test_host_lifecycle_live.py", "test_legacy_cache_live.py",
    "test_tui_terminal_live.py", "test_soak_limits_live.py",
    "test_mcp_authorization_live.py", "test_inventory_workflows_live.py",
    "test_workflow_execution_failures_live.py",
    "test_mcp_stdio_bounded_live.py",
    "test_graphql_workflow_live.py",
    "test_preparation_scheduler.py",
    "test_cleanup_quarantine_live.py",
}
LOCAL_BROWSER_FILES = {"test_viewer_steering_live.py", "test_browser_auth_flow_live.py"}
NAMESPACE_ONLY_FILES = {"test_source_tools_live.py", "test_legacy_shell_boundary_live.py",
                        "test_network_tools_live.py", "test_mcp_target_live.py",
                        "test_service_tools_live.py", "test_preparation_native.py"}
PLATFORM_FILES = {"test_legacy_shell_darwin_live.py": "Darwin", "test_owned_memory_live.py": "Linux",
                  "test_lab_validation_live.py": "Linux"}
KERNEL_ONLY_FILES = {"test_owned_memory_live.py"}
NAMESPACE_CGROUP_FILES = {"test_lab_validation_live.py", "test_trivy_sbom_live.py", "test_wpscan_observe_live.py"}
LOCAL_PROCESS_CASES = {
    "test_failed_fenced_capture_never_activates_staged_vault",
    "test_real_stdio_unknown_mutation_is_never_replayed",
    "test_real_stdio_cancellation_terminates_worker_and_releases_lease",
    "test_real_sdk_pty_keeps_lease_until_polled_completion_and_closes",
    "test_real_stdio_idle_session_keeps_memory_reservation_and_server_state",
}
MOCK_CONTRACT_FILES = {"test_fixture_dns_contract.py", "test_soak_fault_contracts.py"}
KERNEL_ONLY_CASES = {
    "test_actual_kernel_memory_max_kills_oversized_tree",
    "test_actual_orphan_is_killed_before_crashed_owner_capacity_is_reclaimed",
}


def pytest_addoption(parser):
    parser.addoption("--ci-suite", choices=("all", "regression", "integration"), default="all")


def pytest_collection_modifyitems(config, items):
    selected, deselected = [], []
    non_applicable = []
    suite = config.getoption("--ci-suite")
    capability_path = os.environ.get("REDJOHN_CI_CAPABILITIES")
    capabilities = json.loads(Path(capability_path).read_text()) if capability_path else None
    for item in items:
        filename = Path(str(item.path)).name
        name = item.originalname or item.name
        real = name in REAL_CASES or name in REAL_TESTS.get(filename, frozenset())
        if filename in PLATFORM_FILES and platform.system() != PLATFORM_FILES[filename]:
            if suite == "all" or (suite == "integration") == real:
                non_applicable.append({"nodeid": item.nodeid, "required_platform": PLATFORM_FILES[filename],
                                   "actual_platform": platform.system(),
                                   "reason": "platform_not_applicable_not_executed_not_passed"})
            deselected.append(item)
            continue
        doubles = filename in MOCK_CONTRACT_FILES or "unittest.mock" in Path(str(item.path)).read_text()
        item.user_properties.append(
            ("evidence_kind", "real_integration" if real else
             "mock_contract" if doubles else "unit_contract_or_mixed")
        )
        if real and capabilities is not None:
            required = ({"cgroup_available", "browser_available", "namespace_available"}
                        if filename == "test_owned_memory_live.py" and name == "test_actual_browser_sdk_mcp_and_native_worker_inherit_the_owner_hard_fence" else
                        {"namespace_available", "cgroup_available"} if filename in NAMESPACE_CGROUP_FILES else
                        {"cgroup_available"} if filename in KERNEL_ONLY_FILES else
                        {"namespace_available"} if filename in NAMESPACE_ONLY_FILES else
                        {"browser_available"} if filename in LOCAL_BROWSER_FILES else
                        set() if filename in LOCAL_NUCLEI_FILES or name in LOCAL_NUCLEI_CASES or filename in LOCAL_PROCESS_FILES or name in LOCAL_PROCESS_CASES
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
    if os.environ.get("GITHUB_ACTIONS") == "true":
        output = Path(os.environ["GITHUB_WORKSPACE"]) / "artifacts" / ("non-applicable-" + suite + ".json")
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps({"suite": suite, "cases": non_applicable}, indent=2) + "\n")


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    # CI requires dependencies/capabilities. Preserve the original skip in
    # JUnit and the separate final gate rejects it; do not rewrite a skip as pass.
    if report.skipped:
        item.user_properties.append(("capability_or_dependency_skip", "true"))
