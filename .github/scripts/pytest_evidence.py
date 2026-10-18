"""Classify existing tests without changing their assertions or dependencies.

Only the reviewed native suites below receive real-integration status. All
remaining cases are reported as unit/contract/mixed, never as scanner E2E.
"""

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


def pytest_addoption(parser):
    parser.addoption("--ci-suite", choices=("all", "regression", "integration"), default="all")


def pytest_collection_modifyitems(config, items):
    selected, deselected = [], []
    suite = config.getoption("--ci-suite")
    for item in items:
        real = Path(str(item.path)).name in REAL_FILES
        doubles = "unittest.mock" in Path(str(item.path)).read_text()
        item.user_properties.append(
            ("evidence_kind", "real_integration" if real else
             "mock_contract" if doubles else "unit_contract_or_mixed")
        )
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
