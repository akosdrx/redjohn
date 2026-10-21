"""Fast tests for the evidence machinery; these are CI contract tests."""

import importlib.util
import json
import os
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch


def register_synthetic_real_tests(plugin, *pairs):
    """Test-only manifest entries; do not add these names to production evidence."""
    merged = {key: set(value) for key, value in plugin.REAL_TESTS.items()}
    for filename, name in pairs:
        merged.setdefault(filename, set()).add(name)
    plugin.REAL_TESTS = {key: frozenset(value) for key, value in merged.items()}


SPEC = importlib.util.spec_from_file_location("ci", Path(__file__).parents[1] / "scripts/ci.py")
ci = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ci)


def synthetic_owner_receipt():
    """Schema fixture only: never evidence of Linux kernel enforcement."""
    memory = {"enforced": True, "memory_max_bytes": 2048 * 1024**2,
              "swap_max_bytes": 0, "pids_max": 512, "memory_oom_group": 1,
              "oom_events": 0, "oom_kills": 0, "memory_peak_bytes": 100,
              "method": "linux_cgroup_v2_before_controller_exec",
              "scope": "fresh_exec_local_owner_and_inherited_descendants",
              "owner_namespace": {key: True for key in (
                  "verified", "capabilities_zero", "no_new_privileges",
                  "direct_control_open_denied", "supervisor_proc_root_open_denied")}}
    memory["aggregate"] = {**{key: value for key, value in memory.items()
                              if key not in {"owner_namespace", "method", "scope"}},
                           "memory_max_bytes": 4096 * 1024**2,
                           "pids_max": 4096, "memory_oom_group": 0}
    return {"product": "RedJohn", "mode": "owned_local_process_tree_hard_memory",
            "outcome": "owner_exited", "owner_returncode": 0,
            "supervisor_outside_budget": True, "external_daemon_or_remote_workers_included": False,
            "process_cleanup_verified": True, "owner_cgroup_removed": True,
            "supervisor_peak_rss_bytes": 100, "os_memory": memory}


def bind_synthetic_owner(root, value=None):
    path = root / ci.SOAK_OWNER_RECEIPT
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(synthetic_owner_receipt() if value is None else value))
    command_path = root / "mixed-soak.json"
    command = json.loads(command_path.read_text()) if command_path.exists() else {}
    command["kernel_owner_receipt"] = ci.soak_owner_reference()[1]
    command_path.write_text(json.dumps(command))


def put_synthetic_kernel_cases(path):
    tree = ET.parse(path) if path.exists() else ET.ElementTree(ET.Element("testsuite"))
    for filename, name in sorted(ci.KERNEL_CONTROL_CASES):
        case = ET.SubElement(tree.getroot(), "testcase", file=filename, name=name)
        props = ET.SubElement(case, "properties")
        for key, value in {"evidence_kind": "real_integration",
                           "required_runner_capabilities": "cgroup_available"}.items():
            ET.SubElement(props, "property", name=key, value=value)
    tree.write(path)


def synthetic_memory_observation():
    memory = synthetic_owner_receipt()["os_memory"]
    return {"status": "complete", "process_limit_exceeded": False,
            "sample_monotonic": 4.0,
            "processes": [{"role": "controller", "status": "complete", "pid": 100, "start_ticks": 123,
                           "rss_bytes": 100, "pss_bytes": 90, "private_bytes": 80}],
            "kernel_memory": memory}


def synthetic_soak_receipt():
    names = ("before_synthetic_pressure", "after_synthetic_pressure",
             "runtime_ready_before_loop", "after_warmup", "before_runtime_close",
             "after_runtime_close", "after_workload_return_before_gc",
             "after_diagnostic_gc", "after_tracemalloc_stop", "after_allocator_trim")
    result = {"commit_sha": "abc", "ok": True, "requested_cycles": 2,
            "checks": {name: True for name in ci.SOAK_CHECKS},
            "minimum_elapsed_seconds": 0, "observation_errors": {},
            "resources_after_close": {"os_hard_limit": False},
            "workload": {"cycles": [{"cycle": 0}, {"cycle": 1}], "timing": {
                "loop_returned_normally": True, "completed_cycles": 2,
                "loop_started_monotonic": 1, "loop_ended_monotonic": 21,
                "loop_elapsed_seconds": 20, "loop_nonpacing_seconds": 10,
                "pacing_seconds": 10, "runtime_setup_elapsed_seconds": 1}},
            "memory_attribution": {"observation_errors": {}, "maximum_retained_samples": 2048,
                "maximum_processes_per_sample": 512, "retention_limit_reached": False,
                "samples": [synthetic_memory_observation()], "sample_count": 1,
                "checkpoints": [{**synthetic_memory_observation(), "checkpoint": name}
                                for name in names],
                "phase_peaks": {"browser": synthetic_memory_observation()},
                "role_peaks": {"controller": synthetic_memory_observation()}},
            "allocation_observations": {"closed_cache_payload_bytes": 0,
                                        "retained_memory_observation_json_bytes": 100}}
    before = synthetic_memory_observation()
    before["sample_monotonic"] = 10
    after = next(item for item in result["memory_attribution"]["checkpoints"]
                 if item["checkpoint"] == "after_allocator_trim")
    after["sample_monotonic"] = 11
    result["allocation_diagnostic"] = {"status": "completed", "method": "glibc_malloc_trim_0",
        "call_count": 1, "returncode": 0, "glibc_version": "synthetic-contract",
        "elapsed_seconds": 0.01, "scope": "controller_allocator_only",
        "runtime_policy_changed": False, "library_prepared_before_observation": True,
        "before_checkpoint": "after_tracemalloc_stop", "after_checkpoint": "after_allocator_trim",
        "before_observation": before, "after_observation": after}
    return result


def synthetic_controller_soak_receipt():
    """Controller counter schema only, never evidence of allocator behavior."""
    result = synthetic_soak_receipt()
    result["controller_details_requested"] = True
    result["memory_attribution"]["controller_diagnostics"] = [
        {"checkpoint": name, "controller_details": {
            "mappings": {"status": "observed", "mapping_count": 1, "groups": {
                "synthetic": {"mappings": 1, "Size_bytes": 1, "Rss_bytes": 1,
                              "Pss_bytes": 1, "Private_Clean_bytes": 0, "Private_Dirty_bytes": 1}}},
            "glibc_allocator": {"status": "observed", **dict.fromkeys((
                "arena", "ordblks", "smblks", "hblks", "hblkhd", "usmblks", "fsmblks",
                "uordblks", "fordblks", "keepcost"), 0)},
            "python_allocated_blocks": 1, "module_count": 1, "new_modules": [],
            "new_modules_truncated": False, "linecache_files": 0,
            "linecache_source_bytes": 0, "gc_tracked_objects": 0, "live_component_types": {},
        }} for name in sorted(ci.CONTROLLER_MIXED_PHASES)
    ]
    result["python_allocator_diagnostic"] = {
        phase: {"status": "observed", **dict.fromkeys(ci.PYMALLOC_COUNTERS, 1)}
        for phase in ("before_asyncio_run", "after_asyncio_run")
    }
    return result


class EvidenceContract(unittest.TestCase):
    def setUp(self):
        # Keep synthetic rejection cases out of the real runner's step summary.
        summary = patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": "", "GITHUB_ACTIONS": "false",
            "REDJOHN_SOAK_CYCLES": "2", "REDJOHN_SOAK_MINIMUM_SECONDS": "0"})
        summary.start()
        self.addCleanup(summary.stop)

    def test_junit_preserves_failures_errors_skips_and_kinds(self):
        xml = """<testsuites><testsuite><testcase name="real"><properties>
        <property name="evidence_kind" value="real_integration"/></properties></testcase>
        <testcase name="bad"><failure/></testcase><testcase name="oops"><error/></testcase>
        <testcase name="blocked"><skipped message="missing cgroup"/></testcase>
        </testsuite></testsuites>"""
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "junit.xml"
            path.write_text(xml)
            result = ci.junit_summary(path)
        self.assertEqual(result["counts"], {"passed": 1, "failed": 1, "errors": 1, "skipped": 1})
        self.assertEqual(result["evidence_kinds"]["real_integration"]["passed"], 1)
        self.assertEqual(result["skips"][0]["reason"], "missing cgroup")

    def test_missing_evidence_cannot_succeed(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            self.assertEqual(ci.summarize(), 1)
            result = json.loads((Path(folder) / "summary.json").read_text())
            self.assertFalse(result["success"])
            self.assertIn("blocked_runner_capability", result["blockers"])

    def test_valid_commands_do_not_hide_skipped_integration(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            for name in ci.REQUIRED:
                (root / (name + ".json")).write_text(json.dumps({"commit_sha": "abc", "exit_code": 0,
                    "leaked_descendant_pids_before_cleanup": []}))
            (root / "capabilities.json").write_text('{"available":true}')
            (root / "regression.junit.xml").write_text('<testsuite><testcase/></testsuite>')
            (root / "integration.junit.xml").write_text('<testsuite><testcase/><testcase><skipped/></testcase></testsuite>')
            self.assertEqual(ci.summarize(), 1)
            self.assertIn("incomplete_suite:integration", json.loads((root / "summary.json").read_text())["blockers"])

    def test_commit_mismatch_cannot_succeed(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            for name in ci.REQUIRED:
                (root / (name + ".json")).write_text(json.dumps({"commit_sha": "other", "exit_code": 0,
                    "leaked_descendant_pids_before_cleanup": []}))
            self.assertEqual(ci.summarize(), 1)
            self.assertIn("failed_command:python-integration", json.loads((root / "summary.json").read_text())["blockers"])

    def test_complete_contract_writes_isolated_github_summary(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            for name in ci.REQUIRED:
                (root / (name + ".json")).write_text(json.dumps({"commit_sha": "abc", "exit_code": 0,
                    "leaked_descendant_pids_before_cleanup": []}))
            (root / "capabilities.json").write_text('{"available":true}')
            (root / "cgroup-cleanup.json").write_text('{"removed":true,"leaked_processes":false}')
            (root / "apparmor-cleanup.json").write_text('{"success":true}')
            (root / "go-tests.log").write_text('{"Package":"fixture","Test":"TestContract","Action":"pass"}\n')
            for name in ("regression", "integration", "frontend"):
                (root / (name + ".junit.xml")).write_text('<testsuite><testcase name="fixture"/></testsuite>')
            put_synthetic_kernel_cases(root / "integration.junit.xml")
            (root / "mixed-soak").mkdir()
            (root / "mixed-soak/mixed-soak.json").write_text(json.dumps(synthetic_soak_receipt()))
            bind_synthetic_owner(root)
            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(root / "summary.md")}):
                self.assertEqual(ci.summarize(), 0)
            self.assertIn("Complete.", (root / "summary.md").read_text())
            self.assertTrue((root / "go.junit.xml").exists())
            index = json.loads((root / "evidence-index.json").read_text())
            self.assertEqual(index["commit_sha"], "abc")
            self.assertIn("summary.json", index["files"])

    def test_cooperative_soak_success_cannot_replace_kernel_owner_receipt(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            (root / "mixed-soak").mkdir()
            (root / "mixed-soak/mixed-soak.json").write_text('{"commit_sha":"abc","ok":true}')
            self.assertEqual(ci.summarize(), 1)
            blockers = json.loads((root / "summary.json").read_text())["blockers"]
            self.assertTrue(any(x.startswith("invalid_mixed_soak_kernel_memory:") for x in blockers))

    def test_normal_soak_rejects_unenforced_mismatched_oom_and_incomplete_cleanup(self):
        for scope, key, invalid in (
            ("receipt", "outcome", "blocked"),
            ("receipt", "owner_returncode", False),
            ("receipt", "process_cleanup_verified", False),
            ("receipt", "owner_cgroup_removed", False),
            ("receipt", "supervisor_outside_budget", False),
            ("owner", "enforced", False),
            ("owner", "memory_max_bytes", 4096 * 1024**2),
            ("owner", "memory_oom_group", 0),
            ("owner", "oom_events", 1),
            ("owner", "oom_kills", 1),
            ("owner", "swap_max_bytes", False),
            ("owner", "pids_max", 4096),
            ("owner", "memory_peak_bytes", None),
            ("aggregate", "enforced", False),
            ("aggregate", "memory_max_bytes", 8192 * 1024**2),
            ("aggregate", "swap_max_bytes", 1),
            ("aggregate", "oom_kills", 1),
            ("namespace", "verified", False),
            ("namespace", "supervisor_proc_root_open_denied", False),
        ):
            with self.subTest(scope=scope, key=key, invalid=invalid):
                value = synthetic_owner_receipt()
                target = {"receipt": value, "owner": value["os_memory"],
                          "aggregate": value["os_memory"]["aggregate"],
                          "namespace": value["os_memory"]["owner_namespace"]}[scope]
                target[key] = invalid
                with self.assertRaisesRegex(ValueError, "mixed_soak_"):
                    ci.validate_soak_owner(value)
        self.assertTrue(ci.validate_soak_owner(synthetic_owner_receipt())["owner_cgroup_removed"])

    def test_owner_receipt_changed_after_command_cannot_be_reused(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            (root / "mixed-soak.json").write_text(json.dumps({"commit_sha": "abc", "exit_code": 0,
                "leaked_descendant_pids_before_cleanup": []}))
            bind_synthetic_owner(root)
            path = root / ci.SOAK_OWNER_RECEIPT
            value = json.loads(path.read_text())
            value["supervisor_peak_rss_bytes"] += 1
            path.write_text(json.dumps(value))
            self.assertEqual(ci.summarize(), 1)
            blockers = json.loads((root / "summary.json").read_text())["blockers"]
            self.assertIn("invalid_mixed_soak_kernel_memory:"
                          "mixed_soak_owner_receipt_not_bound_to_command_commit", blockers)

    def test_oversized_or_symlinked_owner_receipt_is_not_read_as_valid_evidence(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)):
            root = Path(folder)
            path = root / ci.SOAK_OWNER_RECEIPT
            path.parent.mkdir()
            path.write_bytes(b" " * 65537)
            with self.assertRaisesRegex(ValueError, "byte_limit"):
                ci.soak_owner_reference()
            path.unlink()
            path.symlink_to(root / "missing")
            with self.assertRaisesRegex(ValueError, "not_regular"):
                ci.soak_owner_reference()
            path.unlink()
            os.mkfifo(path)
            with self.assertRaisesRegex(ValueError, "not_regular"):
                ci.soak_owner_reference()

    def test_missing_mocked_or_duplicate_fault_control_cannot_pass_as_kernel_evidence(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "integration.junit.xml"
            for fault in ("missing", "mock", "skipped", "duplicate"):
                with self.subTest(fault=fault):
                    path.unlink(missing_ok=True)
                    put_synthetic_kernel_cases(path)
                    tree = ET.parse(path)
                    first = tree.getroot().find("testcase")
                    if fault == "missing":
                        tree.getroot().remove(first)
                    elif fault == "mock":
                        first.find("properties/property").set("value", "mock_contract")
                    elif fault == "skipped":
                        ET.SubElement(first, "skipped")
                    else:
                        tree.getroot().append(first)
                    tree.write(path)
                    with self.assertRaisesRegex(ValueError, "kernel_control_case"):
                        ci.validate_kernel_control_cases(path)

    def test_loop_window_and_memory_observation_cannot_be_omitted_or_fabricated_from_elapsed(self):
        for fault in ("missing-window", "short-window", "wrong-request", "aborted-loop",
                      "wrong-cycle-count", "observation-error", "no-samples", "missing-checkpoint",
                      "no-controller-pss", "no-observed-kernel-fence", "retention-overflow"):
            with self.subTest(fault=fault):
                value = synthetic_soak_receipt()
                timing, profile = value["workload"]["timing"], value["memory_attribution"]
                if fault == "missing-window":
                    del timing["loop_elapsed_seconds"]
                elif fault == "short-window":
                    value["minimum_elapsed_seconds"] = 1200
                elif fault == "wrong-request":
                    value["requested_cycles"] = 120
                elif fault == "aborted-loop":
                    timing["loop_returned_normally"] = False
                elif fault == "wrong-cycle-count":
                    timing["completed_cycles"] = 3
                elif fault == "observation-error":
                    profile["observation_errors"] = {"RuntimeError": 1}
                elif fault == "no-samples":
                    profile["samples"] = []
                elif fault == "missing-checkpoint":
                    profile["checkpoints"].pop()
                elif fault == "no-controller-pss":
                    profile["samples"][0]["processes"][0]["pss_bytes"] = None
                elif fault == "no-observed-kernel-fence":
                    profile["samples"][0]["kernel_memory"]["enforced"] = False
                else:
                    profile["retention_limit_reached"] = True
                with self.assertRaisesRegex(ValueError, "mixed_soak_"):
                    ci.validate_soak_observations(value)
        # Cooperative admission retains its meaning even with genuine OS
        # receipts alongside it; this field must not be relabelled as kernel proof.
        value = synthetic_soak_receipt()
        self.assertFalse(value["resources_after_close"]["os_hard_limit"])
        self.assertEqual(ci.validate_soak_observations(value)["actual_cycles"], 2)
        with patch.dict(os.environ, {"REDJOHN_SOAK_MINIMUM_SECONDS": "1200"}):
            value["minimum_elapsed_seconds"] = 1200
            with self.assertRaisesRegex(ValueError, "explicit_workload_window"):
                ci.validate_soak_observations(value)

    def test_allocator_call_availability_and_bracketed_identity_are_required(self):
        for fault in ("missing", "blocked", "failed", "no-call", "bad-return", "bool-return",
                      "unprepared-library", "changed-policy", "wrong-owner", "reordered",
                      "different-after-checkpoint", "missing-pss"):
            with self.subTest(fault=fault):
                value = synthetic_soak_receipt()
                diagnostic = value["allocation_diagnostic"]
                if fault == "missing":
                    del value["allocation_diagnostic"]
                elif fault in {"blocked", "failed"}:
                    diagnostic["status"] = fault
                elif fault == "no-call":
                    diagnostic["call_count"] = 0
                elif fault == "bad-return":
                    diagnostic["returncode"] = -1
                elif fault == "bool-return":
                    diagnostic["returncode"] = False
                elif fault == "unprepared-library":
                    diagnostic["library_prepared_before_observation"] = False
                elif fault == "changed-policy":
                    diagnostic["runtime_policy_changed"] = True
                elif fault == "wrong-owner":
                    diagnostic["before_observation"]["processes"][0]["start_ticks"] += 1
                elif fault == "reordered":
                    diagnostic["before_observation"]["sample_monotonic"] = 12
                elif fault == "different-after-checkpoint":
                    diagnostic["after_observation"] = synthetic_memory_observation()
                else:
                    diagnostic["before_observation"]["processes"][0]["pss_bytes"] = None
                with self.assertRaisesRegex(ValueError, "mixed_soak_"):
                    ci.validate_soak_observations(value)

    def test_allocator_noop_and_no_rss_reduction_remain_valid_observations(self):
        for returned in (0, 1):
            with self.subTest(returned=returned):
                value = synthetic_soak_receipt()
                value["allocation_diagnostic"]["returncode"] = returned
                summary = ci.validate_soak_observations(value)["allocation_diagnostic"]
                self.assertEqual(summary["returncode"], returned)
                self.assertEqual(summary["controller_after_minus_before"],
                                 {"rss_bytes": 0, "pss_bytes": 0, "private_bytes": 0})

    def test_controller_gate_preserves_unrequested_historical_receipts(self):
        value = synthetic_soak_receipt()
        self.assertIsNone(ci.validate_soak_observations(value)["controller_diagnostics"])
        with self.assertRaisesRegex(ValueError, "requested_controller_details_missing"):
            ci.validate_soak_observations(value, require_controller_details=True)
        value = synthetic_controller_soak_receipt()
        checked = ci.validate_soak_observations(value, require_controller_details=True)
        self.assertEqual(set(checked["controller_diagnostics"]["checkpoints"]),
                         ci.CONTROLLER_MIXED_PHASES)

    def test_requested_controller_gate_rejects_missing_truncated_or_retained_evidence(self):
        for fault in ("missing-details", "missing-phase", "duplicate-phase", "truncated-modules",
                      "missing-live-types", "truncated-live-types", "retained-component",
                      "missing-allocator", "blocked-allocator", "missing-counter", "boolean-counter"):
            with self.subTest(fault=fault):
                value = synthetic_controller_soak_receipt()
                details = value["memory_attribution"]["controller_diagnostics"]
                after_gc = next(item["controller_details"] for item in details
                                if item["checkpoint"] == "after_diagnostic_gc")
                if fault == "missing-details":
                    del value["memory_attribution"]["controller_diagnostics"]
                elif fault == "missing-phase":
                    details.pop()
                elif fault == "duplicate-phase":
                    details.append(details[0])
                elif fault == "truncated-modules":
                    after_gc["new_modules_truncated"] = True
                elif fault == "missing-live-types":
                    del after_gc["live_component_types"]
                elif fault == "truncated-live-types":
                    after_gc["live_component_types"] = {str(number): 1 for number in range(512)}
                elif fault == "retained-component":
                    after_gc["live_component_types"][ci.RELEASED_TYPES[0]] = 1
                elif fault == "missing-allocator":
                    del value["python_allocator_diagnostic"]
                elif fault == "blocked-allocator":
                    value["python_allocator_diagnostic"]["after_asyncio_run"]["status"] = "blocked"
                elif fault == "missing-counter":
                    del value["python_allocator_diagnostic"]["after_asyncio_run"]["arenas_current"]
                else:
                    value["python_allocator_diagnostic"]["after_asyncio_run"]["arenas_current"] = True
                with self.assertRaises(ValueError):
                    ci.validate_soak_observations(value, require_controller_details=True)

    def test_actual_command_details_flag_cannot_be_omitted_from_full_summary_evidence(self):
        for requested in (False, True):
            with self.subTest(command_requests_details=requested), tempfile.TemporaryDirectory() as folder, \
                    patch.object(ci, "OUT", Path(folder)), \
                    patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
                root = Path(folder)
                for name in ci.REQUIRED:
                    (root / (name + ".json")).write_text(json.dumps({"commit_sha": "abc", "exit_code": 0,
                        "leaked_descendant_pids_before_cleanup": [], "command": (
                            ["python", "mixed_soak.py", "--controller-details"]
                            if name == "mixed-soak" and requested else ["synthetic"])}))
                (root / "capabilities.json").write_text('{"available":true}')
                (root / "cgroup-cleanup.json").write_text('{"removed":true,"leaked_processes":false}')
                (root / "apparmor-cleanup.json").write_text('{"success":true}')
                (root / "go-tests.log").write_text('{"Package":"fixture","Test":"TestContract","Action":"pass"}\n')
                for name in ("regression", "integration", "frontend"):
                    (root / (name + ".junit.xml")).write_text('<testsuite><testcase name="fixture"/></testsuite>')
                put_synthetic_kernel_cases(root / "integration.junit.xml")
                (root / "mixed-soak").mkdir()
                (root / "mixed-soak/mixed-soak.json").write_text(json.dumps(synthetic_soak_receipt()))
                bind_synthetic_owner(root)
                self.assertEqual(ci.summarize(), int(requested))
                blockers = json.loads((root / "summary.json").read_text())["blockers"]
                if requested:
                    self.assertIn("incomplete_mixed_soak_observations:"
                                  "mixed_soak_requested_controller_details_missing", blockers)
                    (root / "mixed-soak/mixed-soak.json").write_text(
                        json.dumps(synthetic_controller_soak_receipt())
                    )
                    self.assertEqual(ci.summarize(), 0)

    def test_missing_browser_does_not_hide_supported_native_or_kernel_cases(self):
        spec = importlib.util.spec_from_file_location("evidence", Path(__file__).parents[1] / "scripts/pytest_evidence.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        register_synthetic_real_tests(
            plugin,
            ("test_nuclei_live.py", "test_live_pinned_nuclei_native_marker_then_fixed_control"),
            ("test_os_memory_live.py", "test_actual_kernel_memory_max_kills_oversized_tree"),
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            capability = root / "capabilities.json"
            capability.write_text('{"browser_available":false,"namespace_available":false,"cgroup_available":true}')
            items, markers = [], {}
            for filename, name in (("test_nuclei_live.py", "test_live_pinned_nuclei_native_marker_then_fixed_control"),
                                   ("test_os_memory_live.py", "test_actual_kernel_memory_max_kills_oversized_tree"),
                                   ("test_assessment_browser.py", "test_real_chromium_request_admission_and_response_callbacks")):
                path = root / filename
                path.write_text("")
                markers[name] = []
                items.append(SimpleNamespace(path=path, originalname=name, name=name,
                    user_properties=[], add_marker=markers[name].append))
            config = SimpleNamespace(getoption=lambda _: "integration",
                hook=SimpleNamespace(pytest_deselected=lambda **_: None))
            with patch.dict(os.environ, {"REDJOHN_CI_CAPABILITIES": str(capability)}):
                plugin.pytest_collection_modifyitems(config, items)
            self.assertEqual(len(items), 3)
            self.assertFalse(markers["test_live_pinned_nuclei_native_marker_then_fixed_control"])
            self.assertFalse(markers["test_actual_kernel_memory_max_kills_oversized_tree"])
            self.assertEqual(len(markers["test_real_chromium_request_admission_and_response_callbacks"]), 1)

    def test_zero_go_functions_are_recorded_without_inventing_passed_tests(self):
        with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
            root = Path(folder)
            (root / "go-tests.log").write_text('{"Package":"fixture","Action":"skip"}\n')
            self.assertEqual(ci.summarize(), 1)  # Other required evidence is deliberately absent.
            result = json.loads((root / "summary.json").read_text())
            self.assertEqual(result["go_tests"], {"passed": 0, "failed": 0, "skipped": 0})
            self.assertEqual(result["go_test_coverage"], "no_test_functions_defined")
            self.assertNotIn("missing_go_results", result["blockers"])
            self.assertIn("incomplete_go_tests", result["blockers"])

    def test_soak_cannot_succeed_for_another_commit_or_a_failed_check(self):
        for payload in ({"commit_sha": "other", "ok": True}, {"commit_sha": "abc", "ok": False}):
            with tempfile.TemporaryDirectory() as folder, patch.object(ci, "OUT", Path(folder)), \
                    patch.object(ci, "identity", return_value={"commit_sha": "abc", "machine": "contract"}):
                root = Path(folder)
                (root / "mixed-soak").mkdir()
                (root / "mixed-soak/mixed-soak.json").write_text(json.dumps(payload))
                self.assertEqual(ci.summarize(), 1)
                self.assertIn("incomplete_mixed_soak", json.loads((root / "summary.json").read_text())["blockers"])

    def test_node_junit_direct_testcase_children_are_counted(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "frontend.junit.xml"
            path.write_text('<testsuites><testcase name="parser"/><testcase name="fetch"><failure/></testcase></testsuites>')
            self.assertEqual(ci.junit_summary(path)["counts"], {"passed": 1, "failed": 1, "skipped": 0, "errors": 0})

    def test_reviewed_node_fetch_double_stays_distinct_from_real_http(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "frontend.junit.xml"
            name = "dropped POST transport is an explicit failure and the next action can retry"
            path.write_text(f'<testsuites><testcase name="{name}" file="/owned/tests/server-source.test.mjs"/></testsuites>')
            result = ci.junit_summary(path)
            self.assertEqual(result["evidence_kinds"]["mock_contract"]["passed"], 1)
            self.assertNotIn("real_integration", result["evidence_kinds"])

    def test_actual_node22_format_without_file_attributes_keeps_fetch_double_label(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "frontend.junit.xml"
            name = "steering preserves agent and message, HTTP rejection stays failure"
            path.write_text(f'<testsuites><testcase name="{name}" classname="test"/>'
                            '<testcase name="parser" classname="test"/></testsuites>')
            result = ci.junit_summary(path)
            self.assertEqual(result["counts"]["passed"], 2)
            self.assertEqual(result["evidence_kinds"]["mock_contract"]["passed"], 1)
            self.assertEqual(result["evidence_kinds"]["unit_contract_or_mixed"]["passed"], 1)

    def test_darwin_cases_are_explicitly_not_applicable_and_namespace_blocks_stay_visible(self):
        spec = importlib.util.spec_from_file_location("evidence", Path(__file__).parents[1] / "scripts/pytest_evidence.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        register_synthetic_real_tests(
            plugin,
            ("test_legacy_shell_darwin_live.py", "test_real"),
            ("test_source_tools_live.py", "test_real"),
        )
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            capability = root / "capabilities.json"
            capability.write_text('{"browser_available":false,"namespace_available":false}')
            items, markers, deselected = [], {}, []
            for filename in ("test_legacy_shell_darwin_live.py", "test_source_tools_live.py"):
                path = root / filename
                path.write_text("")
                markers[filename] = []
                items.append(SimpleNamespace(path=path, originalname="test_real", name="test_real",
                    nodeid=filename + "::test_real", user_properties=[], add_marker=markers[filename].append))
            config = SimpleNamespace(getoption=lambda _: "integration",
                hook=SimpleNamespace(pytest_deselected=lambda **kw: deselected.extend(kw["items"])))
            with patch.dict(os.environ, {"REDJOHN_CI_CAPABILITIES": str(capability),
                                        "GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(root)}), \
                    patch.object(plugin.platform, "system", return_value="Linux"):
                plugin.pytest_collection_modifyitems(config, items)
            self.assertEqual([item.nodeid for item in deselected], ["test_legacy_shell_darwin_live.py::test_real"])
            self.assertEqual(len(items), 1)
            self.assertEqual(len(markers["test_source_tools_live.py"]), 1)
            evidence = json.loads((root / "artifacts/non-applicable-integration.json").read_text())
            self.assertEqual(len(evidence["cases"]), 1)
            self.assertEqual(evidence["cases"][0]["required_platform"], "Darwin")
            self.assertIn("not_passed", evidence["cases"][0]["reason"])

    def test_network_and_target_mcp_require_namespace_without_a_browser_dependency(self):
        spec = importlib.util.spec_from_file_location("evidence", Path(__file__).parents[1] / "scripts/pytest_evidence.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        register_synthetic_real_tests(
            plugin,
            ("test_network_tools_live.py", "test_real"),
            ("test_mcp_target_live.py", "test_real"),
        )
        self.assertIn("network-scanner-install", ci.REQUIRED)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            capability = root / "capabilities.json"
            for namespace in (False, True):
                capability.write_text(json.dumps({"browser_available": False,
                                                  "namespace_available": namespace}))
                items, markers = [], {}
                for filename in ("test_network_tools_live.py", "test_mcp_target_live.py"):
                    path = root / filename
                    path.write_text("")
                    markers[filename] = []
                    items.append(SimpleNamespace(path=path, originalname="test_real", name="test_real",
                        user_properties=[], add_marker=markers[filename].append))
                config = SimpleNamespace(getoption=lambda _: "integration",
                    hook=SimpleNamespace(pytest_deselected=lambda **_: None))
                with patch.dict(os.environ, {"REDJOHN_CI_CAPABILITIES": str(capability)}):
                    plugin.pytest_collection_modifyitems(config, items)
                self.assertEqual(len(items), 2)
                for item in items:
                    self.assertIn(("evidence_kind", "real_integration"), item.user_properties)
                    self.assertIn(("required_runner_capabilities", "namespace_available"), item.user_properties)
                    self.assertEqual(len(markers[item.path.name]), int(not namespace))

    def test_actual_nuclei_case_in_mixed_file_is_never_a_regression_or_browser_skip(self):
        spec = importlib.util.spec_from_file_location("evidence", Path(__file__).parents[1] / "scripts/pytest_evidence.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "test_body_token_refresh.py"
            path.write_text("")
            capability = root / "capabilities.json"
            capability.write_text(json.dumps({"browser_available": False, "namespace_available": False}))
            name = "test_actual_nuclei_public_multipart_template_survives_refreshed_boundary"
            for suite in ("regression", "integration"):
                markers, deselected = [], []
                item = SimpleNamespace(path=path, originalname=name, name=name,
                    user_properties=[], add_marker=markers.append)
                items = [item]
                config = SimpleNamespace(getoption=lambda _: suite,
                    hook=SimpleNamespace(pytest_deselected=lambda **kwargs: deselected.extend(kwargs["items"])))
                with patch.dict(os.environ, {"REDJOHN_CI_CAPABILITIES": str(capability)}):
                    plugin.pytest_collection_modifyitems(config, items)
                self.assertEqual(len(items), int(suite == "integration"))
                self.assertEqual(len(deselected), int(suite == "regression"))
                self.assertEqual(markers, [])
                self.assertIn(("evidence_kind", "real_integration"), item.user_properties)
                self.assertIn(("required_runner_capabilities", ""), item.user_properties)

    def test_ci_apparmor_profile_has_no_global_write_or_privileged_capabilities(self):
        policy = (Path(__file__).parents[1] / "policies/redjohn-ci.apparmor").read_text()
        assert "/{,**} mrwlkix" not in policy
        for capability in ("net_admin", "sys_ptrace"):
            assert f"capability {capability}," not in policy
        assert "capability sys_admin," in policy  # setuid bwrap namespace setup
        assert "/home/*/work/** rwklix" in policy
        assert "/sys/fs/cgroup/redjohn-ci-*/** rwklix" in policy

    def test_dirty_or_untracked_source_blocks_snapshot_and_preflight(self):
        dirty = SimpleNamespace(returncode=0, stdout="?? untracked-probe.py\n", stderr="")
        clean = SimpleNamespace(returncode=0, stdout="", stderr="")
        with patch.object(ci.subprocess, "run", return_value=dirty):
            with self.assertRaisesRegex(RuntimeError, "dirty_worktree_blocks_evidence"):
                ci.require_clean_worktree()
            with patch.object(ci, "write") as write:
                with self.assertRaisesRegex(RuntimeError, "dirty_worktree_blocks_evidence"):
                    ci.snapshot()
                write.assert_not_called()
        with patch.object(ci.subprocess, "run", return_value=clean):
            self.assertEqual(ci.require_clean_worktree(), {"clean": True, "path_count": 0})

    def test_owned_lab_requires_both_namespace_and_kernel_without_a_browser(self):
        spec = importlib.util.spec_from_file_location("evidence", Path(__file__).parents[1] / "scripts/pytest_evidence.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        register_synthetic_real_tests(plugin, ("test_lab_validation_live.py", "test_actual"))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "test_lab_validation_live.py"
            path.write_text("")
            capability = root / "capabilities.json"
            for namespace, kernel in ((False, True), (True, False), (True, True)):
                capability.write_text(json.dumps({"namespace_available": namespace,
                    "cgroup_available": kernel, "browser_available": False}))
                markers = []
                item = SimpleNamespace(path=path, originalname="test_actual", name="test_actual",
                    user_properties=[], add_marker=markers.append)
                items = [item]
                config = SimpleNamespace(getoption=lambda _: "integration",
                    hook=SimpleNamespace(pytest_deselected=lambda **_: None))
                with patch.dict(os.environ, {"REDJOHN_CI_CAPABILITIES": str(capability)}), patch.object(plugin.platform, "system", return_value="Linux"):
                    plugin.pytest_collection_modifyitems(config, items)
                self.assertEqual(items, [item])
                self.assertIn(("required_runner_capabilities", "cgroup_available,namespace_available"), item.user_properties)
                self.assertEqual(len(markers), int(not (namespace and kernel)))

    def test_owned_memory_cases_require_kernel_capability_and_remain_nonapplicable_on_darwin(self):
        spec = importlib.util.spec_from_file_location("evidence", Path(__file__).parents[1] / "scripts/pytest_evidence.py")
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        register_synthetic_real_tests(plugin, ("test_owned_memory_live.py", "test_real"))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            path = root / "test_owned_memory_live.py"
            path.write_text("")
            capability = root / "capabilities.json"
            for system, kernel in (("Darwin", True), ("Linux", False), ("Linux", True)):
                capability.write_text(json.dumps({"cgroup_available": kernel,
                                                  "browser_available": False,
                                                  "namespace_available": False}))
                markers, deselected = [], []
                item = SimpleNamespace(path=path, originalname="test_real", name="test_real",
                    nodeid=path.name + "::test_real", user_properties=[], add_marker=markers.append)
                items = [item]
                config = SimpleNamespace(getoption=lambda _: "integration",
                    hook=SimpleNamespace(pytest_deselected=lambda **kw: deselected.extend(kw["items"])))
                with patch.dict(os.environ, {"REDJOHN_CI_CAPABILITIES": str(capability)}), \
                        patch.object(plugin.platform, "system", return_value=system):
                    plugin.pytest_collection_modifyitems(config, items)
                if system == "Darwin":
                    self.assertEqual(items, [])
                    self.assertEqual(deselected, [item])
                    self.assertEqual(markers, [])
                else:
                    self.assertEqual(items, [item])
                    self.assertIn(("required_runner_capabilities", "cgroup_available"), item.user_properties)
                    self.assertEqual(len(markers), int(not kernel))


    def test_real_integration_status_is_per_test_not_per_filename(self):
        spec = importlib.util.spec_from_file_location(
            "evidence", Path(__file__).parents[1] / "scripts/pytest_evidence.py"
        )
        plugin = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin)
        assert "test_actual_ffuf_report_web_view_chromium" in plugin.REAL_TESTS[
            "test_viewer_assessment.py"
        ]
        assert "test_invalid_assessment_report_never_looks_like_clean_completion" not in (
            plugin.REAL_TESTS["test_viewer_assessment.py"]
        )
        assert "test_never_seen_contract" not in plugin.REAL_TESTS.get(
            "test_viewer_assessment.py", frozenset()
        )


if __name__ == "__main__":
    unittest.main()
