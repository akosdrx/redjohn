"""Memory-observation parser/bounds contracts; no scanner or long-soak claim."""

from __future__ import annotations

import importlib
import tracemalloc
from pathlib import Path
from types import SimpleNamespace

import pytest


def helpers(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "benchmarks"))
    return importlib.import_module("memory_profile")


def test_controller_mapping_counters_do_not_publish_paths_or_addresses(tmp_path, monkeypatch):
    helpers(monkeypatch)
    module = importlib.import_module("controller_diagnostics")
    path = tmp_path / "smaps"
    path.write_text(
        "1000-2000 rw-p 00000000 00:00 0 [heap]\n"
        "Size: 8 kB\nRss: 4 kB\nPss: 4 kB\nPrivate_Dirty: 3 kB\nPrivate_Clean: 0 kB\n"
        "2000-3000 r--p 00000000 00:00 0 /private/sensitive/library.so\n"
        "Size: 4 kB\nRss: 2 kB\nPss: 1 kB\nPrivate_Clean: 1 kB\nPrivate_Dirty: 0 kB\n"
    )
    value = module.mapping_counters(path)
    assert value["status"] == "observed"
    assert value["groups"]["brk_heap"]["Private_Dirty_bytes"] == 3072
    assert value["groups"]["file_backed"]["Rss_bytes"] == 2048
    assert "sensitive" not in str(value) and "1000-2000" not in str(value)


def test_controller_mapping_missing_or_invalid_data_is_blocked(tmp_path, monkeypatch):
    helpers(monkeypatch)
    module = importlib.import_module("controller_diagnostics")
    assert module.mapping_counters(tmp_path / "absent")["status"] == "blocked"
    path = tmp_path / "smaps"
    path.write_text("1000-2000 rw-p 00000000 00:00 0\nRss: 4 bytes\n")
    assert module.mapping_counters(path)["status"] == "blocked"


def test_empty_controller_mapping_observation_is_not_success(tmp_path, monkeypatch):
    helpers(monkeypatch)
    module = importlib.import_module("controller_diagnostics")
    path = tmp_path / "empty_smaps"
    path.write_text("")
    assert module.mapping_counters(path)["status"] == "blocked"


def test_controller_live_object_probe_tolerates_nonstring_module_descriptors(monkeypatch):
    helpers(monkeypatch)
    module = importlib.import_module("controller_diagnostics")
    class Odd:
        __module__ = property(lambda _self: "secret")
    monkeypatch.setattr(module.gc, "get_objects", lambda: [Odd()])
    value = module.ControllerDiagnostics().capture()
    assert value["gc_tracked_objects"] == 1
    assert value["live_component_types"] == {}


def test_supplemental_controller_data_does_not_change_bracketed_observations(monkeypatch):
    profile = helpers(monkeypatch)
    recorder = profile.MemoryAttribution(0)
    recorder.controller_diagnostics = SimpleNamespace(capture=lambda: {"numeric_control": 1})
    supplied = {"status": "controlled", "sample_monotonic": 1}
    result = recorder.checkpoint("after_allocator_trim", observation=supplied)
    assert result == {**supplied, "phase": "setup", "cycle": None,
                      "checkpoint": "after_allocator_trim"}
    assert recorder.report["checkpoints"] == [result]
    assert recorder.report["controller_diagnostics"][0]["memory_observation"] is result
    assert recorder.report["controller_diagnostics"][0]["controller_details"] == {
        "numeric_control": 1,
    }


def test_compact_allocation_sites_match_public_stdlib_statistics(monkeypatch):
    helpers(monkeypatch)
    module = importlib.import_module("allocation_profile")
    assert not tracemalloc.is_tracing()
    tracemalloc.start(5)
    try:
        retained = [bytearray(1000 + index) for index in range(30)]
        snapshot = tracemalloc.take_snapshot()
        expected = {
            (item.traceback[0].filename, item.traceback[0].lineno): [item.size, item.count]
            for item in snapshot.statistics("lineno")
        }
        assert module.allocation_sites(snapshot) == expected
        assert sum(row[0] for row in expected.values()) >= sum(map(len, retained))
    finally:
        tracemalloc.stop()


def test_compact_allocation_changes_preserve_positive_and_negative_counts(monkeypatch):
    helpers(monkeypatch)
    module = importlib.import_module("allocation_profile")
    tracemalloc.start(5)
    try:
        retained = [bytearray(2000) for _ in range(30)]
        before = tracemalloc.take_snapshot()
        retained.clear()
        after = tracemalloc.take_snapshot()
        expected = {
            str(item.traceback): (item.size_diff, item.count_diff)
            for item in after.compare_to(before, "lineno")
        }
        actual = module.changed_sites(
            module.allocation_sites(before), module.allocation_sites(after), limit=16384,
        )
        assert {row["location"]: (row["bytes_diff"], row["count_diff"])
                for row in actual} == expected
        assert any(row[0] < 0 for row in expected.values())
    finally:
        tracemalloc.stop()


def write_process(root, pid, parent, name, *, identity=123, rss_pages=10, smaps=True):
    directory = root / str(pid)
    directory.mkdir()
    fields = ["0"] * 22
    fields[0], fields[1], fields[19], fields[21] = "S", str(parent), str(identity), str(rss_pages)
    (directory / "stat").write_text(f"{pid} ({name}) {' '.join(fields)}\n")
    if smaps:
        (directory / "smaps_rollup").write_text(
            "0000-ffff ---p 00000000 00:00 0 [rollup]\n"
            "Rss: 40 kB\nPss: 25 kB\nPrivate_Clean: 2 kB\n"
            "Private_Dirty: 3 kB\nPrivate_Hugetlb: 1 kB\n"
        )


def test_linux_tree_profiles_roles_pss_and_private_without_arguments(tmp_path, monkeypatch):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "linux")
    write_process(tmp_path, 100, 1, "python")
    write_process(tmp_path, 101, 100, "node")
    write_process(tmp_path, 102, 101, "chrome)")
    write_process(tmp_path, 103, 100, "nuclei")
    write_process(tmp_path, 999, 1, "unrelated")
    value = profile.process_memory_sample(proc_root=tmp_path, controller_pid=100)
    assert value["status"] == "complete"
    assert value["process_count"] == 4
    assert set(value["roles"]) == {"controller", "node", "chromium", "nuclei"}
    assert value["roles"]["nuclei"]["pss_bytes"] == 25 * 1024
    assert value["roles"]["nuclei"]["private_bytes"] == 6 * 1024
    assert all("name" not in row and "argv" not in row for row in value["processes"])
    assert value["summed_rss_bytes"] == 4 * 40 * 1024


def test_missing_smaps_is_explicit_partial_observation_not_zero_memory(tmp_path, monkeypatch):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "linux")
    write_process(tmp_path, 100, 1, "python", smaps=False)
    value = profile.process_memory_sample(proc_root=tmp_path, controller_pid=100)
    assert value["status"] == "partial"
    assert value["roles"]["controller"]["pss_bytes"] is None
    assert value["roles"]["controller"]["rss_bytes"] > 0
    assert value["observation_status_counts"] == {"exited_during_observation": 1}


def test_reused_pid_does_not_publish_stale_smaps(tmp_path, monkeypatch):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "linux")
    write_process(tmp_path, 100, 1, "python")
    original = profile._stat
    calls = 0

    def changing_identity(path):
        nonlocal calls
        calls += 1
        name, parent, identity, rss = original(path)
        return name, parent, identity + (calls > 1), rss

    monkeypatch.setattr(profile, "_stat", changing_identity)
    value = profile.process_memory_sample(proc_root=tmp_path, controller_pid=100)
    assert value["status"] == "partial"
    assert value["processes"][0]["pss_bytes"] is None


def test_observation_recording_is_bounded_and_peak_retains_phase_identity(monkeypatch):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile, "MAX_SAMPLES", 2)
    recorder = profile.MemoryAttribution(100)
    for index in range(10):
        recorder.record(
            {
                "sample_monotonic": 100 + 2 * index,
                "phase": "browser",
                "cycle": index,
                "summed_rss_bytes": index,
                "processes": [],
            }
        )
    assert len(recorder.report["samples"]) == 2
    assert recorder.report["sample_count"] == 10
    assert recorder.report["retention_limit_reached"]
    assert recorder.report["phase_peaks"]["browser"]["cycle"] == 9
    with pytest.raises(ValueError, match="unknown_memory_measurement_phase"):
        recorder.set_phase("target_derived_value")


def test_process_limit_is_reported_as_partial_not_silently_complete(tmp_path, monkeypatch):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "linux")
    monkeypatch.setattr(profile, "MAX_PROCESSES", 1)
    write_process(tmp_path, 100, 1, "python")
    write_process(tmp_path, 101, 100, "httpx")
    value = profile.process_memory_sample(proc_root=tmp_path, controller_pid=100)
    assert value["status"] == "partial"
    assert value["process_count"] == 2
    assert len(value["processes"]) == 1
    assert value["process_limit_exceeded"]


def test_short_lived_scanner_observation_survives_later_phase_rss_peak(monkeypatch):
    profile = helpers(monkeypatch)
    recorder = profile.MemoryAttribution(100)
    scanner = {
        "sample_monotonic": 100,
        "phase": "nuclei",
        "summed_rss_bytes": 100,
        "roles": {"nuclei": {"rss_bytes": 80}},
    }
    later = {
        "sample_monotonic": 101,
        "phase": "nuclei",
        "summed_rss_bytes": 200,
        "roles": {"controller": {"rss_bytes": 200}},
    }
    recorder.record(scanner)
    recorder.record(later)
    assert recorder.report["phase_peaks"]["nuclei"] is later
    assert recorder.report["role_peaks"]["nuclei"] is scanner
    assert recorder.report["phase_observations"]["nuclei"]["role_sample_counts"]["nuclei"] == 1


def test_unsupported_platform_reports_unavailable_instead_of_fabricating_pss(monkeypatch):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "darwin")
    value = profile.process_memory_sample()
    assert value["status"] == "unavailable"
    assert value["reason"] == "linux_smaps_rollup_required"
    assert value["processes"] == []


def test_executable_basename_classifies_renamed_browser_threads_without_exporting_paths(
    tmp_path, monkeypatch
):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "linux")
    write_process(tmp_path, 100, 1, "python")
    write_process(tmp_path, 101, 100, "MainThread")
    write_process(tmp_path, 102, 101, "MainThread")
    (tmp_path / "101/exe").symlink_to("/private/controlled/browser/headless_shell")
    (tmp_path / "102/exe").symlink_to("/private/controlled/driver/node")
    value = profile.process_memory_sample(proc_root=tmp_path, controller_pid=100)
    assert set(value["roles"]) == {"controller", "chromium", "node"}
    for row in value["processes"][1:]:
        assert row["role_source"] == "executable_basename"
        assert row["role_observation_status"] == "observed"
        assert not {"argv", "environment", "executable", "basename", "name"} & row.keys()


def test_executable_readlink_denial_is_explicit_comm_fallback(tmp_path, monkeypatch):
    profile = helpers(monkeypatch)
    write_process(tmp_path, 100, 1, "node")

    def denied(_path):
        raise PermissionError("controlled_proc_readlink_denial")

    monkeypatch.setattr(Path, "readlink", denied)
    role, source, status = profile._observed_role(tmp_path, 100, "node", 123, 1)
    assert (role, source, status) == (
        "node",
        "comm_fallback",
        "executable_basename_permission_denied",
    )


def test_reused_pid_cannot_publish_executable_role(tmp_path, monkeypatch):
    profile = helpers(monkeypatch)
    write_process(tmp_path, 100, 1, "MainThread", identity=124)
    (tmp_path / "100/exe").symlink_to("/controlled/headless_shell")
    role, source, status = profile._observed_role(tmp_path, 100, "MainThread", 123, 1)
    assert (role, source, status) == ("other_descendant", "unverified", "process_identity_changed")


@pytest.mark.parametrize("returned", [0, 1])
def test_glibc_trim_brackets_only_call_after_library_preparation(monkeypatch, returned):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "linux")
    events = []

    class Function:
        def __init__(self, action):
            self.action = action

        def __call__(self, *arguments):
            return self.action(*arguments)

    def trim(pad):
        events.append("trim")
        assert pad == 0
        return returned

    def version():
        events.append("version")
        return b"2.39"

    def load(name):
        assert name is None
        events.append("library")
        return SimpleNamespace(gnu_get_libc_version=Function(version), malloc_trim=Function(trim))

    def capture():
        events.append("observation")
        return {"sample_order": len(events)}

    result = profile.allocator_trim_diagnostic(capture, library_loader=load)
    assert events == ["library", "version", "observation", "trim", "observation"]
    assert result["status"] == "completed" and result["returncode"] == returned
    assert result["call_count"] == 1 and result["library_prepared_before_observation"] is True
    assert result["before_observation"]["sample_order"] == 3
    assert result["after_observation"]["sample_order"] == 5
    assert result["runtime_policy_changed"] is False


def test_trim_unavailable_is_blocked_without_a_call_or_fabricated_observations(monkeypatch):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "linux")
    result = profile.allocator_trim_diagnostic(
        lambda: pytest.fail("unavailable trim must not fabricate pre/post observations"),
        library_loader=lambda _: SimpleNamespace(),
    )
    assert result["status"] == "blocked" and result["call_count"] == 0
    assert result["reason"] == "glibc_malloc_trim_symbol_unavailable"
    assert "before_observation" not in result and "after_observation" not in result


def test_non_linux_trim_diagnostic_never_loads_native_allocator(monkeypatch):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "darwin")
    result = profile.allocator_trim_diagnostic(
        lambda: pytest.fail("unsupported capture"),
        library_loader=lambda _: pytest.fail("unsupported library load"),
    )
    assert result["status"] == "blocked" and result["call_count"] == 0


@pytest.mark.parametrize("failure", ["unexpected_returncode", "os_error"])
def test_failed_trim_preserves_before_after_evidence_and_remains_failed(monkeypatch, failure):
    profile = helpers(monkeypatch)
    monkeypatch.setattr(profile.sys, "platform", "linux")

    def version():
        return b"2.39"

    def trim(_pad):
        if failure == "os_error":
            raise OSError("controlled_trim_failure")
        return 2

    observations = []

    def capture():
        value = {"observation": len(observations)}
        observations.append(value)
        return value

    result = profile.allocator_trim_diagnostic(
        capture,
        library_loader=lambda _: SimpleNamespace(gnu_get_libc_version=version, malloc_trim=trim),
    )
    assert result["status"] == "failed" and result["call_count"] == 1
    assert result["before_observation"] is observations[0]
    assert result["after_observation"] is observations[1]
    assert "returncode" not in result
