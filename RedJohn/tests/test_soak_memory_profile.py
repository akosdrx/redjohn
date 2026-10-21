"""Memory-observation parser/bounds contracts; no scanner or long-soak claim."""

from __future__ import annotations

import importlib
from pathlib import Path

import pytest


def helpers(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "benchmarks"))
    return importlib.import_module("memory_profile")


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
