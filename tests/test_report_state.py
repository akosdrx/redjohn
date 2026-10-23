"""Regression tests for the scan finalization memory hook (K-audit K1/M1)."""

from __future__ import annotations

from redjohn.memory.openviking import hooks
from redjohn.report.state import ReportState


def test_update_scan_final_fields_uses_run_id_and_scan_config(monkeypatch, tmp_path):
    captured: dict[str, object] = {}

    def fake_summary(scan_id: str, targets: object, summary: str) -> None:
        captured["scan_id"] = scan_id
        captured["targets"] = targets
        captured["summary"] = summary

    monkeypatch.setattr(hooks, "remember_pentest_summary", fake_summary)
    monkeypatch.chdir(tmp_path)

    state = ReportState(run_name="audit-run")
    state.scan_config = {"targets": [{"original": "https://example.com"}]}
    state.update_scan_final_fields("done", "methodology", "technical", "recommendations")

    assert captured["scan_id"] == state.run_id
    assert captured["targets"] == [{"original": "https://example.com"}]
    assert "done" in str(captured["summary"])


def test_update_scan_final_fields_defaults_targets_to_empty(monkeypatch, tmp_path):
    captured: dict[str, object] = {}

    def fake_summary(scan_id: str, targets: object, summary: str) -> None:
        captured["targets"] = targets

    monkeypatch.setattr(hooks, "remember_pentest_summary", fake_summary)
    monkeypatch.chdir(tmp_path)

    state = ReportState(run_name="audit-run-2")
    state.update_scan_final_fields("x", "m", "t", "r")

    assert captured["targets"] == []
