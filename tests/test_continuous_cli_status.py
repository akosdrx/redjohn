"""Mock CLI status contract; actual Chromium/Nuclei E2E is a separate test."""

import json

import pytest

from redjohn.assessment.cli import main


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ({"errors": [{"code": "queue_capacity_exhausted"}], "pending_events": 1}, 1),
        ({"reconciliation_errors": 1}, 1),
        ({"pending_events": 0, "errors": [], "reconciliation_errors": 0}, 0),
        ({"pending_events": 1, "errors": []}, 0),
    ],
)
def test_mock_cli_distinguishes_blocked_continuation_from_batch_limit(
    tmp_path, monkeypatch, capsys, status, expected
):
    configuration = tmp_path / "config.json"
    configuration.write_text(json.dumps({"seeds": []}))

    async def configured(_config, _output, *, max_jobs):
        assert max_jobs == 1
        return {"coverage": [], "metrics": {"continuous_replay": status}}

    monkeypatch.setattr("redjohn.assessment.cli.configured_run", configured)
    result = main(
        ["run", "--config", str(configuration), "--output", str(tmp_path), "--max-jobs", "1"]
    )
    assert result == expected
    assert json.loads(capsys.readouterr().out)["continuous_replay"] == status
