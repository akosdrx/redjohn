"""Read-only report projection, actual HTTP authorization and real Chromium UI."""

import asyncio
import json
import os
from pathlib import Path

import httpx
import pytest

from redjohn.assessment.cli import configured_run
from redjohn.interface.viewer import auth, server
from redjohn.interface.viewer.assessment import REPORT_LIMIT, assessment_summary
from redjohn.interface.viewer.transcript import read_run_summary


@pytest.mark.parametrize("invalid", ["malformed", "oversized", "symlink", "wrong_product"])
def test_invalid_assessment_report_never_looks_like_clean_completion(tmp_path, invalid):
    report = tmp_path / "assessment-report.json"
    if invalid == "symlink":
        other = tmp_path / "other.json"
        other.write_text("{}")
        report.symlink_to(other)
    else:
        report.write_bytes(
            b"x" * (REPORT_LIMIT + 1)
            if invalid == "oversized"
            else b'{"product":"Other"}'
            if invalid == "wrong_product"
            else b"{broken"
        )
    summary = assessment_summary(tmp_path)
    assert summary["assessment"]["error"] == "assessment_report_unavailable"
    assert summary["finished"] is False
    assert summary["status"] == "failed"


def test_existing_legacy_run_record_takes_precedence(tmp_path):
    (tmp_path / "run.json").write_text(
        json.dumps(
            {
                "run_name": "preserved-user-run",
                "status": "stopped",
                "end_time": "2026-10-17T00:00:00Z",
            }
        )
    )
    (tmp_path / "assessment-report.json").write_text("{broken")
    assert read_run_summary(tmp_path) == {
        "run_name": "preserved-user-run",
        "status": "stopped",
        "end_time": "2026-10-17T00:00:00Z",
        "finished": True,
    }


async def test_actual_ffuf_report_web_view_chromium(tmp_path, monkeypatch):  # noqa: PLR0915 - actual UI, HTTP auth and file-replacement fence
    from playwright.async_api import async_playwright, expect  # noqa: PLC0415 - optional real browser extra

    from tests.test_ffuf_live import installed, owned_fixture  # noqa: PLC0415 - actual scanner fixture

    if not server.bundle_is_built():
        pytest.skip("blocked_missing_dependency: build the actual viewer assets first")
    # The only override is the account-state file location. Bootstrap tokens,
    # session cookies, HTTP handlers, scanner and browser are real.
    monkeypatch.setattr(auth, "AUTH_PATH", tmp_path / "local-account.json")
    with owned_fixture("127.0.0.1", tmp_path / "tls") as fixture:
        output = tmp_path / "redjohn-viewer-assessment"
        await configured_run(
            {
                "policy": {
                    "engagement_id": "RedJohn ffuf verification",
                    "owner_id": "operator",
                    "allowed_origins": [fixture.origin],
                    "profile": "isolated-lab",
                    "egress_mode": "local-fixture",
                    "request_budget": 8,
                },
                "ffuf": installed(),
                "tls": {"upstream_ca_file": str(fixture.ca_file)},
                "seeds": [{"url": fixture.origin + "/", "capabilities": ["ffuf_discover"]}],
            },
            output,
        )
        httpd, base, token = server.serve(output, open_browser=False)
        try:
            async with httpx.AsyncClient(trust_env=False) as client:
                assert (await client.get(base + "/api/run")).status_code == 403
                assert (await client.post(base + "/api/scans/start", json={})).status_code == 403
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(headless=True, chromium_sandbox=True)
                try:
                    context = await browser.new_context(
                        viewport={"width": 1440, "height": 1100}, reduced_motion="reduce"
                    )
                    page = await context.new_page()
                    failures = []
                    page.on("pageerror", lambda error: failures.append(str(error)))
                    await page.goto(
                        server.authorized_url(base, token), wait_until="domcontentloaded"
                    )
                    await expect(
                        page.get_by_role("heading", name="Bounded assessment", exact=True)
                    ).to_be_visible()
                    coverage = page.get_by_role("list", name="Assessment coverage")
                    await expect(coverage).to_contain_text("content discovery")
                    await expect(coverage).to_contain_text("Coverage: completed (1)")
                    await expect(
                        page.get_by_text("Read-only report snapshot", exact=True)
                    ).to_be_visible()
                    assert (
                        await page.request.post(base + "/api/scans/stop", data={})
                    ).status == 409
                    report_path = output / "assessment-report.json"
                    saved_path = output / "saved-report.json"
                    report_path.rename(saved_path)
                    try:
                        assert (
                            await page.request.post(base + "/api/scans/start", data={})
                        ).status == 409
                    finally:
                        saved_path.rename(report_path)
                    assert (await page.request.get(base + "/api/transcript")).status == 200
                    assert not failures
                    if picture := os.environ.get("REDJOHN_VIEWER_SCREENSHOT"):
                        await page.screenshot(path=picture, full_page=True)
                    await page.set_viewport_size({"width": 375, "height": 1000})
                    await expect(
                        page.get_by_role("heading", name="Bounded assessment", exact=True)
                    ).to_be_visible()
                    box = await coverage.bounding_box()
                    assert box and box["width"] > 0
                    assert await coverage.evaluate("(node) => node.scrollWidth <= node.clientWidth")
                    if picture:
                        await page.screenshot(
                            path=str(Path(picture).with_stem(Path(picture).stem + "-mobile")),
                            full_page=True,
                        )
                    await context.close()
                finally:
                    await browser.close()
        finally:
            await asyncio.to_thread(httpd.shutdown)
            httpd.server_close()
