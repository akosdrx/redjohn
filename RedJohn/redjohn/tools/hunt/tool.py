"""Run one explicitly authorized specialist through the existing sandbox.

Optional scanners are selected individually. A run requires an engagement
policy and shared resource admission; missing prerequisites never become an
empty or successful negative scan.
"""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlsplit

from agents import RunContextWrapper, function_tool

from redjohn.tools.hunt.nuclei import (
    BoundedScannerRunner,
    NucleiAdapter,
    NucleiContractError,
    NucleiLock,
    NucleiOptions,
    nuclei_argv,
    result_error,
)


_KINDS = ("sqli", "xss", "rce", "cve")
_CVE_ID = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_UNSAFE_URL = re.compile(r"[\s\n\r\"'`$\\]")
_TIMEOUT_SECONDS = 180
_OUTPUT_CHARS = 12_000


def hunt_argv(
    kind: str, url: str, cve_id: str = "", *, nuclei_lock: NucleiLock | None = None
) -> list[str]:
    """Build a fixed argv; Nuclei requires a separately reviewed bundle lock."""
    error = _check_url(url)
    if error:
        raise NucleiContractError(error)
    if kind == "sqli":
        return [
            "sqlmap",
            "-u",
            url,
            "--batch",
            "--disable-coloring",
            "--ignore-redirects",
            "--level",
            "1",
            "--risk",
            "1",
            "--threads",
            "1",
            "--timeout",
            "10",
            "--retries",
            "0",
        ]
    if kind == "xss":
        return [
            "dalfox",
            "url",
            url,
            "--no-color",
            "--silence",
            "--format",
            "json",
            "--rate-limit",
            "5",
            "--worker",
            "1",
            "--timeout",
            "10",
        ]
    if kind == "rce":
        return ["commix", "--batch", "--url", url]
    if kind != "cve":
        raise NucleiContractError("Unsupported hunt kind")
    if nuclei_lock is None:
        raise NucleiContractError("Nuclei requires an explicit binary and template-bundle lock")
    selections = tuple(
        item
        for item in nuclei_lock.templates
        if not cve_id or item.template_id.upper() == cve_id.upper()
    )
    if not selections:
        raise NucleiContractError("Requested CVE is not in the reviewed template selection")
    return nuclei_argv(url, nuclei_lock, NucleiOptions(), selections)


def _check_url(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
        _ = parsed.port
    except ValueError:
        return "hunt: invalid URL or port."
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        return "hunt: url must be an http(s) URL without embedded credentials."
    if _UNSAFE_URL.search(url):
        return "hunt: url contains whitespace or an unsupported metacharacter."
    return None


def _session(ctx: RunContextWrapper) -> Any:
    context = ctx.context if isinstance(ctx.context, dict) else {}
    session = context.get("sandbox_session")
    return session if session is not None and hasattr(session, "exec") else None


async def _run(ctx: RunContextWrapper, kind: str, url: str, cve_id: str) -> Any:  # noqa: PLR0911, PLR0912
    if kind not in _KINDS:
        return result_error(
            "unsupported_input", f"kind must be one of {', '.join(_KINDS)}", coverage="unsupported"
        )
    if (error := _check_url(url)) or (cve_id and not _CVE_ID.fullmatch(cve_id)):
        return result_error("unsupported_input", error or "Invalid CVE ID", coverage="unsupported")
    context = ctx.context if isinstance(ctx.context, dict) else {}
    policy = context.get("assessment_policy")
    governor = context.get("resource_governor")
    if policy is None or not callable(getattr(policy, "check_url", None)):
        return result_error("policy_required", "Explicit engagement policy is required")
    try:
        policy.check_url(url)
        profiles = (
            ("isolated-lab",)
            if kind == "rce"
            else (
                ("active-staging", "isolated-lab")
                if kind in {"sqli", "xss"}
                else ("safe-production", "active-staging", "isolated-lab")
            )
        )
        policy.check_capability(domains=("web",), profiles=profiles)
    except ValueError as error:
        return result_error("blocked_by_policy", str(error))
    if governor is None:
        return result_error("resource_governor_required", "Shared resource admission is required")
    session = _session(ctx)
    if session is None:
        return result_error("sandbox_unavailable", "No sandbox session is available")
    runner: BoundedScannerRunner | None = None
    try:
        if kind == "cve":
            lock = context.get("nuclei_lock")
            if isinstance(lock, dict):
                lock = NucleiLock.from_mapping(lock)
            if not isinstance(lock, NucleiLock):
                return result_error(
                    "template_lock_required",
                    "Configure the existing Nuclei binary and reviewed bundle lock",
                )
            runner = NucleiAdapter(session, lock)
        else:
            runner = BoundedScannerRunner(session)
        try:
            lease = governor.acquire(kind="scanner", estimated_bytes=64 * 1024 * 1024)
        except RuntimeError as error:
            return result_error("resource_admission_denied", str(error), coverage="blocked")
        try:
            if isinstance(runner, NucleiAdapter):
                return await runner.run(url, cve_id=cve_id, policy=policy)
            raw = await runner._execute(
                hunt_argv(kind, url, cve_id),
                NucleiOptions(max_output_bytes=_OUTPUT_CHARS),
                scan=False,
                digests={},
            )
            status = "succeeded"
            if raw.get("timed_out"):
                status = "timed_out"
            elif raw.get("truncated"):
                status = "resource_exhausted"
            elif raw.get("error") or raw.get("exit_code") != 0:
                status = "failed"
            return {
                "kind": kind,
                "execution_status": status,
                "coverage_status": "inconclusive",
                "findings": [],
                "no_finding_observed": False,
                **raw,
                "note": (
                    "Specialist output requires replay and validation; "
                    "no normalized negative result is asserted."
                ),
            }
        finally:
            lease.release()
    except (ValueError, OSError) as error:
        return result_error("adapter_contract_error", str(error), coverage="inconclusive")
    finally:
        if runner is not None:
            await runner.cleanup()


@function_tool(timeout=_TIMEOUT_SECONDS + 30)
async def hunt(ctx: RunContextWrapper, url: str, kind: str, cve_id: str = "") -> Any:
    """Run one policy-authorized specialist in the RedJohn sandbox.

    Select only an applicable test for observed input. Resource admission limits
    simultaneous execution. Nuclei uses the operator's pinned, reviewed HTTP
    template selection. A scanner hit is a candidate requiring replay.

    Args:
        url: In-scope http(s) URL without credentials.
        kind: ``sqli`` (sqlmap), ``xss`` (dalfox), ``rce`` (Commix, isolated lab
            only), or ``cve`` (the existing pinned Nuclei engine).
        cve_id: Optional explicit CVE ID already present in the reviewed bundle.
    """
    return await _run(ctx, kind.strip().lower(), url.strip(), cve_id.strip().upper())
