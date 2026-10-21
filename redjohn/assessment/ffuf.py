"""Opt-in, pinned ffuf path discovery; the host proxy owns network admission.

Only approved relative paths are substituted. No arbitrary flags, file paths,
headers, bodies, recursion, calibration, authentication or external mutators.
Scanner JSON is reconciled with complete host-observed responses before an
endpoint becomes observed inventory. Discovery never creates a finding.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import signal
import sys
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.egress import EgressUnavailable, LinuxEgressBoundary
from redjohn.assessment.models import (
    AdapterResult,
    CoverageStatus,
    JobSpec,
    Surface,
    error_record,
    stable_key,
)
from redjohn.assessment.policy import EngagementPolicy, PolicyDenied, origin_for
from redjohn.assessment.store import CapacityExceeded


if TYPE_CHECKING:
    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.contracts import HTTPRateLimits
    from redjohn.assessment.store import AssessmentStore


VERSION = "2.1.0"
OUTPUT_LIMIT = 128 * 1024


@dataclass(frozen=True)
class FFUFConfig:
    binary_path: Path
    binary_sha256: str
    paths: tuple[str, ...]
    version: str = VERSION
    rate_limit: int = 5
    request_timeout: int = 5

    def __post_init__(self) -> None:
        if (
            not self.binary_path.is_absolute()
            or self.version != VERSION
            or re.fullmatch(r"[0-9a-f]{64}", self.binary_sha256) is None
            or type(self.rate_limit) is not int
            or not 1 <= self.rate_limit <= 10
            or type(self.request_timeout) is not int
            or not 1 <= self.request_timeout <= 15
            or not 1 <= len(self.paths) <= 64
            or len(set(self.paths)) != len(self.paths)
            or any(
                not isinstance(word, str)
                or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,127}", word) is None
                or "FUZZ" in word
                or any(part in {"", ".", ".."} for part in word.split("/"))
                for word in self.paths
            )
        ):
            raise ValueError("invalid_ffuf_configuration")

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> FFUFConfig:
        if (
            not isinstance(value, dict)
            or set(value) - {"binary", "paths", "rate_limit", "request_timeout"}
            or not isinstance(value.get("binary"), dict)
            or set(value["binary"]) != {"path", "sha256", "version"}
            or not all(isinstance(x, str) for x in value["binary"].values())
            or not isinstance(value.get("paths"), list)
            or not all(isinstance(word, str) for word in value["paths"])
        ):
            raise ValueError("invalid_ffuf_configuration")
        return cls(
            Path(value["binary"]["path"]),
            value["binary"]["sha256"],
            tuple(value["paths"]),
            value["binary"]["version"],
            value.get("rate_limit", 5),
            value.get("request_timeout", 5),
        )

    @property
    def revision(self) -> str:
        # A scheduling-only rate/timeout change cannot authorize duplicate
        # network tests. Reviewed inputs and engine content define identity.
        return stable_key([self.binary_sha256, self.paths])

    def validate_input(
        self, policy: EngagementPolicy, surface: Surface, spec: JobSpec
    ) -> tuple[str, ...]:
        policy.check_capability(domains=("web",), profiles=("active-staging", "isolated-lab"))
        parsed = urlsplit(surface.url)
        if (
            surface.method != "GET"
            or surface.actor_id != "anonymous"
            or surface.content_type
            or surface.body_sha256
            or not parsed.path.endswith("/")
            or parsed.query
            or parsed.fragment
            or "FUZZ" in surface.url
            or set(spec.options) - {"path_subset"}
        ):
            raise ValueError("ffuf_unsupported_input")
        subset = spec.options.get("path_subset", list(self.paths))
        if (
            not isinstance(subset, list)
            or not subset
            or not all(isinstance(word, str) and word in self.paths for word in subset)
            or len(subset) != len(set(subset))
        ):
            raise ValueError("ffuf_unapproved_paths")
        for word in subset:
            policy.check_readonly_request(surface.url + word, "GET")
        if spec.tool_version != self.version or spec.template_version != self.revision:
            raise ValueError("ffuf_configuration_revision_mismatch")
        return tuple(subset)


def ffuf_argv(config: FFUFConfig, base_url: str, wordlist: Path, proxy_url: str) -> list[str]:
    """All flags are host-owned; even ffufrc comes from the supervisor's empty HOME."""
    return [
        str(config.binary_path),
        "-u",
        base_url + "FUZZ",
        "-w",
        str(wordlist),
        "-x",
        proxy_url,
        "-X",
        "GET",
        "-t",
        "1",
        "-rate",
        str(config.rate_limit),
        "-timeout",
        str(config.request_timeout),
        "-noninteractive",
        "-json",
        "-s",
        "-mc",
        "all",
        "-ignore-body",
        "-H",
        "Accept-Encoding: identity",
    ]


class FFUFDiscoveryAdapter:
    resource_class = "scanner"

    def __init__(
        self,
        config: FFUFConfig,
        policy: EngagementPolicy,
        store: AssessmentStore,
        rate_limits: HTTPRateLimits,
        *,
        tls_config: BrowserTLSConfig | None = None,
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        self.rate_limits, self.tls_config = rate_limits, tls_config
        self._process: asyncio.subprocess.Process | None = None
        self._boundary: LinuxEgressBoundary | None = None
        self._workspace: Path | None = None
        self._token = ""
        self.partial_evidence_refs: tuple[str, ...] = ()

    async def _terminate(self) -> None:
        process = self._process
        if process is None:
            return
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), 2)
        except TimeoutError:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            await process.wait()
        # The supervisor normally reaps its own process group. A forced
        # supervisor death still needs descendant cleanup before lease release.
        if self._boundary is not None:
            await self._boundary.terminate_workers(process.pid)
        elif self._workspace is not None:
            marker = self._workspace / ".redjohn-hunt" / (self._token + ".child")
            if marker.is_file():
                with contextlib.suppress(OSError, ValueError):
                    os.killpg(int(marker.read_text()), signal.SIGKILL)
        self._process = None

    async def _execute(
        self, argv: list[str], timeout: float, *, wordlist: Path | None = None
    ) -> dict[str, Any]:
        assert self._workspace is not None
        self._token = uuid.uuid4().hex
        digests = {str(self.config.binary_path): self.config.binary_sha256}
        if wordlist is not None:
            digests[str(wordlist)] = hashlib.sha256(wordlist.read_bytes()).hexdigest()
        config = {
            "argv": argv,
            "token": self._token,
            "digests": digests,
            "timeout": timeout,
            "max_output_bytes": OUTPUT_LIMIT,
        }
        source = Path(__file__).parents[1].joinpath("tools/hunt/bounded_worker.py").read_text()
        command = [sys.executable, "-I", "-S", "-c", source, json.dumps(config)]
        if self._boundary is not None:
            command = self._boundary.wrap_argv(command, cwd=self._workspace)
        spawn = asyncio.create_task(
            asyncio.create_subprocess_exec(
                *command,
                cwd=self._workspace,
                env={
                    "PATH": "/usr/bin:/bin",
                    "HOME": str(self._workspace),
                    "TMPDIR": str(self._workspace),
                    "LANG": "C.UTF-8",
                },
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                start_new_session=True,
            )
        )
        try:
            self._process = await asyncio.shield(spawn)
        except asyncio.CancelledError:
            self._process = await spawn
            await asyncio.shield(self._terminate())
            raise

        async def drain(stream: asyncio.StreamReader | None) -> bytes:
            assert stream is not None
            data = bytearray()
            while chunk := await stream.read(8192):
                if len(data) + len(chunk) > OUTPUT_LIMIT * 12 + 8192:
                    raise ValueError("ffuf_supervisor_output_limit")
                data.extend(chunk)
            return bytes(data)

        tasks = [
            asyncio.create_task(drain(stream))
            for stream in (self._process.stdout, self._process.stderr)
        ]
        try:
            async with asyncio.timeout(timeout + 5):
                stdout, _stderr = await asyncio.gather(*tasks)
                await self._process.wait()
            result = json.loads(stdout)
            if not isinstance(result, dict):
                raise TypeError("ffuf_supervisor_schema_error")
            return result
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.shield(self._terminate())

    async def healthcheck(self) -> dict[str, Any]:
        raw = await self._execute([str(self.config.binary_path), "-V"], 5)
        if (
            raw.get("error")
            or raw.get("exit_code") != 0
            or raw.get("truncated")
            or not re.fullmatch(r"\s*(?:ffuf version: )?2\.1\.0\s*", raw.get("stdout", ""))
        ):
            raise ValueError("ffuf_binary_or_version_mismatch")
        return {"tool_version": self.config.version, "binary_sha256": self.config.binary_sha256}

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:  # noqa: PLR0915 - one owned proxy/worker lifecycle
        self.partial_evidence_refs = ()
        try:
            paths = self.config.validate_input(self.policy, surface, spec)
        except PolicyDenied:
            raise
        except ValueError as exc:
            return AdapterResult(
                "failed", "unsupported", error=error_record(str(exc), coverage_effect="unsupported")
            )
        if not self.config.binary_path.is_file():
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record("ffuf_binary_missing", coverage_effect="blocked"),
            )
        responses: dict[str, dict[str, Any]] = {}
        expected = {surface.url + path for path in paths}
        seen: set[str] = set()
        failure: list[str] = []

        def admit(url: str) -> None:
            if url not in expected or url in seen:
                failure[:] = ["ffuf_unapproved_or_duplicate_request"]
                raise PolicyDenied(failure[0])
            if not self.rate_limits.admit(origin_for(url)):
                failure[:] = ["rate_limited"]
                raise CapacityExceeded(failure[0])
            try:
                self.store.consume_requests(self.policy)
            except CapacityExceeded:
                failure[:] = ["request_budget_exceeded"]
                raise
            seen.add(url)

        def response_policy(_url: str, _status: int, fields: tuple[tuple[str, str], ...]) -> None:
            if any(
                name == "content-encoding" and value.lower() != "identity" for name, value in fields
            ):
                failure[:] = ["ffuf_encoded_response_unsupported"]
                raise ValueError(failure[0])

        def complete(url: str, method: str, status: int, headers: dict[str, str]) -> None:
            self.rate_limits.observe(origin_for(url), status, headers)
            responses[url] = {"url": url, "method": method, "status": status, "complete": True}

        proxy = BrowserEgressProxy(
            self.policy,
            max_connections=2,
            max_wire_bytes=1024 * 1024,
            timeout_seconds=min(self.config.request_timeout, 10),
            request_admission=admit,
            on_complete=complete,
            response_policy=response_policy,
            tls_config=self.tls_config,
        )
        started = time.monotonic()
        root = self.store.path.parent / "ffuf-workers"
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix="job-", dir=root) as directory:
                self._workspace = Path(directory)
                await proxy.start()
                if self.policy.egress_mode == "enforced":
                    self._boundary = LinuxEgressBoundary(
                        proxy.url, self._workspace, read_only_paths=(self.config.binary_path,)
                    )
                    await self._boundary.start()
                    await self._boundary.attest()
                elif (
                    self.policy.egress_mode != "local-fixture"
                    or self.policy.profile != "isolated-lab"
                ):
                    raise EgressUnavailable("ffuf_kernel_egress_required")  # noqa: TRY301 - fail closed
                try:
                    health = await self.healthcheck()
                except ValueError as exc:
                    return AdapterResult(
                        "failed",
                        "blocked",
                        error=error_record(
                            str(exc), category="capability", coverage_effect="blocked"
                        ),
                    )
                wordlist = self._workspace / "approved-paths.txt"
                wordlist.write_text("\n".join(paths) + "\n")
                wordlist.chmod(0o600)
                raw = await self._execute(
                    ffuf_argv(self.config, surface.url, wordlist, proxy.url),
                    spec.timeout_seconds,
                    wordlist=wordlist,
                )
                await proxy.close()
                return self.normalize(
                    job,
                    surface,
                    paths,
                    raw,
                    responses,
                    failure,
                    proxy,
                    health,
                    time.monotonic() - started,
                )
        except EgressUnavailable as exc:
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(str(exc).split(":")[0], coverage_effect="blocked"),
            )
        except asyncio.CancelledError:
            ref = self.store.evidence_put(
                self.policy.engagement_id,
                {
                    "tool": "ffuf",
                    "interrupted": True,
                    "expected_requests": len(paths),
                    "forwarded_requests": proxy.forwarded_requests,
                    "complete_responses": list(responses.values()),
                    "coverage_status": "partial",
                    "finding_claim": "none_discovery_only",
                },
                job_id=job["id"],
                kind="ffuf_interrupted",
            )
            self.partial_evidence_refs = (ref,)
            raise
        finally:
            await asyncio.shield(self.cleanup())
            await proxy.close()

    def normalize(  # noqa: PLR0912 - independent execution/coverage boundaries
        self,
        job: dict[str, Any],
        surface: Surface,
        paths: tuple[str, ...],
        raw: dict[str, Any],
        responses: dict[str, dict[str, Any]],
        failure: list[str],
        proxy: BrowserEgressProxy,
        health: dict[str, Any],
        duration: float,
    ) -> AdapterResult:
        code = failure[0] if failure else ""
        records: dict[str, int] = {}
        try:
            for line in raw.get("stdout", "").splitlines():
                row = json.loads(line)
                url, status = row["url"], row["status"]
                if (
                    len(records) >= len(paths)
                    or url in records
                    or type(status) is not int
                    or url not in responses
                    or responses[url]["status"] != status
                ):
                    raise ValueError("ffuf_output_observer_mismatch")  # noqa: TRY301 - normalize untrusted JSON
                records[url] = status
        except (ValueError, KeyError, TypeError):
            code = code or "ffuf_output_schema_error"
        if raw.get("timed_out"):
            code = code or "ffuf_timeout"
        elif raw.get("truncated"):
            code = code or "ffuf_output_truncated"
        elif raw.get("error") or raw.get("exit_code") != 0:
            code = code or "ffuf_worker_failed"
        elif proxy.upstream_tls_failures:
            code = code or "ffuf_upstream_tls_verification_failed"
        elif proxy.denied_requests or proxy.limit_drops:
            code = code or "ffuf_proxy_incomplete_response"
        elif len(records) != len(paths) or len(responses) != len(paths):
            code = code or "ffuf_incomplete_coverage"
        if any(row["status"] in {401, 403, 429, 503} for row in responses.values()):
            code = code or (
                "rate_limited"
                if any(row["status"] == 429 for row in responses.values())
                else "ffuf_permission_or_service_unavailable"
            )
        ref = self.store.evidence_put(
            self.policy.engagement_id,
            {
                "tool": "ffuf",
                **health,
                "configuration_revision": self.config.revision,
                "stdout": raw.get("stdout", ""),
                "stderr": raw.get("stderr", ""),
                "observations": list(responses.values()),
                "expected_requests": len(paths),
                "duration_seconds": duration,
                "error_code": code or None,
                "egress_attestations": list(self._boundary.attestations) if self._boundary else [],
                "tls_validation": "host_proxy_verified",
                "finding_claim": "none_discovery_only",
            },
            job_id=job["id"],
            kind="ffuf_discovery",
        )
        discovered = 0
        for url, row in responses.items():
            if records.get(url) == row["status"] and 200 <= row["status"] < 400:
                self.store.upsert_surface(
                    self.policy.engagement_id,
                    Surface(
                        url,
                        tenant_id=surface.tenant_id,
                        workflow_state=surface.workflow_state,
                        request_ref=ref,
                        source="observed",
                        session_revision=surface.session_revision,
                    ),
                )
                discovered += 1
        summary = {
            "requests": proxy.forwarded_requests,
            "complete_responses": len(responses),
            "expected_requests": len(paths),
            "discovered_endpoints": discovered,
            "evidence_refs": [ref],
            "model_calls": 0,
            "duration_seconds": duration,
            "outcome": "path_discovery_completed" if not code else "path_discovery_incomplete",
        }
        if code:
            coverage: CoverageStatus = (
                "blocked" if code in {"rate_limited", "request_budget_exceeded"} else "inconclusive"
            )
            error = error_record(code, coverage_effect=coverage)
            error["partial_evidence_refs"] = [ref]
            return AdapterResult("failed", coverage, summary, error=error)
        return AdapterResult("succeeded", "completed", summary)

    async def cancel(self) -> None:
        await self._terminate()

    async def cleanup(self) -> None:
        await self._terminate()
        if self._boundary is not None:
            await self._boundary.close()
            self._boundary = None
        self._workspace = None
