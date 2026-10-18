"""Opt-in ProjectDiscovery httpx and standard Katana, using one governed queue.

The host observes complete, TLS-verified responses before publishing inventory.
Only anonymous GET is supported here; existing authenticated browser/Nuclei
replay remains the execution path for sessions and captured request bodies.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.egress import EgressUnavailable
from redjohn.assessment.models import (
    AdapterResult,
    CoverageStatus,
    JobSpec,
    Surface,
    error_record,
    stable_key,
)
from redjohn.assessment.pinned_tools import BinaryPin, PinnedToolRunner
from redjohn.assessment.policy import PolicyDenied, origin_for
from redjohn.assessment.store import CapacityExceeded


if TYPE_CHECKING:
    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.contracts import HTTPRateLimits
    from redjohn.assessment.intelligence import TechnologyDetector
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


@dataclass(frozen=True)
class DiscoveryToolConfig:
    tool: str
    binary: BinaryPin
    rate_limit: int = 5
    request_timeout: int = 5
    depth: int = 2
    max_pages: int = 16
    js_crawl: bool = True

    @classmethod
    def from_mapping(cls, tool: str, value: dict[str, Any]) -> DiscoveryToolConfig:
        allowed = {"binary", "rate_limit", "request_timeout"}
        if tool == "katana":
            allowed |= {"depth", "max_pages", "js_crawl"}
        if tool not in {"httpx", "katana"} or not isinstance(value, dict) or set(value) - allowed:
            raise ValueError("invalid_discovery_tool_configuration")
        result = cls(
            tool,
            BinaryPin.from_mapping(tool, value.get("binary")),
            value.get("rate_limit", 5),
            value.get("request_timeout", 5),
            value.get("depth", 2),
            value.get("max_pages", 16) if tool == "katana" else 1,
            value.get("js_crawl", True),
        )
        if (
            type(result.rate_limit) is not int
            or not 1 <= result.rate_limit <= 10
            or type(result.request_timeout) is not int
            or not 1 <= result.request_timeout <= 15
            or type(result.depth) is not int
            or not 1 <= result.depth <= 3
            or type(result.max_pages) is not int
            or not 1 <= result.max_pages <= 32
            or type(result.js_crawl) is not bool
        ):
            raise ValueError("invalid_discovery_tool_limits")
        return result

    @property
    def version(self) -> str:
        return self.binary.version

    @property
    def revision(self) -> str:
        # Rate and transport timeout changes do not repeat a completed test.
        return stable_key(
            [
                "redjohn-discovery-adapter-v1",
                self.tool,
                self.binary.sha256,
                self.depth,
                self.max_pages,
                self.js_crawl,
            ]
        )

    def validate_input(self, policy: EngagementPolicy, surface: Surface, spec: JobSpec) -> None:
        policy.check_readonly_request(surface.url, surface.method)
        if (
            surface.method != "GET"
            or surface.actor_id != "anonymous"
            or surface.body_sha256
            or surface.content_type
            or urlsplit(surface.url).fragment
            or not urlsplit(surface.url).path.startswith("/")
            or "," in surface.url
            or spec.options
        ):
            raise ValueError(f"{self.tool}_unsupported_input")
        if spec.tool_version != self.version or spec.template_version != self.revision:
            raise ValueError(f"{self.tool}_configuration_revision_mismatch")


def katana_scope(url: str) -> str:
    parsed = urlsplit(origin_for(url))
    default = 443 if parsed.scheme == "https" else 80
    authority, suffix = parsed.netloc, ""
    if parsed.port == default:
        authority = authority.rsplit(":", 1)[0]
        suffix = f"(?::{default})?"
    return "(?i)^" + re.escape(f"{parsed.scheme}://{authority}") + suffix + r"(?:/|$)"


def request_identity(url: str) -> str:
    """Reconcile origin spelling only; preserve every path/query byte and order."""
    parsed = urlsplit(url)
    prefix_length = len(parsed.scheme) + 3 + len(parsed.netloc)
    return origin_for(url) + url[prefix_length:]


def discovery_argv(config: DiscoveryToolConfig, url: str, proxy: str) -> list[str]:
    common = [
        str(config.binary.path),
        "-u",
        url,
        "-silent",
        "-nc",
        "-duc",
        "-proxy",
        proxy,
        "-rl",
        str(config.rate_limit),
        "-timeout",
        str(config.request_timeout),
        "-H",
        "Accept-Encoding: identity",
    ]
    if config.tool == "httpx":
        return [
            *common,
            "-json",
            "-nfs",
            "-threads",
            "1",
            "-retries",
            "0",
            "-no-stdin",
            "-x",
            "GET",
            "-rstr",
            "65536",
            "-rsts",
            "65536",
            "-no-decode",
            "-status-code",
            "-content-type",
            "-title",
            "-web-server",
            "-irh",
            "-ob",
        ]
    # Never enable headless/hybrid, forms, path climbing, knowledge-base/model
    # downloads, secret validation, dashboard upload or automatic redirects.
    return [
        *common,
        "-jsonl",
        # v1.8.0's -ob mutates response.Body before JS parsing. Filtering the
        # serialization instead preserves actual JS discovery without bodies
        # or secret-bearing raw headers in the worker output.
        "-eof",
        "raw,body,headers",
        "-c",
        "1",
        "-p",
        "1",
        "-retry",
        "0",
        "-d",
        str(config.depth),
        "-mdp",
        str(config.max_pages),
        "-mrs",
        "65536",
        "-dr",
        "-cs",
        katana_scope(url),
        *(["-jc"] if config.js_crawl else []),
    ]


class BoundedDiscoveryAdapter:
    resource_class = "scanner"

    def __init__(
        self,
        config: DiscoveryToolConfig,
        policy: EngagementPolicy,
        store: AssessmentStore,
        rate_limits: HTTPRateLimits,
        *,
        tls_config: BrowserTLSConfig | None = None,
        technology: TechnologyDetector | None = None,
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        self.rate_limits, self.tls_config, self.technology = rate_limits, tls_config, technology
        self.runner = PinnedToolRunner(
            config.tool, config.binary, store.path.parent / (config.tool + "-workers")
        )
        self.partial_evidence_refs: tuple[str, ...] = ()

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:  # noqa: PLR0915 - owned proxy/worker/evidence lifecycle
        self.partial_evidence_refs = ()
        tool = self.config.tool
        responses: dict[str, Any] = {}
        observed_headers: dict[str, dict[str, str]] = {}
        failure: list[str] = []
        try:
            self.config.validate_input(self.policy, surface, spec)
        except PolicyDenied:
            raise
        except ValueError as exc:
            return AdapterResult(
                "failed", "unsupported", error=error_record(str(exc), coverage_effect="unsupported")
            )
        if not self.config.binary.path.is_file():
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record(f"{tool}_binary_missing", coverage_effect="blocked"),
            )
        seen: set[str] = set()

        def admit(url: str) -> None:
            identity = request_identity(url)
            if (tool == "httpx" or not seen) and identity != request_identity(surface.url):
                failure[:] = [f"{tool}_request_rewrite_unsupported"]
                raise PolicyDenied(failure[0])
            if identity in seen:
                failure[:] = [f"{tool}_duplicate_request_denied"]
                raise PolicyDenied(failure[0])
            if len(seen) >= self.config.max_pages:
                failure[:] = [f"{tool}_page_limit_reached"]
                raise CapacityExceeded(failure[0])
            if not self.rate_limits.admit(origin_for(url)):
                failure[:] = ["rate_limited"]
                raise CapacityExceeded(failure[0])
            try:
                self.store.consume_requests(self.policy)
            except CapacityExceeded:
                failure[:] = ["request_budget_exceeded"]
                raise
            seen.add(identity)

        def response_policy(_url: str, _status: int, fields: tuple[tuple[str, str], ...]) -> None:
            observed_headers[_url] = {
                name: value
                for name, value in fields
                if name in {"server", "x-powered-by", "content-type"}
            }
            if any(
                name == "content-encoding" and value.lower() != "identity" for name, value in fields
            ):
                failure[:] = [f"{tool}_encoded_response_unsupported"]
                raise ValueError(failure[0])

        def complete(url: str, method: str, status: int, headers: dict[str, str]) -> None:
            self.rate_limits.observe(origin_for(url), status, headers)
            # Keep only the claimed product headers, not cookies or raw bodies.
            responses[request_identity(url)] = {
                "url": url,
                "method": method,
                "status": status,
                "headers": observed_headers.get(url, {}),
            }

        proxy = BrowserEgressProxy(
            self.policy,
            max_connections=2,
            max_wire_bytes=64 * 1024,
            timeout_seconds=min(self.config.request_timeout, 10),
            request_admission=admit,
            on_complete=complete,
            response_policy=response_policy,
            tls_config=self.tls_config,
        )
        started = time.monotonic()
        try:
            await proxy.start()
            await self.runner.prepare(self.policy, proxy)
            try:
                health = await self.runner.healthcheck()
            except ValueError as exc:
                return AdapterResult(
                    "failed", "blocked", error=error_record(str(exc), coverage_effect="blocked")
                )
            raw = await self.runner.execute(
                discovery_argv(self.config, surface.url, proxy.url), spec.timeout_seconds
            )
            await proxy.close()
            return self.normalize(
                job, surface, raw, responses, failure, proxy, health, time.monotonic() - started
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
                    "tool": tool,
                    "interrupted": True,
                    "complete_responses": list(responses.values()),
                    "forwarded_requests": proxy.forwarded_requests,
                    "finding_claim": "none_discovery_only",
                },
                job_id=job["id"],
                kind=tool + "_interrupted",
            )
            self.partial_evidence_refs = (ref,)
            raise
        finally:
            await asyncio.shield(self.cleanup())
            await proxy.close()

    def normalize(  # noqa: PLR0912, PLR0915 - untrusted output and independent coverage state
        self,
        job: dict[str, Any],
        surface: Surface,
        raw: dict[str, Any],
        responses: dict[str, Any],
        failure: list[str],
        proxy: BrowserEgressProxy,
        health: dict[str, str],
        duration: float,
    ) -> AdapterResult:
        tool, code = self.config.tool, failure[0] if failure else ""
        records: dict[str, str] = {}
        inferred: set[str] = set()
        schema_error = False
        try:
            lines = raw.get("stdout", "").splitlines()
            if len(lines) > 256:
                raise ValueError("discovery_record_limit")  # noqa: TRY301
            for line in lines:
                row = json.loads(line)
                if tool == "httpx":
                    url, status = row["url"], row["status_code"]
                else:
                    request = row["request"]
                    url = request["endpoint"]
                    if request.get("method") != "GET":
                        raise ValueError("discovery_non_get_output")  # noqa: TRY301
                    status = (row.get("response") or {}).get("status_code")
                    if status is None:
                        if isinstance(url, str) and len(url) <= 4096:
                            inferred.add(url)
                            continue
                        raise ValueError("discovery_invalid_endpoint")  # noqa: TRY301
                if (
                    type(status) is not int
                    or request_identity(url) not in responses
                    or responses[request_identity(url)]["status"] != status
                ):
                    raise ValueError("discovery_observer_mismatch")  # noqa: TRY301
                records[request_identity(url)] = url
        except (ValueError, KeyError, TypeError, AttributeError):
            schema_error = True
        if raw.get("timed_out"):
            code = code or f"{tool}_timeout"
        elif raw.get("truncated"):
            code = code or f"{tool}_output_truncated"
        elif proxy.upstream_tls_failures:
            code = code or f"{tool}_upstream_tls_verification_failed"
        elif (
            proxy.denied_requests != (proxy.blocked_proxy_type_probes if tool == "katana" else 0)
        ) or proxy.limit_drops:
            code = code or f"{tool}_proxy_incomplete_response"
        elif schema_error:
            code = code or f"{tool}_output_schema_error"
        elif raw.get("error") or raw.get("exit_code") != 0:
            code = code or f"{tool}_worker_failed"
        elif (
            request_identity(surface.url) not in responses
            or not records
            or (tool == "httpx" and set(records) != {request_identity(surface.url)})
        ):
            code = code or f"{tool}_incomplete_coverage"
        if any(row["status"] in {401, 403, 429, 503} for row in responses.values()):
            code = code or (
                "rate_limited"
                if any(row["status"] == 429 for row in responses.values())
                else f"{tool}_permission_or_service_unavailable"
            )
        ref = self.store.evidence_put(
            self.policy.engagement_id,
            {
                "tool": tool,
                **health,
                "configuration_revision": self.config.revision,
                # JSON headers may contain Set-Cookie, even for anonymous GET.
                # Do not persist raw CLI output or fingerprint/template bodies.
                "stdout_sha256": hashlib.sha256(raw.get("stdout", "").encode()).hexdigest(),
                "stdout_bytes": raw.get("stdout_bytes", 0),
                "reconciled_endpoints": sorted(records.values()),
                "stderr": raw.get("stderr", ""),
                "observations": list(responses.values()),
                "inferred_endpoints": sorted(inferred),
                "error_code": code or None,
                "duration_seconds": duration,
                "egress_attestations": list(self.runner.boundary.attestations)
                if self.runner.boundary
                else [],
                "tls_validation": "failed"
                if proxy.upstream_tls_failures
                else ("host_proxy_verified" if proxy.forwarded_requests else "not_observed")
                if urlsplit(surface.url).scheme == "https"
                else "not_applicable_local_http",
                "upstream_tls_failures": proxy.upstream_tls_failures,
                "finding_claim": "none_discovery_only",
                "coverage_scope": "single_readonly_url"
                if tool == "httpx"
                else "bounded_standard_crawl",
                "crawl_limits": {
                    "max_pages": self.config.max_pages,
                    "max_depth": self.config.depth if tool == "katana" else 0,
                    "response_wire_bytes": 65536,
                },
                "blocked_optional_proxy_type_probes": proxy.blocked_proxy_type_probes,
            },
            job_id=job["id"],
            kind=tool + "_discovery",
        )
        discovered = 0
        for identity, reported_url in sorted(records.items()):
            url = surface.url if identity == request_identity(surface.url) else reported_url
            if 200 <= responses[identity]["status"] < 400:
                self.store.upsert_surface(
                    self.policy.engagement_id,
                    replace(
                        surface,
                        url=url,
                        source="observed",
                        request_ref=ref,
                        input_location=surface.input_location if url == surface.url else "",
                        input_name=surface.input_name if url == surface.url else "",
                    ),
                )
                discovered += 1
                if self.technology is not None:
                    self.technology.detect_headers(
                        self.policy.engagement_id,
                        responses[identity]["headers"],
                        evidence_ref=ref,
                        asset_ref=url,
                        actor_ref=surface.actor_id,
                    )
        summary = {
            "requests": proxy.forwarded_requests,
            "complete_responses": len(responses),
            "discovered_endpoints": discovered,
            "inferred_endpoints": len(inferred),
            "evidence_refs": [ref],
            "model_calls": 0,
            "duration_seconds": duration,
            "blocked_optional_proxy_type_probes": proxy.blocked_proxy_type_probes,
            "outcome": "discovery_completed" if not code else "discovery_incomplete",
            "crawl_limits": {
                "max_pages": self.config.max_pages,
                "max_depth": self.config.depth if tool == "katana" else 0,
                "response_wire_bytes": 65536,
            },
            "limitations": [
                "standard_mode_no_javascript_execution",
                "regex_js_extraction_not_complete",
                "headless_coverage_requires_playwright",
            ]
            if tool == "katana"
            else ["single_url_metadata_not_vulnerability_validation"],
        }
        if code:
            coverage: CoverageStatus = "inconclusive"
            if code in {"rate_limited", "request_budget_exceeded"}:
                coverage = "blocked"
            elif code == f"{tool}_request_rewrite_unsupported":
                coverage = "unsupported"
            error = error_record(code, coverage_effect=coverage)
            error["partial_evidence_refs"] = [ref]
            return AdapterResult("failed", coverage, summary, error=error)
        if tool == "katana" and len(responses) >= self.config.max_pages:
            summary["outcome"] = "bounded_page_budget_reached"
            return AdapterResult(
                "succeeded",
                "partial",
                summary,
                error=error_record("katana_page_budget_reached", coverage_effect="partial"),
            )
        return AdapterResult("succeeded", "completed", summary)

    async def healthcheck(self) -> dict[str, str]:
        return await self.runner.healthcheck()

    async def cancel(self) -> None:
        await self.runner.cancel()

    async def cleanup(self) -> None:
        await self.runner.cleanup()


class HTTPXProbeAdapter(BoundedDiscoveryAdapter):
    """ProjectDiscovery's Go binary, never the Python httpx client executable."""


class KatanaDiscoveryAdapter(BoundedDiscoveryAdapter):
    """Supplemental standard crawl; mandatory Playwright stays independently governed."""
