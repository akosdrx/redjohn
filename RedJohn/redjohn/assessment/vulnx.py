"""One bounded VulnX intelligence adapter, never a vulnerability scanner.

Only host-approved public CVE IDs leave the controller. Provider egress is a
separate service policy and cannot add the provider to the engagement's active
target scope. API keys, when explicitly configured, stay in the host proxy.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import os
import re
import stat
import time
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

from redjohn.assessment.browser_proxy import BrowserEgressProxy
from redjohn.assessment.egress import EgressUnavailable
from redjohn.assessment.intelligence import AdvisoryRecord
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
from redjohn.assessment.store import CapacityExceeded, json_text


if TYPE_CHECKING:
    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.contracts import HTTPRateLimits
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


PUBLIC_API = "https://api.projectdiscovery.io"
_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,10}\Z")


@dataclass(frozen=True)
class VulnXConfig:
    binary: BinaryPin
    cve_ids: tuple[str, ...]
    api_ips: tuple[str, ...]
    api_url: str = PUBLIC_API
    request_timeout: int = 10
    ttl_seconds: int = 3600
    api_key_file: Path | None = None

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> VulnXConfig:
        if (
            not isinstance(value, dict)
            or set(value)
            - {
                "binary",
                "cve_ids",
                "api_ips",
                "api_url",
                "request_timeout",
                "ttl_seconds",
                "api_key_file",
            }
            or not isinstance(value.get("cve_ids"), list)
            or not 1 <= len(value["cve_ids"]) <= 8
            or not all(isinstance(item, str) and _CVE.fullmatch(item) for item in value["cve_ids"])
            or len(set(value["cve_ids"])) != len(value["cve_ids"])
            or not isinstance(value.get("api_ips"), list)
            or not 1 <= len(value["api_ips"]) <= 16
            or not all(isinstance(item, str) for item in value["api_ips"])
            or not isinstance(value.get("api_url", PUBLIC_API), str)
            or (
                value.get("api_key_file") is not None
                and (
                    not isinstance(value["api_key_file"], str)
                    or not Path(value["api_key_file"]).is_absolute()
                )
            )
        ):
            raise ValueError("invalid_vulnx_configuration")
        api_url = value.get("api_url", PUBLIC_API)
        parsed = urlsplit(api_url)
        if (
            parsed.scheme != "https"
            or parsed.path
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise ValueError("vulnx_requires_exact_https_provider_origin")
        if origin_for(api_url) == origin_for(PUBLIC_API):
            api_url = PUBLIC_API
        if api_url != PUBLIC_API:
            # Custom remote services are not an implicit asset-upload facility.
            # Only an owned literal-IP HTTPS lab fixture is supported as override.
            ipaddress.ip_address(str(urlsplit(api_url).hostname))
        ips = tuple(str(ipaddress.ip_address(item)) for item in value["api_ips"])
        if api_url == PUBLIC_API and any(not ipaddress.ip_address(item).is_global for item in ips):
            raise ValueError("vulnx_public_provider_requires_public_ip_pins")
        result = cls(
            BinaryPin.from_mapping("vulnx", value.get("binary")),
            tuple(value["cve_ids"]),
            ips,
            api_url,
            value.get("request_timeout", 10),
            value.get("ttl_seconds", 3600),
            Path(value["api_key_file"]) if value.get("api_key_file") is not None else None,
        )
        if (
            type(result.request_timeout) is not int
            or not 1 <= result.request_timeout <= 15
            or type(result.ttl_seconds) is not int
            or not 1 <= result.ttl_seconds <= 86400
        ):
            raise ValueError("invalid_vulnx_limits")
        return result

    @property
    def version(self) -> str:
        return self.binary.version

    @property
    def revision(self) -> str:
        return stable_key(
            [
                "redjohn-vulnx-adapter-v1",
                self.binary.sha256,
                self.cve_ids,
                self.api_url,
                self.api_ips,
                self.ttl_seconds,
            ]
        )

    def validate_input(
        self, policy: EngagementPolicy, surface: Surface, spec: JobSpec
    ) -> tuple[str, ...]:
        policy.check_scope_url(surface.url)
        if (
            surface.method != "GET"
            or surface.actor_id != "anonymous"
            or surface.body_sha256
            or set(spec.options) - {"cve_ids"}
        ):
            raise ValueError("vulnx_unsupported_input")
        if spec.tool_version != self.version or spec.template_version != self.revision:
            raise ValueError("vulnx_configuration_revision_mismatch")
        ids = spec.options.get("cve_ids", list(self.cve_ids))
        if (
            not isinstance(ids, list)
            or not ids
            or not all(isinstance(item, str) and item in self.cve_ids for item in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ValueError("vulnx_unapproved_cve_ids")
        if self.api_url != PUBLIC_API and policy.profile != "isolated-lab":
            raise PolicyDenied("vulnx_fixture_requires_isolated_lab")
        return tuple(ids)

    def service_policy(self, policy: EngagementPolicy) -> EngagementPolicy:
        return replace(
            policy,
            allowed_origins=(self.api_url,),
            allowed_ips=self.api_ips,
            allowed_replay_urls=(),
            allowed_refresh_urls=(),
            actor_ids=("anonymous",),
        )


def vulnx_argv(config: VulnXConfig, cve_id: str, proxy: str) -> list[str]:
    if cve_id not in config.cve_ids:
        raise ValueError("vulnx_unapproved_cve_id")
    return [
        str(config.binary.path),
        "--disable-update-check",
        "--silent",
        "--no-color",
        "--json",
        "--timeout",
        str(config.request_timeout) + "s",
        "--proxy",
        proxy,
        "id",
        cve_id,
    ]


class IntelligenceCache:
    """Small persistent TTL cache. Expiry/eviction never removes evidence."""

    def __init__(self, store: AssessmentStore, engagement: str) -> None:
        self.store, self.engagement = store, engagement
        with store.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS rj_intelligence_cache(engagement TEXT NOT NULL, "
                "cache_key TEXT NOT NULL, payload TEXT NOT NULL, expires REAL NOT NULL, "
                "accessed REAL NOT NULL, PRIMARY KEY(engagement,cache_key))"
            )
            db.execute(
                "CREATE INDEX IF NOT EXISTS rj_intelligence_expiry "
                "ON rj_intelligence_cache(engagement,expires)"
            )

    def get(self, key: str) -> dict[str, Any] | None:
        with self.store.transaction() as db:
            row = db.execute(
                "SELECT payload FROM rj_intelligence_cache "
                "WHERE engagement=? AND cache_key=? AND expires>?",
                (self.engagement, key, time.time()),
            ).fetchone()
            if row is None:
                return None
            db.execute(
                "UPDATE rj_intelligence_cache SET accessed=? WHERE engagement=? AND cache_key=?",
                (time.time(), self.engagement, key),
            )
            value = json.loads(row[0])
        return value if isinstance(value, dict) else None

    def put(self, key: str, record: dict[str, Any], ttl: int) -> None:
        payload, now = json_text(record), time.time()
        if len(payload.encode()) > 8192:
            raise ValueError("intelligence_cache_record_limit")
        with self.store.transaction() as db:
            db.execute(
                "DELETE FROM rj_intelligence_cache WHERE engagement=? AND expires<=?",
                (self.engagement, now),
            )
            db.execute(
                "INSERT OR REPLACE INTO rj_intelligence_cache VALUES(?,?,?,?,?)",
                (self.engagement, key, payload, min(now, record.get("fetched_at", now)) + ttl, now),
            )
            db.execute(
                "DELETE FROM rj_intelligence_cache WHERE engagement=? AND cache_key IN "
                "(SELECT cache_key FROM rj_intelligence_cache WHERE engagement=? "
                "ORDER BY accessed DESC,cache_key LIMIT -1 OFFSET 128)",
                (self.engagement, self.engagement),
            )


class VulnXIntelligenceAdapter:
    resource_class = "scanner"

    def __init__(
        self,
        config: VulnXConfig,
        policy: EngagementPolicy,
        store: AssessmentStore,
        rate_limits: HTTPRateLimits,
        *,
        tls_config: BrowserTLSConfig | None = None,
    ) -> None:
        self.config, self.policy, self.store = config, policy, store
        self.rate_limits = rate_limits
        # Target/lab trust must not authorize a certificate for the public
        # intelligence provider. The real API uses the system roots; only an
        # explicitly isolated protocol fixture inherits the lab CA.
        self.tls_config = None if config.api_url == PUBLIC_API else tls_config
        self.runner = PinnedToolRunner("vulnx", config.binary, store.path.parent / "vulnx-workers")
        self.cache = IntelligenceCache(store, policy.engagement_id)
        self.partial_evidence_refs: tuple[str, ...] = ()

    def _api_key(self) -> str | None:
        path = self.config.api_key_file
        if path is None:
            return None
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(descriptor, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (
                    not stat.S_ISREG(info.st_mode)
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_uid != os.getuid()
                    or info.st_nlink != 1
                    or info.st_size > 4096
                ):
                    raise ValueError("vulnx_private_api_key_file_required")
                data = json.loads(stream.read(4097))
            if (
                not isinstance(data, dict)
                or set(data) != {"api_key"}
                or not isinstance(data["api_key"], str)
                or re.fullmatch(r"[A-Za-z0-9._~-]{8,512}", data["api_key"]) is None
            ):
                raise ValueError("vulnx_invalid_api_key_file")
            return str(data["api_key"])
        except OSError as exc:
            raise ValueError("vulnx_api_key_file_unavailable") from exc

    def _key(self, cve: str) -> str:
        return stable_key(
            [
                "redjohn-vulnx-adapter-v1",
                self.config.api_url,
                self.config.binary.sha256,
                cve,
                self.config.ttl_seconds,
            ]
        )

    def normalize(self, cve: str, raw: dict[str, Any], status: int | None) -> dict[str, Any]:
        if (
            raw.get("error")
            or raw.get("truncated")
            or raw.get("timed_out")
            or raw.get("exit_code") != 0
            or status != 200
        ):
            raise ValueError("vulnx_provider_response_incomplete")
        value = json.loads(raw.get("stdout", ""))
        if not isinstance(value, dict) or value.get("cve_id") != cve:
            raise ValueError("vulnx_output_schema_error")
        # Unknown ranges remain unknown. Do not invent affected versions from
        # product names, free-form prose, CVE severity or a matching technology.
        product = value.get("product", "unspecified")
        if (
            not isinstance(product, str)
            or re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._ -]{0,127}", product) is None
        ):
            product = "unspecified"
        updated = value.get("cve_updated_at") or value.get("updated_at")
        if updated is not None and (not isinstance(updated, str) or len(updated) > 128):
            raise ValueError("vulnx_output_schema_error")
        digest = hashlib.sha256(raw["stdout"].encode()).hexdigest()
        advisory = AdvisoryRecord(
            cve,
            product,
            self.config.api_url + "/v2/vulnerability/" + cve,
            time.time(),
            updated or "unversioned-content:" + digest,
            ttl_seconds=self.config.ttl_seconds,
        )
        # Only bounded metadata is retained: upstream PoC/template bodies are
        # neither adopted as licensed code nor executed by this adapter.
        return {
            **asdict(advisory),
            "provider": "VulnX",
            "tool_version": self.config.version,
            "applicability": "unknown",
            "applicability_reason": "asset_version_and_structured_affected_ranges_not_validated",
            "record_sha256": digest,
            "provider_timestamp": updated,
            "data_origin": "public_provider"
            if self.config.api_url == PUBLIC_API
            else "controlled_protocol_fixture",
            "severity": value.get("severity")
            if value.get("severity") in {"critical", "high", "medium", "low", "info"}
            else "unknown",
            "is_kev": value.get("is_kev") is True,
            "dynamic_finding": False,
        }

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:  # noqa: PLR0911, PLR0912, PLR0915 - one provider lifecycle and durable evidence boundary
        self.partial_evidence_refs = ()
        try:
            ids = self.config.validate_input(self.policy, surface, spec)
            api_key = self._api_key()
        except PolicyDenied:
            raise
        except ValueError as exc:
            return AdapterResult(
                "failed", "blocked", error=error_record(str(exc), coverage_effect="blocked")
            )
        if not self.config.binary.path.is_file():
            return AdapterResult(
                "failed",
                "blocked",
                error=error_record("vulnx_binary_missing", coverage_effect="blocked"),
            )
        records = {
            cve: record
            for cve in ids
            if not spec.retest_revision and (record := self.cache.get(self._key(cve))) is not None
        }
        cache_hits, responses, raw_errors = len(records), {}, []
        pending = [cve for cve in ids if cve not in records]
        if not pending:
            return AdapterResult(
                "succeeded",
                "completed",
                {
                    "requests": 0,
                    "model_calls": 0,
                    "cache_hits": cache_hits,
                    "advisories": list(records.values()),
                    "evidence_refs": list(
                        dict.fromkeys(row["evidence_ref"] for row in records.values())
                    ),
                    "outcome": "intelligence_available_from_fresh_persistent_cache",
                    "dynamic_findings": 0,
                },
            )
        expected = {self.config.api_url + "/v2/vulnerability/" + cve for cve in pending}
        seen: set[str] = set()
        failure: list[str] = []

        def admit(url: str) -> None:
            if url not in expected or url in seen:
                failure[:] = failure or ["vulnx_unapproved_or_duplicate_request"]
                raise PolicyDenied(failure[0])
            if not self.rate_limits.admit(origin_for(url)):
                failure[:] = failure or ["rate_limited"]
                raise CapacityExceeded(failure[0])
            try:
                self.store.consume_requests(self.policy)
            except CapacityExceeded:
                failure[:] = failure or ["request_budget_exceeded"]
                raise
            seen.add(url)

        def headers(url: str, _method: str, fields: list[tuple[str, str]]) -> list[tuple[str, str]]:
            if url not in expected:
                raise PolicyDenied("vulnx_provider_path_denied")
            fields = [
                (name, value)
                for name, value in fields
                if name.lower() not in {"x-api-key", "accept-encoding"}
            ]
            return (
                fields
                + [("Accept-Encoding", "identity")]
                + ([("X-Api-Key", api_key)] if api_key else [])
            )

        def rewrite(url: str, method: str) -> str:
            # Go's macOS platform verifier does not use this ephemeral CA.
            # Only the bounded CVE path crosses the local gateway; the host
            # verifies provider TLS. Linux workers use the attested relay.
            parsed = urlsplit(url)
            canonical = self.config.api_url + parsed.path
            if (
                method != "GET"
                or origin_for(url) != origin_for(proxy.url)
                or parsed.query
                or parsed.fragment
                or canonical not in expected
            ):
                raise PolicyDenied("vulnx_gateway_path_denied")
            return canonical

        def observe(url: str, status: int, fields: dict[str, str]) -> None:
            self.rate_limits.observe(origin_for(url), status, fields)
            if status in {401, 403, 429, 503}:
                failure[:] = failure or [
                    "rate_limited"
                    if status == 429
                    else "vulnx_provider_auth_or_service_unavailable"
                ]

        def complete(url: str, _method: str, status: int, _fields: dict[str, str]) -> None:
            responses[url] = status

        def response_policy(_url: str, _status: int, fields: tuple[tuple[str, str], ...]) -> None:
            if any(
                name == "content-encoding" and value.lower() != "identity" for name, value in fields
            ):
                failure[:] = failure or ["vulnx_encoded_response_unsupported"]
                raise ValueError(failure[0])

        proxy = BrowserEgressProxy(
            self.config.service_policy(self.policy),
            max_connections=2,
            max_wire_bytes=1024 * 1024,
            timeout_seconds=self.config.request_timeout,
            request_admission=admit,
            request_headers=headers,
            rewrite_url=rewrite,
            on_response=observe,
            on_complete=complete,
            response_policy=response_policy,
            tls_config=self.tls_config,
        )
        started, health = time.monotonic(), {}
        try:
            await proxy.start()
            await self.runner.prepare(proxy.policy, proxy)
            try:
                health = await self.runner.healthcheck()
            except ValueError as exc:
                return AdapterResult(
                    "failed", "blocked", error=error_record(str(exc), coverage_effect="blocked")
                )
            for cve in pending:
                raw = await self.runner.execute(
                    vulnx_argv(self.config, cve, proxy.url),
                    spec.timeout_seconds,
                    api_url=proxy.url,
                )
                try:
                    records[cve] = self.normalize(
                        cve, raw, responses.get(self.config.api_url + "/v2/vulnerability/" + cve)
                    )
                except (ValueError, TypeError):
                    failure[:] = failure or [
                        "vulnx_timeout"
                        if raw.get("timed_out")
                        else "vulnx_output_truncated"
                        if raw.get("truncated")
                        else "vulnx_provider_or_schema_error"
                    ]
                    raw_errors.append(
                        {
                            "cve_id": cve,
                            "exit_code": raw.get("exit_code"),
                            "truncated": raw.get("truncated"),
                            "timed_out": raw.get("timed_out"),
                        }
                    )
                if failure:
                    break
            await proxy.close()
            code = failure[0] if failure else ""
            if proxy.upstream_tls_failures:
                code = "vulnx_upstream_tls_verification_failed"
            elif (
                proxy.denied_requests or proxy.limit_drops or len(records) != len(ids)
            ) and not code:
                code = "vulnx_provider_response_incomplete"
            ref = self.store.evidence_put(
                self.policy.engagement_id,
                {
                    "tool": "vulnx",
                    **health,
                    "provider": self.config.api_url,
                    "requested_public_cve_ids": pending,
                    "complete_provider_cve_ids": [
                        cve
                        for cve in pending
                        if self.config.api_url + "/v2/vulnerability/" + cve in responses
                    ],
                    "admitted_requests": len(seen),
                    "forwarded_requests": proxy.forwarded_requests,
                    "advisories": [records[cve] for cve in pending if cve in records],
                    "responses": responses,
                    "worker_errors": raw_errors,
                    "error_code": code or None,
                    "egress_attestations": list(self.runner.boundary.attestations)
                    if self.runner.boundary
                    else [],
                    "duration_seconds": time.monotonic() - started,
                    "tls_validation": "failed"
                    if proxy.upstream_tls_failures
                    else "host_proxy_verified"
                    if proxy.forwarded_requests
                    else "not_observed",
                    "upstream_tls_failures": proxy.upstream_tls_failures,
                    "worker_transport": "loopback_gateway_only",
                    "provider_tls_roots": "explicit_lab_ca"
                    if self.tls_config is not None and self.tls_config.upstream_ca_file is not None
                    else "system",
                    "private_asset_uploaded": False,
                    "finding_claim": "none_intelligence_only",
                },
                job_id=job["id"],
                kind="vulnx_intelligence",
            )
            for cve in pending:
                if cve in records:
                    records[cve]["evidence_ref"] = ref
                    self.cache.put(self._key(cve), records[cve], self.config.ttl_seconds)
            summary = {
                "requests": proxy.forwarded_requests,
                "model_calls": 0,
                "cache_hits": cache_hits,
                "advisories": list(records.values()),
                "evidence_refs": [ref],
                "dynamic_findings": 0,
                "duration_seconds": time.monotonic() - started,
                "outcome": "intelligence_available" if not code else "intelligence_incomplete",
            }
            if code:
                coverage: CoverageStatus = (
                    "blocked"
                    if code
                    in {
                        "rate_limited",
                        "request_budget_exceeded",
                        "vulnx_provider_auth_or_service_unavailable",
                    }
                    else "inconclusive"
                )
                error = error_record(code, coverage_effect=coverage)
                error["partial_evidence_refs"] = [ref]
                return AdapterResult("failed", coverage, summary, error=error)
            return AdapterResult("succeeded", "completed", summary)
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
                    "tool": "vulnx",
                    "interrupted": True,
                    "forwarded_requests": proxy.forwarded_requests,
                    "responses": responses,
                    "advisories": list(records.values()),
                    "finding_claim": "none_intelligence_only",
                },
                job_id=job["id"],
                kind="vulnx_interrupted",
            )
            self.partial_evidence_refs = (ref,)
            raise
        finally:
            await asyncio.shield(self.cleanup())
            await proxy.close()

    async def healthcheck(self) -> dict[str, str]:
        return await self.runner.healthcheck()

    async def cancel(self) -> None:
        await self.runner.cancel()

    async def cleanup(self) -> None:
        await self.runner.cleanup()
