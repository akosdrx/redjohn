"""Selected, bounded Arjun/sqlmap/Dalfox jobs on observed GET inputs.

The worker sees an HTTP alias and no credentials. The host maps that alias to
one reviewed endpoint, validates each mutation, resolves/pins IPs and verifies
upstream TLS. POST/body mutation is explicitly unsupported by these adapters;
existing captured POST replay continues through the Nuclei integration.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, quote, unquote_plus, urlsplit

from redjohn.assessment.auth_replay import AuthReplayBinding, AuthReplayDenied, AuthReplayVault
from redjohn.assessment.browser_proxy import BrowserEgressProxy
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
from redjohn.assessment.python_tools import PinnedPythonToolRunner
from redjohn.assessment.session_recovery import auth_recovery_marker
from redjohn.assessment.store import CapacityExceeded


if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

    from redjohn.assessment.browser_tls import BrowserTLSConfig
    from redjohn.assessment.contracts import HTTPRateLimits
    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


CAPABILITIES = {
    "arjun": "arjun_parameters",
    "sqlmap": "sqlmap_validate",
    "dalfox": "dalfox_validate",
}
PARAMETER = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


@dataclass(frozen=True)
class SpecialistConfig:
    tool: str
    binary: BinaryPin
    parameters: tuple[str, ...] = ()
    dbms: str = "SQLite"
    rate_limit: int = 10
    request_timeout: int = 3
    max_requests: int = 96

    @classmethod
    def from_mapping(cls, tool: str, value: dict[str, Any]) -> SpecialistConfig:
        allowed = {"binary", "rate_limit", "request_timeout", "max_requests"}
        allowed |= {"parameters"} if tool == "arjun" else {"dbms"} if tool == "sqlmap" else set()
        if tool not in CAPABILITIES or not isinstance(value, dict) or set(value) - allowed:
            raise ValueError("invalid_specialist_configuration")
        words = value.get("parameters", [])
        if (
            not isinstance(words, list)
            or len(words) > 16
            or len(set(map(str, words))) != len(words)
            or any(not isinstance(x, str) or not PARAMETER.fullmatch(x) for x in words)
            or (tool == "arjun" and len(words) < 2)
        ):
            raise ValueError("invalid_approved_parameter_names")
        result = cls(
            tool,
            BinaryPin.from_mapping(tool, value.get("binary")),
            tuple(words),
            value.get("dbms", "SQLite"),
            value.get("rate_limit", 10),
            value.get("request_timeout", 3),
            value.get("max_requests", 96),
        )
        if (
            not isinstance(result.dbms, str)
            or result.dbms not in {"SQLite", "PostgreSQL", "MySQL", "Microsoft SQL Server"}
            or type(result.rate_limit) is not int
            or not 1 <= result.rate_limit <= 10
            or type(result.request_timeout) is not int
            or not 1 <= result.request_timeout <= 10
            or type(result.max_requests) is not int
            or not 8 <= result.max_requests <= 128
        ):
            raise ValueError("invalid_specialist_limits")
        return result

    @property
    def version(self) -> str:
        return self.binary.version

    @property
    def revision(self) -> str:
        return stable_key(
            [
                "redjohn-specialists-v1",
                self.tool,
                self.binary.sha256,
                self.parameters,
                self.dbms,
                self.max_requests,
            ]
        )

    def validate_input(self, policy: EngagementPolicy, surface: Surface, spec: JobSpec) -> None:
        policy.check_readonly_request(surface.url, surface.method)
        policy.check_actor(surface.actor_id)
        parsed = urlsplit(surface.url)
        if (
            surface.method != "GET"
            or surface.content_type
            or surface.body_sha256
            or parsed.fragment
            or not parsed.path.startswith("/")
            or surface.source != "observed"
            or not surface.request_ref
            or surface.url.endswith("?")
            or spec.tool_version != self.version
            or spec.template_version != self.revision
        ):
            raise ValueError("specialist_requires_observed_supported_get_and_current_revision")
        if self.tool == "arjun":
            if parsed.query or surface.actor_id != "anonymous" or spec.options:
                raise ValueError("arjun_requires_anonymous_endpoint_without_query")
        else:
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            if (
                surface.input_location != "query"
                or not PARAMETER.fullmatch(surface.input_name)
                or sum(name == surface.input_name for name, _ in pairs) != 1
                or set(spec.options) != {"hint_ref"}
                or not isinstance(spec.options["hint_ref"], str)
                or not re.fullmatch(r"[a-f0-9]{32}", spec.options["hint_ref"])
            ):
                raise ValueError("specialist_requires_single_selected_query_input_and_hint")
            if self.tool == "dalfox" and surface.actor_id != "anonymous":
                raise ValueError("dalfox_authenticated_browser_confirmation_unsupported")


def captured_request(
    store: AssessmentStore,
    policy: EngagementPolicy,
    surface: Surface,
    *,
    current_session: bool = True,
) -> None:
    value = store.evidence_get(policy.engagement_id, surface.request_ref)
    data = json.loads(value["excerpt"])
    if (
        value["truncated"]
        or not isinstance(data, dict)
        or any(
            data.get(k) != getattr(surface, k)
            for k in ("url", "method", "actor_id", "tenant_id", "session_revision")
        )
        or data.get("sent") is not True
        or type(data.get("status")) is not int
        or data.get("engagement_id") != policy.engagement_id
        or data.get("policy_revision") != policy.revision
    ):
        raise ValueError("specialist_completed_browser_capture_required")
    if surface.actor_id != "anonymous" and current_session:
        store.assert_session_revision(policy, surface)


def query_mutation_allowed(original: str, mutated: str, parameter: str) -> bool:
    """Only the selected value may change. Other encoded pairs/order stay exact."""
    old, new = urlsplit(original), urlsplit(mutated)
    if origin_for(original) != origin_for(mutated) or old.path != new.path or new.fragment:
        return False
    before, after = old.query.split("&"), new.query.split("&")
    if len(before) != len(after):
        return False
    seen = 0
    for a, b in zip(before, after, strict=True):
        if unquote_plus(a.partition("=")[0]) == parameter:
            seen += 1
            if a.partition("=")[0] != b.partition("=")[0] or "=" not in b:
                return False
        elif a != b:
            return False
    return seen == 1


def replace_query_value(url: str, parameter: str, value: str) -> str:
    prefix, _, query = url.partition("?")
    return (
        prefix
        + "?"
        + "&".join(
            key + "=" + quote(value, safe="") if unquote_plus(key) == parameter else item
            for item in query.split("&")
            for key in [item.partition("=")[0]]
        )
    )


class SpecialistAdapter:
    resource_class = "scanner"

    def __init__(
        self,
        config: SpecialistConfig,
        policy: EngagementPolicy,
        store: AssessmentStore,
        rate_limits: HTTPRateLimits,
        *,
        tls_config: BrowserTLSConfig | None = None,
        auth_vault_file: str | Path | None = None,
        session_recovery_enabled: bool = False,
    ) -> None:
        self.config, self.policy, self.store, self.rate_limits = config, policy, store, rate_limits
        self.tls_config, self.auth_vault_file = tls_config, auth_vault_file
        self.session_recovery_enabled = session_recovery_enabled
        runner_class = (
            PinnedToolRunner if config.tool in {"dalfox", "tinja"} else PinnedPythonToolRunner
        )
        self.runner = runner_class(
            config.tool, config.binary, store.path.parent / (config.tool + "-workers")
        )
        self.partial_evidence_refs: tuple[str, ...] = ()
        if config.tool == "dalfox":
            ensure_followups(store)

    async def run(self, job: dict[str, Any], surface: Surface, spec: JobSpec) -> AdapterResult:  # noqa: PLR0912, PLR0915
        self.partial_evidence_refs = ()
        config, tool, policy = self.config, self.config.tool, self.policy
        binding = None
        try:
            config.validate_input(policy, surface, spec)
            self.validate_capture(surface)
            if tool != "arjun":
                hint = self.store.evidence_get(policy.engagement_id, spec.options["hint_ref"])
                signal = json.loads(hint["excerpt"])
                if (
                    hint["truncated"]
                    or not isinstance(signal, dict)
                    or signal.get("signal")
                    != {
                        "sqlmap": "sqli",
                        "dalfox": "xss",
                        "tinja": "ssti",
                        "schemathesis": "schema",
                    }[tool]
                    or signal.get("request_ref") != surface.request_ref
                    or signal.get("input_name") != surface.input_name
                ):
                    raise ValueError("specialist_hint_capture_mismatch")  # noqa: TRY301 - explicit schema gate
            if surface.actor_id != "anonymous":
                if self.auth_vault_file is None:
                    raise AuthReplayDenied("auth_replay_credentials_missing")
                binding = AuthReplayVault.from_file_for_surface(
                    self.auth_vault_file, policy, surface
                ).authorize(surface)
            worker_surface = self.worker_surface(surface)
            transform = self.request_transform(surface, binding)
        except PolicyDenied as exc:
            return AdapterResult(
                "failed", "blocked", error=error_record(str(exc), coverage_effect="blocked")
            )
        except (ValueError, KeyError) as exc:
            code = (
                str(exc)
                if isinstance(exc, AuthReplayDenied)
                else "specialist_unsupported_input_or_capture"
            )
            coverage: CoverageStatus = (
                "blocked" if isinstance(exc, AuthReplayDenied) else "unsupported"
            )
            return AdapterResult(
                "failed",
                coverage,
                {"auth_recovery": auth_recovery_marker(surface, "credential_expired")}
                if self.session_recovery_enabled and code == "auth_replay_expired"
                else {},
                error=error_record(code, coverage_effect=coverage),
            )
        admitted, responses = 0, 0
        binding_denials = 0
        failure: list[str] = []
        stop = asyncio.Event()

        def fail(code: str) -> None:
            if not failure:
                failure.append(code)
            stop.set()

        observed_values: set[str] = set()
        nonce = "redjohn-" + spec.key[:16]
        payload = '<svg/onload=alert("' + nonce + '")>'
        proof_url = (
            replace_query_value(surface.url, surface.input_name, payload)
            if tool == "dalfox"
            else ""
        )
        proxy: BrowserEgressProxy

        def rewrite(url: str, method: str) -> str:
            nonlocal admitted
            incoming, base = urlsplit(url), urlsplit(worker_surface.url)
            alias_origin = proxy.url
            allowed_method = method == "GET" or (tool == "dalfox" and method == "HEAD")
            if (
                not allowed_method
                or origin_for(url) != origin_for(alias_origin)
                or incoming.fragment
            ):
                fail("specialist_worker_request_outside_selected_input")
                raise PolicyDenied(failure[0])
            canonical = (
                origin_for(surface.url) + url[len(incoming.scheme) + 3 + len(incoming.netloc) :]
            )
            valid = incoming.path == base.path
            if tool == "arjun":
                pairs = parse_qsl(incoming.query, keep_blank_values=True)
                valid &= (
                    len(pairs) <= 16
                    and len({key for key, _ in pairs}) == len(pairs)
                    and all(
                        (key in config.parameters or re.fullmatch(r"z[a-zA-Z0-9]{5}", key))
                        and re.fullmatch(r"[a-zA-Z0-9]{1,32}", value)
                        for key, value in pairs
                    )
                )
            else:
                valid &= self.mutation_allowed(surface, canonical)
                if method == "HEAD":
                    valid &= incoming.query == base.query
            if not valid:
                fail("specialist_request_rewrite_or_unapproved_parameter")
                raise PolicyDenied(failure[0])
            return canonical

        def admit(url: str) -> None:
            nonlocal admitted, binding_denials
            if failure and failure[0] in {"authentication_expired", "auth_replay_expired"}:
                # A native scanner can enqueue another request before its stop
                # task runs. Fence admission synchronously after verified auth
                # failure, before spending budget or opening another socket.
                binding_denials += 1
                raise PolicyDenied(failure[0])
            if admitted >= config.max_requests:
                fail("specialist_request_budget_exhausted")
                raise CapacityExceeded(failure[0])
            if binding is not None:
                try:
                    binding.validate(surface.url, surface.method, policy)
                except AuthReplayDenied as exc:
                    if tool in {"tinja", "schemathesis"}:
                        binding_denials += 1
                        fail(str(exc))
                    raise
                self.store.assert_session_revision(policy, surface)
            if not self.rate_limits.admit(origin_for(url)):
                fail("shared_origin_cooldown")
                raise CapacityExceeded(failure[0])
            self.store.consume_requests(policy)
            admitted += 1
            if tool != "arjun" and surface.method == "GET" and len(observed_values) < 128:
                observed_values.add(
                    next(
                        v
                        for k, v in parse_qsl(urlsplit(url).query, keep_blank_values=True)
                        if k == surface.input_name
                    )
                )

        def complete(url: str, _method: str, status: int, headers: dict[str, str]) -> None:
            nonlocal responses
            responses += 1
            self.rate_limits.observe(origin_for(url), status, headers)
            if (
                status == 401
                and surface.actor_id != "anonymous"
                and tool in {"tinja", "schemathesis"}
            ):
                fail("authentication_expired")
            elif status in {401, 403, 429, 503} or 300 <= status < 400:
                fail("specialist_auth_challenge_rate_limit_or_redirect")

        def headers(_url: str, method: str, fields: list[tuple[str, str]]) -> list[tuple[str, str]]:
            nonlocal binding_denials
            clean = [
                (k, v)
                for k, v in fields
                if k.lower()
                not in {
                    "authorization",
                    "cookie",
                    "x-api-key",
                    "x-auth-token",
                    "x-csrf-token",
                    "x-xsrf-token",
                    "accept-encoding",
                }
            ]
            clean.append(("Accept-Encoding", "identity"))
            try:
                return binding.rewrite_headers(surface.url, method, clean) if binding else clean
            except AuthReplayDenied as exc:
                if tool in {"tinja", "schemathesis"}:
                    binding_denials += 1
                    fail(str(exc))
                raise

        def response_policy(_url: str, _status: int, fields: tuple[tuple[str, str], ...]) -> None:
            if any(
                name == "content-encoding" and value.lower() != "identity" for name, value in fields
            ):
                fail("specialist_encoded_response_unsupported")
                raise ValueError(failure[0])

        def deny_connect(_origin: str) -> None:
            fail("specialist_direct_connect_outside_alias")
            raise PolicyDenied(failure[0])

        proxy = BrowserEgressProxy(
            policy,
            max_connections=2,
            max_wire_bytes=64 * 1024,
            timeout_seconds=config.request_timeout,
            rewrite_url=rewrite,
            connect_policy=deny_connect,
            request_admission=admit,
            on_complete=complete,
            response_policy=response_policy,
            request_headers=headers,
            request_transform=transform,
            tls_config=self.tls_config,
        )
        started = time.monotonic()
        start_ref = self.store.evidence_put(
            policy.engagement_id,
            {
                "tool": tool,
                "request_ref": surface.request_ref,
                "tool_version": config.version,
                "configuration_revision": config.revision,
                "stage": "prepared_not_sent",
            },
            job_id=job["id"],
            kind="specialist_attempt",
        )
        self.partial_evidence_refs = (start_ref,)
        try:
            await proxy.start()
            if isinstance(self.runner, PinnedPythonToolRunner):
                self.runner.proxy_url = proxy.url
            await self.runner.prepare(policy, proxy)
            health = await self.runner.healthcheck()
            workspace = self.runner.workspace
            assert workspace is not None
            alias = (
                proxy.url
                + worker_surface.url[
                    len(urlsplit(worker_surface.url).scheme)
                    + 3
                    + len(urlsplit(worker_surface.url).netloc) :
                ]
            )
            argv = self.argv(alias, proxy.url, surface, workspace, payload)
            raw = await self._execute_guarded(argv, spec.timeout_seconds, stop)
            await proxy.close()
            try:
                output = self.read_output(raw, workspace, alias, worker_surface.input_name, payload)
            except (ValueError, TypeError, OSError):
                output = None
            summary: dict[str, Any] = {
                "tool": tool,
                **health,
                "configuration_revision": config.revision,
                "request_ref": surface.request_ref,
                "requests": admitted,
                "complete_responses": responses,
                "distinct_selected_values": len(observed_values)
                if surface.method == "GET"
                else None,
                "elapsed_seconds": time.monotonic() - started,
                "model_calls": 0,
                "input_tokens": 0,
                "output_tokens": 0,
                "stdout_sha256": hashlib.sha256(raw["stdout"].encode()).hexdigest()
                if "stdout" in raw
                else None,
                "stderr_sha256": hashlib.sha256(raw["stderr"].encode()).hexdigest()
                if "stderr" in raw
                else None,
                "stdout_bytes": raw.get("stdout_bytes"),
                "stderr_bytes": raw.get("stderr_bytes"),
                "streams_available": not raw.get("policy_stopped", False),
                "egress_attestations": list(self.runner.boundary.attestations)
                if self.runner.boundary
                else [],
                "upstream_tls_failures": proxy.upstream_tls_failures,
                "upstream_tls": "host_proxy_verified"
                if surface.url.startswith("https:") and responses
                else "not_applicable_local_http"
                if not surface.url.startswith("https:")
                else "not_observed",
                "request_method": surface.method,
                "auth_replay": binding.metadata() if binding else None,
                "input_transport": "host_private_body_bridge" if transform else "query",
                "unsupported": self.unsupported_profiles(),
            }
            code = (
                failure[0]
                if failure
                else "specialist_worker_timeout"
                if raw.get("timed_out")
                else "specialist_output_truncated"
                if raw.get("truncated")
                else "specialist_upstream_tls_failed"
                if proxy.upstream_tls_failures
                else "specialist_proxy_request_denied"
                if proxy.denied_requests or proxy.limit_drops or proxy.admission_denials
                else "specialist_worker_failed"
                if raw.get("error")
                or (
                    raw.get("exit_code") != 0
                    and not (
                        tool in {"dalfox", "schemathesis"}
                        and raw.get("exit_code") == 1
                        and output
                        and output.get("candidate")
                    )
                )
                else "specialist_incomplete_network_execution"
                if responses != admitted or responses < self.minimum_responses()
                else "specialist_output_schema_error"
                if output is None
                else ""
            )
            ref = self.store.evidence_put(
                policy.engagement_id,
                {**summary, "error_code": code},
                job_id=job["id"],
                kind="specialist_execution",
            )
            self.partial_evidence_refs += (ref,)
            summary["evidence_refs"] = list(self.partial_evidence_refs)
            if code:
                auth_failed = (
                    code in {"authentication_expired", "auth_replay_expired"}
                    and responses == admitted
                    and (responses > 0 or code == "auth_replay_expired")
                    and proxy.denied_requests <= binding_denials
                    and proxy.admission_denials <= binding_denials
                    and not (proxy.upstream_tls_failures or proxy.limit_drops)
                )
                if auth_failed and self.session_recovery_enabled:
                    summary["auth_recovery"] = auth_recovery_marker(
                        surface,
                        "http_401" if code == "authentication_expired" else "credential_expired",
                    )
                error = error_record(
                    code,
                    category="auth" if auth_failed else "execution",
                    coverage_effect="blocked" if auth_failed else "inconclusive",
                )
                error["partial_evidence_refs"] = list(self.partial_evidence_refs)
                return AdapterResult(
                    "timed_out" if raw.get("timed_out") else "failed",
                    "blocked" if auth_failed else "inconclusive",
                    summary,
                    error=error,
                )
            assert output is not None
            summary["scanner_verdict"] = output
            findings: tuple[dict[str, Any], ...] = ()
            if tool == "arjun":
                ids = [
                    self.store.upsert_surface(
                        policy.engagement_id,
                        replace(
                            surface,
                            url=surface.url + "?" + quote(name) + "=1",
                            input_location="query",
                            input_name=name,
                            source="inferred",
                            request_ref="",
                        ),
                    )
                    for name in output["parameters"]
                ]
                summary.update(
                    parameters=output["parameters"],
                    surface_ids=ids,
                    outcome="parameter_candidates" if ids else "no_parameter_observed",
                )
            else:
                candidate = output["candidate"]
                summary["outcome"] = "candidate" if candidate else "no_finding_observed"
                if candidate:
                    findings = (
                        {
                            "id": stable_key([spec.key, tool]),
                            "finding_status": "candidate",
                            "family": spec.family,
                            "cwe": {
                                "sqlmap": "CWE-89",
                                "dalfox": "CWE-79",
                                "tinja": "CWE-1336",
                                "schemathesis": "CWE-20",
                            }[tool],
                            "surface_id": spec.surface_id,
                            "evidence_refs": [ref],
                            "validation": "scanner_signal_requires_independent_confirmation",
                        },
                    )
                if tool == "dalfox" and candidate:
                    if not any(nonce in value for value in observed_values):
                        return AdapterResult(
                            "failed",
                            "inconclusive",
                            summary,
                            error=error_record("dalfox_payload_not_sent"),
                        )
                    candidate_ref = self.store.evidence_put(
                        policy.engagement_id,
                        {
                            "tool": "dalfox",
                            "version": config.version,
                            "url": proof_url,
                            "nonce": nonce,
                            "surface_id": spec.surface_id,
                            "request_ref": surface.request_ref,
                            "parent_job": job["id"],
                            "scanner_evidence": ref,
                        },
                        job_id=job["id"],
                        kind="dalfox_confirmation_plan",
                    )
                    with self.store.transaction() as db:
                        db.execute(
                            "INSERT OR IGNORE INTO rj_specialist_followup VALUES(?,?,?,?,0)",
                            (job["id"], policy.engagement_id, spec.surface_id, candidate_ref),
                        )
                    summary["confirmation_candidate_ref"] = candidate_ref
            return AdapterResult("succeeded", "completed", summary, findings)
        except (ValueError, OSError):
            # No raw tool log, URL, token, source path or arbitrary exception text.
            return AdapterResult(
                "failed",
                "blocked",
                {"evidence_refs": list(self.partial_evidence_refs)},
                error=error_record(
                    "specialist_install_or_version_invalid", coverage_effect="blocked"
                ),
            )
        finally:
            await asyncio.shield(self.runner.cleanup())
            await proxy.close()

    def mutation_allowed(self, surface: Surface, canonical: str) -> bool:
        return query_mutation_allowed(surface.url, canonical, surface.input_name)

    def worker_surface(self, surface: Surface) -> Surface:
        return surface

    def request_transform(
        self, _surface: Surface, _binding: AuthReplayBinding | None
    ) -> (
        Callable[
            [str, str, list[tuple[str, str]], bytes], tuple[str, str, list[tuple[str, str]], bytes]
        ]
        | None
    ):
        return None

    def unsupported_profiles(self) -> list[str]:
        return ["POST_body_mutation", "duplicate_selected_parameter"]

    def validate_capture(self, surface: Surface) -> None:
        captured_request(self.store, self.policy, surface)

    def minimum_responses(self) -> int:
        return 3

    def argv(
        self, alias: str, proxy: str, surface: Surface, workspace: Path, payload: str
    ) -> list[str]:
        c = self.config
        if c.tool == "arjun":
            words = workspace / "approved-parameters.txt"
            words.write_text("\n".join(c.parameters) + "\n")
            return [
                str(c.binary.path),
                "-u",
                alias,
                "-m",
                "GET",
                "-w",
                str(words),
                "-t",
                "1",
                "-c",
                "2",
                "-T",
                str(c.request_timeout),
                "-d",
                str(1 / c.rate_limit),
                "--rate-limit",
                str(c.rate_limit),
                "--disable-redirects",
                "-oJ",
                str(workspace / "arjun.json"),
            ]
        if c.tool == "sqlmap":
            request = workspace / "captured-request.txt"
            parsed = urlsplit(alias)
            request.write_text(
                f"GET {parsed.path}?{parsed.query} HTTP/1.1\n"
                f"Host: {parsed.netloc}\nAccept-Encoding: identity\n\n"
            )
            return [
                str(c.binary.path),
                "-r",
                str(request),
                "-p",
                surface.input_name,
                "--batch",
                "--proxy",
                proxy,
                "--disable-precon",
                "--timeout",
                str(c.request_timeout),
                "--retries",
                "0",
                "--delay",
                str(1 / c.rate_limit),
                "--threads",
                "1",
                "--level",
                "1",
                "--risk",
                "1",
                "--technique",
                "B",
                "--dbms",
                c.dbms,
                "--skip-waf",
                "--skip-heuristics",
                "--disable-coloring",
                "--test-filter",
                "^AND boolean-based blind - WHERE or HAVING clause$",
                "--output-dir",
                str(workspace / "sqlmap-output"),
                "--flush-session",
                "-v",
                "1",
            ]
        payload_file = workspace / "approved-payload.txt"
        payload_file.write_text(payload + "\n")
        return [
            str(c.binary.path),
            "url",
            alias,
            "-p",
            surface.input_name,
            "--format",
            "json",
            "--no-color",
            "--proxy",
            proxy,
            "--insecure=false",
            "--workers",
            "1",
            "--rate-limit",
            str(c.rate_limit),
            "--retries",
            "0",
            "--timeout",
            str(c.request_timeout),
            "--scan-timeout",
            "20",
            "--skip-discovery",
            "--skip-mining",
            "--skip-ast-analysis",
            "--skip-reflection-header",
            "--skip-reflection-cookie",
            "--skip-reflection-path",
            "--skip-waf-probe",
            "--waf-bypass",
            "off",
            "--encoders",
            "none",
            "--custom-payload",
            str(payload_file),
            "--only-custom-payload",
            "--max-payloads-per-param",
            "1",
        ]

    def read_output(  # noqa: PLR0911 - three distinct upstream result contracts
        self, raw: dict[str, Any], workspace: Path, alias: str, parameter: str, payload: str
    ) -> dict[str, Any] | None:
        if self.config.tool == "arjun":
            if any(
                word in raw.get("stdout", "")
                for word in ("Skipping.", "Skipping ", "couldn't", "Unreachable")
            ):
                return None
            path = workspace / "arjun.json"
            if not path.exists():
                return (
                    {"parameters": []}
                    if "No parameters were discovered." in raw.get("stdout", "")
                    else None
                )
            if path.stat().st_size > 65536:
                return None
            data = json.loads(path.read_text())
            if (
                not isinstance(data, dict)
                or set(data) != {alias}
                or not isinstance(data[alias], dict)
                or not isinstance(data[alias].get("params"), list)
                or any(x not in self.config.parameters for x in data[alias]["params"])
            ):
                return None
            return {"parameters": sorted(set(data[alias]["params"]))}
        if self.config.tool == "sqlmap":
            files = list((workspace / "sqlmap-output").glob("*/log"))
            if len(files) > 1 or any(p.stat().st_size > 65536 for p in files):
                return None
            text = files[0].read_text() if files else ""
            candidate = (
                "Type: boolean-based blind" in text and "Title: AND boolean-based blind" in text
            )
            negative = "all tested parameters do not appear to be injectable" in raw.get(
                "stdout", ""
            )
            return {"candidate": candidate} if candidate or negative else None
        data = json.loads(raw.get("stdout", ""))
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("findings"), list)
            or not isinstance(data.get("meta"), dict)
            or data["meta"].get("dalfox_version") != self.config.version
            or data["meta"].get("incomplete") is not False
            or data["meta"].get("failed_requests") != 0
            or data["meta"].get("targets") != [alias]
            or data["meta"].get("findings_count") != len(data["findings"])
            or not isinstance(data["meta"].get("target_summary"), list)
            or len(data["meta"]["target_summary"]) != 1
            or not isinstance(data["meta"]["target_summary"][0], dict)
            or data["meta"]["target_summary"][0].get("status") not in {"clean", "findings"}
            or any(
                not isinstance(item, dict) or item.get("type") not in {"V", "R", "A", "I"}
                for item in data["findings"]
            )
        ):
            return None
        return {
            "candidate": any(
                isinstance(item, dict)
                and item.get("type") in {"V", "R"}
                and item.get("param") == parameter
                and item.get("payload") == payload
                for item in data["findings"]
            )
        }

    async def cancel(self) -> None:
        await self.runner.cancel()

    async def _execute_guarded(
        self, argv: list[str], timeout: float, stop: asyncio.Event
    ) -> dict[str, Any]:
        execution = asyncio.create_task(self.runner.execute(argv, timeout))
        denied = asyncio.create_task(stop.wait())
        try:
            await asyncio.wait((execution, denied), return_when=asyncio.FIRST_COMPLETED)
            if execution.done():
                return await execution
            execution.cancel()
            await asyncio.gather(execution, return_exceptions=True)
            # The supervisor stream may be interrupted by this immediate stop.
            # Do not parse it as an empty result or claim captured stream bytes.
            return {"policy_stopped": True, "exit_code": None}
        finally:
            execution.cancel()
            denied.cancel()
            await asyncio.gather(execution, denied, return_exceptions=True)

    async def cleanup(self) -> None:
        await self.runner.cleanup()

    def healthcheck(self) -> dict[str, Any]:
        return {"tool": self.config.tool, "configured": True, "live_verified": False}


def ensure_followups(store: AssessmentStore) -> None:
    with store.transaction() as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS rj_specialist_followup("
            "parent_job TEXT PRIMARY KEY REFERENCES rj_job(id), engagement TEXT NOT NULL,"
            "surface_id TEXT NOT NULL, candidate_ref TEXT NOT NULL, state INTEGER NOT NULL)"
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS rj_specialist_pending "
            "ON rj_specialist_followup(engagement,state)"
        )


def reconcile_confirmations(store: AssessmentStore, policy: EngagementPolicy) -> None:
    """Crash-safe outbox: only committed successful Dalfox parents release work.

    Queue insertion and acknowledgement may be interrupted independently; the
    stable candidate reference/job key deduplicates recovery after a restart.
    """
    with store.transaction() as db:
        pending = db.execute(
            "SELECT f.*,j.execution_status FROM rj_specialist_followup f "
            "JOIN rj_job j ON j.id=f.parent_job WHERE f.engagement=? AND f.state=0 "
            "AND j.execution_status NOT IN ('queued','running','retry_wait') LIMIT 64",
            (policy.engagement_id,),
        ).fetchall()
    for row in pending:
        if row["execution_status"] == "succeeded":
            spec = JobSpec(
                row["surface_id"],
                "xss_confirmation",
                "browser_xss_confirmation",
                policy_revision=policy.revision,
                options={"candidate_ref": row["candidate_ref"]},
            )
            store.submit(policy, [spec])
        with store.transaction() as db:
            db.execute(
                "UPDATE rj_specialist_followup SET state=? WHERE parent_job=?",
                (1 if row["execution_status"] == "succeeded" else 2, row["parent_job"]),
            )
