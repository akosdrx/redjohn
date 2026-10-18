"""Pinned, explicitly selected HTTP Nuclei integration for the existing hunt tool.

No global template discovery, automatic update or severity/tag authorization.
The controller validates a deliberately small structured HTTP template subset.
Approved authenticated POST templates carry a public placeholder; the private
request body is injected only by the host replay proxy. Other protocols require
their own reviewed adapter and resource policy.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
import uuid
from collections import Counter
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit, urlunsplit


if TYPE_CHECKING:
    from collections.abc import Callable

    from redjohn.assessment.auth_replay import AuthReplayBinding

import yaml
from agents.sandbox.errors import ExecFailureError

from redjohn.assessment.request_body import HOST_REPLAY_BODY_MARKER


_SHA256 = re.compile(r"[0-9a-f]{64}")
_TEMPLATE_ID = re.compile(r"[a-zA-Z0-9_-]{1,160}")
_VERSION = re.compile(r"v?3\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?")
_BUNDLE_FILE_LIMIT = 128
_TEMPLATE_MAX_BYTES = 65536
_BUNDLE_MAX_BYTES = 4194304
HOST_REPLAY_BODY = HOST_REPLAY_BODY_MARKER
_POST_CONTENT_TYPE = re.compile(
    r"(?:application/json|application/x-www-form-urlencoded)(?:; charset=utf-8)?"
    r"|multipart/form-data; boundary=[A-Za-z0-9_-]{1,70}\Z"
)
_CANCEL_SOURCE = """import os, pathlib, signal, sys, time
p=pathlib.Path('.redjohn-hunt')/(sys.argv[1]+'.pid')
end=time.monotonic()+1
while not p.exists() and time.monotonic()<end:
    time.sleep(.025)
try:
    os.kill(int(p.read_text()), signal.SIGTERM)
except (FileNotFoundError, ProcessLookupError):
    pass
end=time.monotonic()+3
while p.exists() and time.monotonic()<end:
    time.sleep(.025)
if p.exists():
    raise RuntimeError('scanner cleanup did not acknowledge cancellation')
"""


class NucleiContractError(ValueError):
    """An explicit input, provenance or template capability is invalid."""


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bundle_digest(files: dict[str, str]) -> str:
    """Digest covers the complete file-name/content-digest manifest, sorted."""
    return _sha(json.dumps(files, sort_keys=True, separators=(",", ":")).encode())


@dataclass(frozen=True)
class TemplateSelection:
    path: str
    template_id: str
    profiles: tuple[str, ...]
    effect: str = "read-only"
    protocol: str = "http"


@dataclass(frozen=True)
class ReviewedHTTPRequest:
    method: str
    path: str
    body: str | None
    content_type: str | None


@dataclass(frozen=True)
class NucleiLock:
    binary_path: str
    binary_version: str
    binary_sha256: str
    binary_source: str
    binary_license: str
    bundle_root: str
    bundle_version: str
    bundle_sha256: str
    bundle_source: str
    bundle_license: str
    files: dict[str, str]
    templates: tuple[TemplateSelection, ...]

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> NucleiLock:
        try:
            binary, bundle = value["binary"], value["bundle"]
            lock = cls(
                binary_path=binary["path"],
                binary_version=binary["version"],
                binary_sha256=binary["sha256"],
                binary_source=binary["source"],
                binary_license=binary["license"],
                bundle_root=bundle["root"],
                bundle_version=bundle["version"],
                bundle_sha256=bundle["sha256"],
                bundle_source=bundle["source"],
                bundle_license=bundle["license"],
                files=dict(bundle["files"]),
                templates=tuple(
                    TemplateSelection(
                        path=item["path"],
                        template_id=item["id"],
                        profiles=tuple(item["profiles"]),
                        effect=item["effect"],
                        protocol=item["protocol"],
                    )
                    for item in bundle["templates"]
                ),
            )
            lock.validate()
        except (KeyError, TypeError, ValueError) as error:
            raise NucleiContractError(f"Invalid Nuclei lock: {error}") from error
        return lock

    def validate(self) -> None:
        if not Path(self.binary_path).is_absolute() or not _VERSION.fullmatch(self.binary_version):
            raise NucleiContractError("A pinned absolute Nuclei v3 binary is required")
        if not _SHA256.fullmatch(self.binary_sha256):
            raise NucleiContractError("Binary SHA-256 is required")
        for text in (
            self.binary_source,
            self.binary_license,
            self.bundle_source,
            self.bundle_license,
            self.bundle_version,
            self.bundle_root,
        ):
            if not isinstance(text, str) or not text.strip() or len(text) > 1024:
                raise NucleiContractError("Source, license and version references are required")
        if not self.files or len(self.files) > _BUNDLE_FILE_LIMIT:
            raise NucleiContractError("Bundle file count is empty or exceeds 128")
        for name, digest in self.files.items():
            path = PurePosixPath(name)
            if (
                len(name) > 512
                or path.is_absolute()
                or ".." in path.parts
                or str(path) != name
                or not _SHA256.fullmatch(digest)
            ):
                raise NucleiContractError("Bundle paths and SHA-256 values must be canonical")
        if bundle_digest(self.files) != self.bundle_sha256:
            raise NucleiContractError("Complete bundle digest mismatch")
        if not self.templates or len(self.templates) > _BUNDLE_FILE_LIMIT:
            raise NucleiContractError("Explicit reviewed template selection is required")
        ids = set()
        for item in self.templates:
            if (
                item.path not in self.files
                or not _TEMPLATE_ID.fullmatch(item.template_id)
                or item.template_id in ids
                or item.protocol != "http"
                or item.effect not in {"read-only", "authenticated-replay"}
                or not item.profiles
                or set(item.profiles) - {"safe-production", "active-staging", "isolated-lab"}
            ):
                raise NucleiContractError("Unsupported or unreviewed template selection")
            if item.effect == "authenticated-replay" and "safe-production" in item.profiles:
                raise NucleiContractError(
                    "Authenticated POST replay requires an active or lab profile"
                )
            ids.add(item.template_id)


@dataclass(frozen=True)
class NucleiOptions:
    timeout_seconds: int = 180
    rate_limit: int = 5
    request_timeout: int = 10
    max_output_bytes: int = 65536

    def validate(self) -> None:
        for value, low, high in (
            (self.timeout_seconds, 1, 180),
            (self.rate_limit, 1, 10),
            (self.request_timeout, 1, 20),
            (self.max_output_bytes, 1024, 262144),
        ):
            if type(value) is not int or not low <= value <= high:
                raise NucleiContractError("Nuclei option is not a bounded allowed integer")


def validate_template(raw: bytes, selection: TemplateSelection) -> int:  # noqa: PLR0912
    """Reject dynamic destinations and higher-effect Nuclei capabilities."""
    if len(raw) > _TEMPLATE_MAX_BYTES:
        raise NucleiContractError("Template exceeds 64 KiB")
    try:
        if any(
            isinstance(token, (yaml.tokens.AliasToken, yaml.tokens.AnchorToken))
            for token in yaml.scan(raw)
        ):
            raise NucleiContractError(
                "YAML aliases/anchors are unsupported within template budgets"
            )
        value = yaml.safe_load(raw)
    except yaml.YAMLError as error:
        raise NucleiContractError("Invalid template YAML") from error
    if not isinstance(value, dict) or set(value) - {"id", "info", "http"}:
        raise NucleiContractError("Only reviewed structured HTTP templates are supported")
    if value.get("id") != selection.template_id or not isinstance(value.get("info"), dict):
        raise NucleiContractError("Template ID/info does not match reviewed selection")
    requests = value.get("http")
    if not isinstance(requests, list) or not 1 <= len(requests) <= 16:
        raise NucleiContractError("HTTP request count is missing or exceeds limit")
    allowed = {
        "method",
        "path",
        "matchers",
        "matchers-condition",
        "extractors",
        "stop-at-first-match",
        "max-size",
        "id",
        "headers",
        "body",
    }
    request_count = 0
    for request in requests:
        if (
            not isinstance(request, dict)
            or set(request) - allowed
            or request.get("method", "GET") not in {"GET", "HEAD", "POST"}
        ):
            raise NucleiContractError(
                "Unsupported HTTP method, redirect, raw or dynamic capability"
            )
        if request.get("method", "GET") == "POST":
            headers = request.get("headers")
            if (
                selection.effect != "authenticated-replay"
                or "safe-production" in selection.profiles
                or request.get("body") != HOST_REPLAY_BODY
                or not isinstance(headers, dict)
                or set(headers) != {"Content-Type"}
                or not isinstance(headers["Content-Type"], str)
                or not _POST_CONTENT_TYPE.fullmatch(headers["Content-Type"])
            ):
                raise NucleiContractError("POST requires a reviewed host-only replay placeholder")
        elif selection.effect != "read-only" or "body" in request or "headers" in request:
            raise NucleiContractError("GET/HEAD templates require the read-only request contract")
        paths = request.get("path")
        if not isinstance(paths, list) or not 1 <= len(paths) <= 16:
            raise NucleiContractError("Explicit bounded HTTP paths are required")
        request_count += len(paths)
        for path in paths:
            if not isinstance(path, str) or not path.startswith(("{{BaseURL}}", "{{RootURL}}")):
                raise NucleiContractError("HTTP path must use the authorized target")
            suffix = path.split("}}", 1)[1]
            if (
                (suffix and not suffix.startswith(("/", "?")))
                or "{{" in suffix
                or "\n" in path
                or "\r" in path
                or "\\" in path
            ):
                raise NucleiContractError("Dynamic or alternate destinations are unsupported")
        # DSL helper expressions can read files or make additional requests. This
        # adapter only admits local word/regex/status/size/binary comparisons.
        for key in ("matchers", "extractors"):
            items = request.get(key, [])
            if not isinstance(items, list) or len(items) > 32:
                raise NucleiContractError("Invalid matcher/extractor list")
            for matcher in items:
                if not isinstance(matcher, dict) or matcher.get("type") not in {
                    "word",
                    "regex",
                    "status",
                    "size",
                    "binary",
                    "kval",
                }:
                    raise NucleiContractError(
                        "DSL, XPath and dynamic helpers require another capability"
                    )
                if "{{" in json.dumps(matcher):
                    raise NucleiContractError(
                        "Dynamic matcher/extractor interpolation is unsupported"
                    )
    return request_count


def validate_proxy_url(url: str | None) -> None:
    """Only the host-created literal loopback listener may be bound."""
    if url is None:
        return
    try:
        parts = urlsplit(url)
        if (
            parts.scheme != "http"
            or parts.hostname != "127.0.0.1"
            or parts.username is not None
            or parts.password is not None
            or parts.path
            or parts.query
            or parts.fragment
            or parts.port is None
            or not 1 <= parts.port <= 65535
            or url != f"http://127.0.0.1:{parts.port}"
        ):
            raise ValueError("invalid loopback proxy")  # noqa: TRY301
    except (ValueError, TypeError) as error:
        raise NucleiContractError("A host-bound literal loopback proxy is required") from error


def nuclei_argv(
    url: str,
    lock: NucleiLock,
    options: NucleiOptions,
    selections: tuple[TemplateSelection, ...],
    *,
    proxy_url: str | None = None,
) -> list[str]:
    options.validate()
    validate_proxy_url(proxy_url)
    argv = [
        lock.binary_path,
        "-u",
        url,
        "-jsonl",
        "-silent",
        "-no-color",
        "-duc",
        "-ni",
        "-dr",
        "-no-stdin",
        "-pt",
        "http",
        "-c",
        "1",
        "-bs",
        "1",
        "-retries",
        "0",
        "-rl",
        str(options.rate_limit),
        "-timeout",
        str(options.request_timeout),
        "-rsr",
        "1048576",
        "-omit-raw",
        "-omit-template",
    ]
    if proxy_url is not None:
        argv.extend(["-proxy", proxy_url, "-proxy-internal"])
    for template in selections:
        argv.extend(["-t", str(PurePosixPath(lock.bundle_root) / template.path)])
    return argv


def result_error(
    code: str, message: str, *, execution: str = "failed", coverage: str = "blocked"
) -> dict[str, Any]:
    return {
        "execution_status": execution,
        "coverage_status": coverage,
        "findings": [],
        "no_finding_observed": False,
        "error": {
            "code": code,
            "category": code,
            "message": f"Nuclei adapter cannot continue: {code}.",
            "retryable": False,
            "terminal": True,
            "tool_id": "nuclei",
            "job_id": None,
            "attempt_id": None,
            "cause_ref": None,
            "retry_after": None,
            "partial_evidence_refs": [],
            "coverage_effect": coverage,
            "recovery_action": "review_prerequisites",
        },
    }


def _http_request_key(url: str) -> str:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if ":" in host:
        host = "[" + host + "]"
    port = parsed.port
    if port and port != {"http": 80, "https": 443}.get(parsed.scheme):
        host += ":" + str(port)
    return urlunsplit((parsed.scheme, host, parsed.path or "/", parsed.query, ""))


def normalize_nuclei(  # noqa: PLR0912, PLR0915 - explicit independent result dimensions
    raw: dict[str, Any],
    selections: tuple[TemplateSelection, ...],
    policy: Any,
    *,
    expected_requests: int | None = None,
    expected_request_urls: tuple[str, ...] | None = None,
) -> dict[str, Any]:
    findings, errors = [], []
    ids = {item.template_id for item in selections}
    for line in raw.get("stdout", "").splitlines():
        if not line.strip() or re.match(r"^\[(?:INF|WRN|DBG)\]", line):
            continue
        try:
            item = json.loads(line)
            if (
                not isinstance(item, dict)
                or item.get("template-id") not in ids
                or item.get("type") != "http"
                or not isinstance(item.get("info"), dict)
            ):
                raise NucleiContractError("Unexpected Nuclei JSONL finding schema")
            if item.get("matcher-status", True) is not True:
                raise NucleiContractError("Unmatched or failed check cannot become a candidate")
            matched = item.get("matched-at")
            if not isinstance(matched, str):
                raise NucleiContractError("Finding has no matched-at URL")
            getattr(policy, "check_scope_url", policy.check_url)(matched)
            findings.append(
                {
                    "template_id": item["template-id"],
                    "matched_at": matched,
                    "severity": str(item["info"].get("severity", "unknown")),
                    "name": str(item["info"].get("name", ""))[:240],
                    "finding_status": "candidate",
                }
            )
        except (ValueError, TypeError, KeyError) as error:
            errors.append(str(error)[:200])
    requests = 0
    for line in raw.get("stderr", "").splitlines():
        if line.lstrip().startswith("{"):
            try:
                item = json.loads(line)
                requests = max(requests, int(item.get("requests", 0)))
                if int(item.get("errors", 0)) > 0:
                    errors.append("Nuclei reported failed requests")
            except (ValueError, TypeError, AttributeError):
                errors.append("Malformed Nuclei statistics JSON")
        if "[ERR]" in line or "[FTL]" in line:
            errors.append("Nuclei reported an execution error")
    responses = raw.get("response_observations", ())
    response_statuses: list[int] = []
    response_urls: list[str] = []
    if not isinstance(responses, (list, tuple)) or len(responses) > 256:
        errors.append("Invalid response observation bound")
        responses = ()
    for response in responses:
        try:
            if not isinstance(response, dict) or type(response.get("status")) is not int:
                raise ValueError("Invalid observed HTTP response")  # noqa: TRY301
            getattr(policy, "check_scope_url", policy.check_url)(response["url"])
            if not 100 <= response["status"] <= 599:
                raise ValueError("Invalid observed HTTP status")  # noqa: TRY301
            response_statuses.append(response["status"])
            response_urls.append(_http_request_key(response["url"]))
        except (ValueError, KeyError, TypeError):
            errors.append("Invalid response observation")
    # The observer is host-owned and reports only complete forwarded responses.
    # A count alone or an empty stdout never proves a completed negative check.
    proven_responses = (
        expected_requests is not None
        and expected_requests > 0
        and len(response_statuses) >= expected_requests
        and all(200 <= status < 300 for status in response_statuses)
        and (
            expected_request_urls is None
            or not (Counter(map(_http_request_key, expected_request_urls)) - Counter(response_urls))
        )
    )
    if raw.get("error"):
        result = result_error(raw["error"], raw.get("message", raw["error"]))
    elif raw.get("cancelled"):
        result = result_error(
            "cancelled", "Scanner was cancelled", execution="cancelled", coverage="partial"
        )
    elif raw.get("timed_out"):
        result = result_error(
            "scanner_timeout", "Scanner deadline reached", execution="timed_out", coverage="partial"
        )
    elif raw.get("truncated"):
        result = result_error(
            "output_limit",
            "Scanner output limit reached",
            execution="resource_exhausted",
            coverage="partial",
        )
    elif raw.get("exit_code") != 0:
        result = result_error(
            "scanner_failed", "Nuclei returned a nonzero exit code", coverage="inconclusive"
        )
    elif errors:
        result = result_error("parser_error", "; ".join(errors), coverage="inconclusive")
    elif any(status in {401, 403, 429} or status >= 500 for status in response_statuses):
        blocked_code = (
            "authentication_expired"
            if 401 in response_statuses
            else "permission_or_challenge"
            if 403 in response_statuses
            else "rate_limited"
            if 429 in response_statuses
            else "server_error"
        )
        result = result_error(
            blocked_code, "Observed response blocked assessment", coverage="blocked"
        )
    elif not findings and proven_responses:
        result = {
            "execution_status": "succeeded",
            "coverage_status": "completed",
            "findings": [],
            "no_finding_observed": True,
        }
    elif not findings and requests <= 0 and not response_statuses:
        result = result_error(
            "execution_unverified",
            "No request statistics or finding proves an executed check",
            coverage="inconclusive",
        )
    elif not findings:
        # Nuclei progress counts failed requests too; without captured response
        # status this cannot distinguish a clean check from 401/403/429/503.
        result = result_error(
            "response_status_unverified",
            "Response status evidence is missing",
            execution="succeeded",
            coverage="inconclusive",
        )
    else:
        result = {
            "execution_status": "succeeded",
            "coverage_status": "completed"
            if (
                proven_responses
                if "response_observations" in raw
                else requests or len(findings) >= len(selections)
            )
            else "partial",
            "findings": [],
            "no_finding_observed": False,
        }
    result["findings"] = findings
    result["telemetry"] = {
        key: raw.get(key, 0) for key in ("duration_seconds", "stdout_bytes", "stderr_bytes")
    }
    result["telemetry"]["http_requests"] = len(response_statuses) or requests or None
    result["telemetry"]["response_statuses"] = response_statuses
    result["truncated"] = bool(raw.get("truncated"))
    result["diagnostics"] = {
        "stderr_sha256": _sha(raw.get("stderr", "").encode()),
        "stderr_bytes": raw.get("stderr_bytes", 0),
    }
    return result


class BoundedScannerRunner:
    """Internal scanner transport, with finite output and cancellation cleanup."""

    def __init__(self, session: Any) -> None:
        self.session = session
        self._tokens: set[str] = set()

    async def _execute(
        self, argv: list[str], options: NucleiOptions, *, scan: bool, digests: dict[str, str]
    ) -> dict[str, Any]:
        token = uuid.uuid4().hex
        self._tokens.add(token)
        config = {
            "token": token,
            "argv": argv,
            "timeout": options.timeout_seconds,
            "max_output_bytes": options.max_output_bytes,
            "digests": digests,
            "nuclei": scan,
            "snapshot_files": [p for p in digests if p != argv[0]],
        }
        source = Path(__file__).with_name("bounded_worker.py").read_text(encoding="utf-8")
        try:
            response = await self.session.exec(
                "python3",
                "-c",
                source,
                json.dumps(config),
                timeout=options.timeout_seconds + 10,
                shell=False,
            )
            if response.exit_code or len(response.stdout) > options.max_output_bytes * 12 + 8192:
                return {"error": "worker_contract_error"}
            result = json.loads(response.stdout)
            if not isinstance(result, dict):
                return {"error": "worker_contract_error"}
            return result  # noqa: TRY300
        except asyncio.CancelledError:
            await asyncio.shield(self._cancel_token(token))
            raise
        except (TimeoutError, OSError, ValueError, ExecFailureError) as error:
            await self._cancel_token(token)
            return {"error": "worker_transport_error", "message": str(error)[:200]}
        finally:
            self._tokens.discard(token)

    async def _cancel_token(self, token: str) -> None:
        await self.session.exec("python3", "-c", _CANCEL_SOURCE, token, timeout=5, shell=False)

    async def cancel(self) -> None:
        for token in tuple(self._tokens):
            await self._cancel_token(token)

    async def cleanup(self) -> None:
        await self.cancel()


class NucleiAdapter(BoundedScannerRunner):
    """Reuse the existing sandbox executable through a bounded worker."""

    def __init__(
        self,
        session: Any,
        lock: NucleiLock,
        *,
        request_admission: Callable[[int], None] | None = None,
        evidence_sink: Callable[[dict[str, Any]], str] | None = None,
        proxy_url: str | None = None,
        response_observations: Callable[[], tuple[dict[str, Any], ...]] | None = None,
        auth_replay: AuthReplayBinding | None = None,
    ) -> None:
        lock.validate()
        super().__init__(session)
        self.lock = lock
        self.request_admission = request_admission
        self.evidence_sink = evidence_sink
        validate_proxy_url(proxy_url)
        self.proxy_url = proxy_url
        self.response_observations = response_observations
        self.auth_replay = auth_replay

    def capabilities(self) -> dict[str, Any]:
        return {
            "tool_id": "nuclei",
            "version": self.lock.binary_version,
            "binary_sha256": self.lock.binary_sha256,
            "bundle_version": self.lock.bundle_version,
            "bundle_sha256": self.lock.bundle_sha256,
            "input": ["http-get-url"]
            + (["https-get-url"] if self.proxy_url else [])
            + (
                ["https-post-json", "https-post-form", "https-post-multipart"]
                if self.auth_replay is not None and self.auth_replay.method == "POST"
                else []
            ),
            "request_body_max_bytes": 65536,
            "request_body_transport": "exact_host_proxy_injection",
            "authenticated_post_replay": self.auth_replay is not None
            and self.auth_replay.method == "POST",
            "https_tls_validation": "host_proxy_verified"
            if self.proxy_url
            else "blocked_requires_verified_proxy",
            "response_status_capture": self.response_observations is not None,
            "egress_proxy_bound": self.proxy_url is not None,
            "auth_replay": self.auth_replay is not None,
            "auth_replay_scope": "exact_observed_request_host_proxy"
            if self.auth_replay is not None
            else "anonymous",
            "cancellation": True,
            "resource_class": "scanner",
            "license": self.lock.binary_license,
            "template_license": self.lock.bundle_license,
        }

    async def healthcheck(self) -> dict[str, Any]:
        raw = await self._execute(
            [self.lock.binary_path, "-version"],
            NucleiOptions(timeout_seconds=5),
            scan=False,
            digests={self.lock.binary_path: self.lock.binary_sha256},
        )
        version = self.lock.binary_version.lstrip("v")
        if raw.get("error"):
            return result_error(raw["error"], raw.get("message", raw["error"]))
        if raw.get("exit_code") != 0 or not re.search(
            rf"(?<![\d.])v?{re.escape(version)}(?![\d.])",
            raw.get("stdout", "") + raw.get("stderr", ""),
        ):
            return result_error("tool_version_mismatch", "Pinned Nuclei version not observed")
        return {
            "execution_status": "succeeded",
            "coverage_status": "not_tested",
            "capability": self.capabilities(),
        }

    async def prepare(self, selections: tuple[TemplateSelection, ...]) -> dict[str, str]:
        total, contents = 0, {}
        for name, expected in self.lock.files.items():
            path = PurePosixPath(self.lock.bundle_root) / name
            stream = await self.session.read(Path(str(path)))
            try:
                raw = stream.read(_TEMPLATE_MAX_BYTES + 1)
            finally:
                stream.close()
            if isinstance(raw, str):
                raw = raw.encode()
            total += len(raw)
            if len(raw) > _TEMPLATE_MAX_BYTES or total > _BUNDLE_MAX_BYTES or _sha(raw) != expected:
                raise NucleiContractError("Template bundle content/digest/size mismatch")
            contents[name] = raw
        self.prepared_request_count = sum(
            validate_template(contents[selection.path], selection) for selection in selections
        )
        self.prepared_template_requests = tuple(
            ReviewedHTTPRequest(
                request.get("method", "GET"),
                path,
                request.get("body"),
                request.get("headers", {}).get("Content-Type"),
            )
            for selection in selections
            for request in yaml.safe_load(contents[selection.path])["http"]
            for path in request["path"]
        )
        self.prepared_http_requests = tuple(
            (request.method, request.path) for request in self.prepared_template_requests
        )
        return {
            str(PurePosixPath(self.lock.bundle_root) / name): digest
            for name, digest in self.lock.files.items()
        }

    def _reviewed_request_urls(self, url: str, policy: Any) -> tuple[str, ...]:
        parsed_target = urlsplit(url)
        root_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
        expected = tuple(
            path.replace("{{BaseURL}}", url.rstrip("/")).replace("{{RootURL}}", root_url)
            for _method, path in self.prepared_http_requests
        )
        for (method, _path), target in zip(self.prepared_http_requests, expected, strict=True):
            if method == "POST":
                policy.check_replay_request(target, method)
            else:
                policy.check_readonly_request(target, method)
        return expected

    async def run(  # noqa: PLR0911, PLR0912, PLR0915 - fail closed prerequisite boundaries
        self,
        url: str,
        options: NucleiOptions | None = None,
        *,
        cve_id: str = "",
        policy: Any = None,
    ) -> dict[str, Any]:
        options = options or NucleiOptions()
        options.validate()
        if policy is None:
            return result_error("policy_required", "Explicit engagement policy is required")
        if getattr(policy, "egress_mode", None) == "enforced":
            try:
                self.session.assert_remote_boundary()
            except (AttributeError, ValueError, RuntimeError, PermissionError):
                return result_error(
                    "remote_egress_boundary_required", "Live kernel egress boundary required"
                )
        try:
            method = self.auth_replay.method if self.auth_replay else "GET"
            if method == "POST":
                policy.check_replay_request(url, method)
            else:
                policy.check_readonly_request(url, method)
            if self.auth_replay is not None:
                if self.proxy_url is None or self.response_observations is None:
                    return result_error(
                        "auth_replay_requires_host_proxy", "Host-owned replay proxy required"
                    )
                self.auth_replay.validate(url, self.auth_replay.method, policy)
        except ValueError as error:
            code = str(error) if str(error).startswith("auth_replay_") else "blocked_by_policy"
            return result_error(code, str(error))
        if urlsplit(url).scheme == "https" and (
            self.proxy_url is None or self.response_observations is None
        ):
            return result_error(
                "https_requires_verified_egress_proxy",
                "HTTPS scanning requires the host-owned verified TLS egress observer",
            )
        deadline = getattr(policy, "deadline", 0)
        if deadline:
            left = int(deadline - time.time())
            if left < 1:
                return result_error("campaign_deadline_exceeded", "Campaign deadline reached")
            options = NucleiOptions(
                min(left, options.timeout_seconds),
                options.rate_limit,
                options.request_timeout,
                options.max_output_bytes,
            )
        selections = tuple(
            item
            for item in self.lock.templates
            if policy.profile in item.profiles
            and (not cve_id or item.template_id.upper() == cve_id.upper())
        )
        if not selections:
            return result_error(
                "template_not_authorized", "No explicitly reviewed template is selected"
            )
        if any(item.effect == "authenticated-replay" for item in selections) and (
            self.auth_replay is None or self.auth_replay.method != "POST"
        ):
            return result_error(
                "auth_replay_required", "Reviewed POST replay requires a host-owned binding"
            )
        health = await self.healthcheck()
        if health["execution_status"] != "succeeded":
            return health
        try:
            digests = await self.prepare(selections)
        except (OSError, ValueError) as error:
            return result_error("template_contract_error", str(error))
        try:
            expected_request_urls = self._reviewed_request_urls(url, policy)
            if self.auth_replay is not None:
                for request, target in zip(
                    self.prepared_template_requests, expected_request_urls, strict=True
                ):
                    if request.method == "POST":
                        self.auth_replay.validate_template_request(
                            target, request.method, request.body, request.content_type, policy
                        )
                    else:
                        self.auth_replay.validate(target, request.method, policy)
        except ValueError as error:
            code = str(error) if str(error).startswith("auth_replay_") else "blocked_by_policy"
            return result_error(code, str(error))
        if self.prepared_request_count > getattr(policy, "request_budget", 128):
            return result_error(
                "request_budget_exceeded", "Reviewed template requests exceed the campaign budget"
            )
        try:
            if self.auth_replay is not None and self.auth_replay.method == "POST":
                policy.check_replay_request(url, "POST")
            else:
                policy.check_readonly_request(url, "GET")
        except ValueError as error:
            return result_error("blocked_by_policy", str(error))
        if self.request_admission is not None:
            self.request_admission(self.prepared_request_count)
        digests[self.lock.binary_path] = self.lock.binary_sha256
        raw = await self._execute(
            nuclei_argv(url, self.lock, options, selections, proxy_url=self.proxy_url),
            options,
            scan=True,
            digests=digests,
        )
        if self.response_observations is not None:
            try:
                observed = self.response_observations()
                if not isinstance(observed, tuple) or len(observed) > 256:
                    raise ValueError("invalid response observer bound")  # noqa: TRY301
                raw["response_observations"] = list(observed)
            except (OSError, ValueError, TypeError):
                raw["error"] = "response_observer_failed"
        # Redaction may alter coincidental protocol words or JSON syntax. Scan
        # classification must use the original bounded, host-memory-only data;
        # every persistence sink below receives only the private-value mask.
        result = normalize_nuclei(
            raw,
            selections,
            policy,
            expected_requests=self.prepared_request_count,
            expected_request_urls=expected_request_urls,
        )
        if self.auth_replay is not None:
            raw = self.auth_replay.redact_worker_output(raw)
            for finding in result["findings"]:
                for field_name in ("name", "matched_at"):
                    finding[field_name] = self.auth_replay.redact_raw(finding[field_name])
            if result.get("error"):
                result["error"]["message"] = self.auth_replay.redact_raw(result["error"]["message"])
        evidence_ref = None
        if self.evidence_sink is not None:
            try:
                evidence_ref = self.evidence_sink(raw)
            except (OSError, ValueError):
                return result_error(
                    "evidence_write_failed", "Evidence persistence failed", coverage="inconclusive"
                )
        if evidence_ref is not None:
            result["evidence_refs"] = [evidence_ref]
            if result.get("error"):
                result["error"]["partial_evidence_refs"] = [evidence_ref]
        result["tool"] = self.capabilities()
        if self.auth_replay is not None:
            result["auth_replay"] = self.auth_replay.metadata()
            for finding in result["findings"]:
                finding["actor_ref"] = self.auth_replay.actor_id
                finding["tenant_ref"] = self.auth_replay.tenant_id
                finding["session_revision"] = self.auth_replay.session_revision
                finding["request_ref"] = self.auth_replay.request_ref
        return result
