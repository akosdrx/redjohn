"""Host-only auth outcome -> exact reviewed GET anchors, with no new HTTP I/O."""

from __future__ import annotations

import fcntl
import json
import math
import os
import stat
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn
from urllib.parse import urlsplit

from redjohn.assessment.auth_replay import AuthReplayVault
from redjohn.assessment.browser_capture import BrowserCaptureDenied
from redjohn.assessment.policy import origin_for
from redjohn.assessment.session_refresh import _atomic_private_json, _fingerprint
from redjohn.assessment.workflow_inputs import PrivateWorkflowState


if TYPE_CHECKING:
    from redjohn.assessment.browser_capture import BrowserPostCaptureService


def _deny(code: str) -> NoReturn:
    raise BrowserCaptureDenied("browser_capture_bootstrap_" + code)


def _proof(
    service: BrowserPostCaptureService,
    actor: str,
    tenant: str,
    revision: str,
    reference: str,
) -> dict[str, Any]:
    policy, db = service.policy, service.store.db
    service.store.inventory._fence(db, policy)
    row = db.execute(
        "SELECT e.payload,e.bytes,e.kind,j.spec,j.execution_status,j.cancel_requested,"
        "j.lease_until,j.id AS producer_job_id FROM rj_evidence e JOIN rj_job j ON e.job_id=j.id "
        "AND e.engagement=j.engagement WHERE e.id=? AND e.engagement=? "
        "AND j.capability='browser_auth_flow'",
        (reference, policy.engagement_id),
    ).fetchone()
    if row is None or row["bytes"] > 8192 or row["kind"] != "auth_flow_outcome":
        _deny("verified_outcome_required")
    data = json.loads(row["payload"])
    if not isinstance(data, dict) or any(
        not isinstance(data.get(key), str)
        for key in (
            "engagement_id",
            "owner_id",
            "policy_revision",
            "flow_id",
            "actor_id",
            "tenant_id",
            "session_revision",
            "identity_url",
            "origin",
        )
    ):
        _deny("invalid_outcome")
    expires = data.get("expires_at")
    if not isinstance(expires, (int, float)) or isinstance(expires, bool):
        _deny("invalid_expiry")
    if (
        (
            data["engagement_id"],
            data["owner_id"],
            data["policy_revision"],
            data["actor_id"],
            data["tenant_id"],
            data["session_revision"],
        )
        != (policy.engagement_id, policy.owner_id, policy.revision, actor, tenant, revision)
        or data.get("outcome") != "authenticated"
        or data.get("identity_verified") is not True
        or type(data.get("identity_status")) is not int
        or data["identity_status"] != 200
        or not math.isfinite(expires)
        or not time.time() < expires <= time.time() + 3600
        or row["cancel_requested"]
        or row["execution_status"] not in {"running", "succeeded"}
        or (row["execution_status"] == "running" and (row["lease_until"] or 0) <= time.time())
    ):
        _deny("outcome_not_current")
    spec = json.loads(row["spec"])
    if (
        spec.get("options", {}).get("flow_id") != data["flow_id"]
        or spec.get("idempotent") is not False
    ):
        _deny("outcome_job_mismatch")
    flow = db.execute(
        "SELECT f.*,p.payload AS plan_payload FROM rj_auth_flow f JOIN rj_auth_plan p "
        "ON f.plan_id=p.id AND f.engagement=p.engagement AND f.policy_revision=p.policy_revision "
        "WHERE f.id=? AND f.engagement=? AND f.policy_revision=?",
        (data["flow_id"], policy.engagement_id, policy.revision),
    ).fetchone()
    session = db.execute(
        "SELECT revision,status FROM rj_session_state WHERE engagement=? AND actor=? "
        "AND tenant=? AND policy_revision=?",
        (policy.engagement_id, actor, tenant, policy.revision),
    ).fetchone()
    if (
        flow is None
        or session is None
        or flow["status"] != "ready"
        or (flow["actor"], flow["tenant"]) != (actor, tenant)
        or not str(flow["from_revision"]).isascii()
        or not str(flow["from_revision"]).isdigit()
        or not 1 <= len(str(flow["from_revision"])) <= 18
        or not 1 <= int(flow["from_revision"]) < 10**18
        or str(int(flow["from_revision"]) + 1) != revision
        or (session["status"], session["revision"]) != ("ready", revision)
    ):
        _deny("ready_identity_required")
    if flow["job_id"] != row["producer_job_id"]:
        _deny("outcome_producer_mismatch")
    plan = json.loads(flow["plan_payload"])
    if (
        plan.get("identity_url"),
        plan.get("actor_id"),
        plan.get("tenant_id"),
        plan.get("outcome"),
    ) != (data["identity_url"], actor, tenant, "authenticated"):
        _deny("reviewed_identity_plan_required")
    policy.check_readonly_request(data["identity_url"], "GET")
    if origin_for(data["identity_url"]) != data["origin"]:
        _deny("identity_origin_mismatch")
    return data


def _private_checkpoint(
    service: BrowserPostCaptureService,
    data: dict[str, Any],
    reference: str,
    storage: dict[str, Any],
    path: Path,
) -> None:
    if not isinstance(storage, dict) or len(json.dumps(storage, allow_nan=False).encode()) > 65536:
        _deny("private_storage_budget")
    checkpoint = PrivateWorkflowState(path, service.policy).get(data["flow_id"])
    if (
        checkpoint.get("actor_id"),
        checkpoint.get("tenant_id"),
        checkpoint.get("session_revision"),
        checkpoint.get("outcome"),
        checkpoint.get("auth_evidence_ref"),
    ) != (
        data["actor_id"],
        data["tenant_id"],
        data["session_revision"],
        "authenticated",
        reference,
    ) or checkpoint.get("storage_state") != storage:
        _deny("private_checkpoint_mismatch")


def _path_matches(path: str, request_path: str) -> bool:
    return path.startswith("/") and (
        path == request_path or request_path.startswith(path if path.endswith("/") else path + "/")
    )


def _cookies(
    storage: dict[str, Any], urls: set[str], expires: float
) -> tuple[list[dict[str, str]], float]:
    raw = storage.get("cookies")
    if not isinstance(raw, list) or len(raw) > 32:
        _deny("cookie_budget")
    host = urlsplit(next(iter(urls))).hostname or ""
    cookies = []
    names: set[str] = set()
    for cookie in raw:
        if not isinstance(cookie, dict):
            _deny("invalid_cookie")
        domain, path = cookie.get("domain"), cookie.get("path")
        if not isinstance(domain, str) or not isinstance(path, str):
            _deny("invalid_cookie")
        domain = domain.lstrip(".").lower()
        if not domain or not (host == domain or host.endswith("." + domain)):
            continue
        if not all(_path_matches(path, urlsplit(url).path or "/") for url in urls):
            continue
        if cookie.get("secure") is True and any(urlsplit(url).scheme != "https" for url in urls):
            continue
        cookie_expiry = cookie.get("expires", -1)
        if type(cookie_expiry) not in {int, float} or not math.isfinite(cookie_expiry):
            _deny("invalid_cookie_expiry")
        if cookie_expiry != -1:
            if cookie_expiry <= time.time():
                continue
            expires = min(expires, cookie_expiry)
        name, value = cookie.get("name"), cookie.get("value")
        if not isinstance(name, str) or not isinstance(value, str) or name in names:
            _deny("ambiguous_cookie")
        names.add(name)
        cookies.append({"name": name, "value": value})
    if not cookies:
        _deny("scoped_session_cookie_required")
    return cookies, expires


def bootstrap_authenticated_context(
    service: BrowserPostCaptureService,
    actor: str,
    tenant: str,
    revision: str,
    storage: dict[str, Any],
    reference: str,
    *,
    private_state_file: Path,
) -> None:
    """Bind verified private cookies only to operator-reviewed capture starts."""
    policy = service.policy
    policy.check_actor(actor)
    if (
        actor == "anonymous"
        or not isinstance(revision, str)
        or not revision.isascii()
        or not revision.isdigit()
    ):
        _deny("named_numeric_identity_required")
    rules = [
        rule
        for rule in service._rules()
        if rule["actor_id"] == actor
        and rule["tenant_id"] == tenant
        and rule["session_revision"] in {revision, "current"}
        and rule.get("start_url")
        and rule["expires_at"] > time.time()
    ]
    if not rules:
        _deny("reviewed_start_required")
    descriptor = os.open(service.vault_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
        ):
            _deny("private_vault_required")
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with service.store.transaction():
            data = _proof(service, actor, tenant, revision, reference)
            _private_checkpoint(service, data, reference, storage, Path(private_state_file))
            if any(
                origin_for(rule["url"]) != data["origin"]
                or origin_for(rule["start_url"]) != data["origin"]
                for rule in rules
            ):
                _deny("reviewed_start_origin_mismatch")
            starts = {policy._request_url(rule["start_url"]) for rule in rules}
            urls = starts | {policy._request_url(rule["url"]) for rule in rules}
            expiry = min(data["expires_at"], *(rule["expires_at"] for rule in rules))
            cookies, expiry = _cookies(storage, urls, expiry)
            entry = {
                "engagement_id": policy.engagement_id,
                "owner_id": policy.owner_id,
                "actor_id": actor,
                "tenant_id": tenant,
                "session_revision": revision,
                "policy_revision": policy.revision,
                "expires_at": expiry,
                "origin": data["origin"],
                "headers": {},
                "cookies": cookies,
                "allowed_requests": [
                    {"url": url, "method": "GET", "request_ref": "auth-bootstrap:" + reference}
                    for url in sorted(starts)
                ],
            }
            vault = service._vault()
            current = [
                e
                for e in vault["entries"]
                if (e["actor_id"], e["tenant_id"], e["session_revision"], e["origin"])
                == (actor, tenant, revision, data["origin"])
            ]
            covered = {
                r["url"]
                for e in current
                if e["cookies"] == cookies and not e["headers"] and e["expires_at"] > time.time()
                for r in e["allowed_requests"]
                if r["method"] == "GET"
            }
            if starts <= covered:
                return
            if current:
                _deny("current_credentials_conflict")
            vault["entries"].append(entry)
            AuthReplayVault.for_rotation_mapping(vault, policy)
            _atomic_private_json(service.vault_file, vault, _fingerprint(info))
    finally:
        os.close(descriptor)
