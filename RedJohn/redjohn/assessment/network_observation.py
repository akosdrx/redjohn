"""Job/attempt-owned native evidence for later atomic inventory completion.

This component starts no engine and creates no execution grants. Only its typed
adapter producers may seal native+transport proof after verified cleanup.
"""

from __future__ import annotations

import json
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import asdict
from typing import TYPE_CHECKING, Any

from redjohn.assessment.egress import LinuxEgressBoundary
from redjohn.assessment.models import JobSpec, Surface, stable_key
from redjohn.assessment.network_broker import ScopedTCPBroker
from redjohn.assessment.network_tools import NetworkToolRunner
from redjohn.assessment.policy import PolicyDenied
from redjohn.assessment.service_broker import HTTP_SERVICE_PROBE, ObservedServiceBroker
from redjohn.assessment.service_tools import NMAP_LICENSE_SHA256, PROBE_SHA256, NmapServiceRunner
from redjohn.assessment.store import CapacityExceeded, json_text


if TYPE_CHECKING:
    import sqlite3

    from redjohn.assessment.policy import EngagementPolicy
    from redjohn.assessment.store import AssessmentStore


VERSION = "redjohn-network-observation-1"
MAX_PROOFS = 256
MAX_PROOF_BYTES = 65536
_SHA = re.compile(r"[a-f0-9]{64}\Z")
Runner = NetworkToolRunner | NmapServiceRunner
Broker = ScopedTCPBroker | ObservedServiceBroker


class NetworkProofDenied(ValueError):  # noqa: N818 - safe proof-failure protocol
    pass


def schema_db(db: sqlite3.Connection) -> None:
    db.execute(
        "CREATE TABLE IF NOT EXISTS rj_network_native_proof("
        "engagement TEXT NOT NULL,job_id TEXT NOT NULL,attempt INTEGER NOT NULL,"
        "owner TEXT NOT NULL,spec TEXT NOT NULL,native_ref TEXT NOT NULL,"
        "native_digest TEXT NOT NULL,seal_ref TEXT,seal_digest TEXT,"
        "transport_ref TEXT,PRIMARY KEY(engagement,job_id,attempt))"
    )
    db.execute(
        "CREATE TABLE IF NOT EXISTS rj_network_service_observation("
        "id TEXT PRIMARY KEY,engagement TEXT NOT NULL,job_id TEXT NOT NULL,"
        "attempt INTEGER NOT NULL,service_id TEXT NOT NULL,payload TEXT NOT NULL,"
        "UNIQUE(engagement,job_id,attempt))"
    )


def schema(store: AssessmentStore) -> None:
    with store._lock:
        schema_db(store.db)


def namespace_proof(value: object) -> list[dict[str, Any]]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= 16:
        raise NetworkProofDenied("network_observation_namespace_required")
    result: list[dict[str, Any]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or list(item.get("interfaces", ())) != ["lo"]
            or item.get("effective_capabilities") != "0"
            or item.get("no_new_privileges") is not True
            or not isinstance(item.get("namespaces"), dict)
            or set(item["namespaces"]) != {"net", "mnt", "pid", "user"}
        ):
            raise NetworkProofDenied("network_observation_namespace_unverified")
        result.append(dict(item))
    return result


def counters(broker: Broker) -> dict[str, Any]:
    result: dict[str, Any] = {
        "connect_attempts": broker.attempted,
        "connected": broker.connected,
        "refused": broker.refused,
        "denied": broker.denied,
        "response_bytes": broker.response_bytes,
    }
    if type(broker) is ObservedServiceBroker:
        result.update(
            response_digests=list(broker.response_digests),
            banner_types=sorted(broker.banner_types),
            sent_probe_count=broker.sent_probe_count,
            probe_bytes_received=broker.probe_bytes_received,
            transport_errors=dict(broker.transport_errors),
        )
    return result


def parse_native(  # noqa: PLR0912 - explicit native/transport/XML validation branches
    engine: str, stdout: str, surface: Surface, transport: dict[str, Any], relay_port: str
) -> dict[str, Any]:
    if not isinstance(stdout, str) or len(stdout.encode()) > 32768:
        raise NetworkProofDenied("network_observation_native_byte_limit")
    for name in ("connect_attempts", "connected", "refused", "denied", "response_bytes"):
        if type(transport.get(name)) is not int or not 0 <= transport[name] <= 131072:
            raise NetworkProofDenied("network_observation_transport_counters")
    attempted, connected, refused = (
        transport[k] for k in ("connect_attempts", "connected", "refused")
    )
    if not 1 <= attempted <= (8 if engine == "nmap" else 16) or transport["denied"]:
        raise NetworkProofDenied("network_observation_admission_not_proven")
    if attempted != connected + refused:
        raise NetworkProofDenied("network_observation_incomplete_connections")
    if engine == "naabu":
        rows = [json.loads(line) for line in stdout.splitlines() if line.strip()]
        if len(rows) > 16 or bool(rows) != bool(connected):
            raise NetworkProofDenied("network_observation_native_connect_mismatch")
        if any(
            not isinstance(row, dict)
            or row.get("ip") != surface.network_address
            or str(row.get("port")) != surface.network_port
            or row.get("protocol", "tcp") != "tcp"
            for row in rows
        ):
            raise NetworkProofDenied("network_observation_native_target_mismatch")
        if connected and refused:
            raise NetworkProofDenied("network_observation_contradictory_single_attempt")
        return {"state": "open" if connected else "closed_or_unreachable", "protocol_name": None}
    if engine != "nmap" or not connected or not 1 <= transport["response_bytes"] <= 131072:
        raise NetworkProofDenied("network_observation_upstream_response_required")
    digests, banners = transport.get("response_digests"), transport.get("banner_types")
    if (
        not isinstance(digests, list)
        or not 1 <= len(digests) <= 8
        or any(not isinstance(item, str) or _SHA.fullmatch(item) is None for item in digests)
        or not isinstance(banners, list)
        or not set(banners) <= {"ssh", "http"}
    ):
        raise NetworkProofDenied("network_observation_banner_proof_required")
    safe = stdout.replace("<!DOCTYPE nmaprun>", "")
    if "<!DOCTYPE" in safe.upper() or "<!ENTITY" in safe.upper():
        raise NetworkProofDenied("network_observation_xml_declaration_denied")
    try:
        document = ET.fromstring(safe)  # noqa: S314 - bounded, declaration-free native XML
    except ET.ParseError:
        raise NetworkProofDenied("network_observation_native_xml_invalid") from None
    ports, finished = document.findall("./host/ports/port"), document.find("./runstats/finished")
    if (
        document.tag != "nmaprun"
        or len(list(document.iter())) > 128
        or len(ports) != 1
        or finished is None
        or finished.get("exit") != "success"
    ):
        raise NetworkProofDenied("network_observation_native_xml_incomplete")
    port = ports[0]
    service, state = port.find("service"), port.find("state")
    if (
        port.get("protocol") != "tcp"
        or port.get("portid") != relay_port
        or state is None
        or state.get("state") != "open"
        or service is None
        or service.get("method") != "probed"
        or service.get("name") not in banners
        or service.get("name") not in {"ssh", "http"}
        or service.get("product")
        != {"ssh": "SSH service", "http": "HTTP service"}.get(service.get("name", ""))
        or service.get("version") not in {None, ""}
    ):
        raise NetworkProofDenied("network_observation_native_banner_mismatch")
    if any(
        len(value) > 128 or any(ord(c) < 32 for c in value) for value in service.attrib.values()
    ):
        raise NetworkProofDenied("network_observation_native_field_limit")
    if service.get("name") == "http" and (
        not 1 <= transport.get("sent_probe_count", 0) <= connected
        or not len(HTTP_SERVICE_PROBE)
        <= transport.get("probe_bytes_received", 0)
        <= (len(HTTP_SERVICE_PROBE) + 1) * connected
    ):
        raise NetworkProofDenied("network_observation_http_probe_required")
    return {"state": "open", "protocol_name": service.get("name")}


def owned_evidence(
    db: sqlite3.Connection,
    engagement: str,
    job_id: str,
    ref: str,
    kind: str,
    digest: str = "",
) -> tuple[dict[str, Any], str, float]:
    row = db.execute(
        "SELECT payload,digest,bytes,created_at FROM rj_evidence WHERE id=? AND engagement=? "
        "AND job_id=? AND kind=? AND bytes<=?",
        (ref, engagement, job_id, kind, MAX_PROOF_BYTES),
    ).fetchone()
    if row is None:
        raise NetworkProofDenied("network_observation_owned_evidence_required")
    value = json.loads(row[0])
    if (
        not isinstance(value, dict)
        or stable_key(value) != row[1]
        or (digest and digest != row[1])
        or len(json_text(value).encode()) != row[2]
    ):
        raise NetworkProofDenied("network_observation_evidence_integrity")
    return value, row[1], row[3]


class NativeObservationCollector:
    def __init__(self, store: AssessmentStore, policy: EngagementPolicy, runner: Runner) -> None:
        self.store, self.policy, self.runner = store, policy, runner
        if type(runner) is NmapServiceRunner:
            self.engine = "nmap"
        elif (
            type(runner) is NetworkToolRunner
            and isinstance(runner, NetworkToolRunner)
            and runner.config.tool == "naabu"
        ):
            self.engine = "naabu"
        else:
            raise TypeError("network_observation_exact_native_runner_required")
        self.pending: tuple[dict[str, Any], Broker, str] | None = None
        schema(store)

    def _running(self, job: dict[str, Any], spec: JobSpec) -> None:
        with self.store._lock:
            self.store.inventory._fence(self.store.db, self.policy)
            row = self.store.db.execute(
                "SELECT spec FROM rj_job WHERE id=? AND engagement=? AND owner=? AND attempt=? "
                "AND execution_status='running' AND cancel_requested=0 AND lease_until>?",
                (job["id"], self.policy.engagement_id, job["owner"], job["attempt"], time.time()),
            ).fetchone()
        if row is None or json.loads(row[0]) != asdict(spec):
            raise PolicyDenied("network_observation_current_attempt_required")

    def capture(
        self,
        job: dict[str, Any],
        surface: Surface,
        spec: JobSpec,
        raw: dict[str, Any],
        broker: Broker,
    ) -> str:
        self._running(job, spec)
        expected = ObservedServiceBroker if self.engine == "nmap" else ScopedTCPBroker
        if (
            type(broker) is not expected
            or self.runner.broker is not broker
            or self.pending is not None
        ):
            raise NetworkProofDenied("network_observation_exact_broker_required")
        broker.fence()
        boundary = self.runner.boundary
        if type(boundary) is not LinuxEgressBoundary or not boundary._verified:
            raise NetworkProofDenied("network_observation_attested_boundary_required")
        attestations = namespace_proof(list(boundary.attestations))
        if (
            raw.get("error")
            or raw.get("timed_out")
            or raw.get("truncated")
            or type(raw.get("exit_code")) is not int
            or raw["exit_code"] != 0
        ):
            raise NetworkProofDenied("network_observation_complete_native_result_required")
        if (
            spec.capability != ("nmap_services" if self.engine == "nmap" else "naabu_ports")
            or spec.policy_revision != self.policy.revision
            or not spec.idempotent
            or spec.tool_version != self.runner.config.version
            or spec.template_version != self.runner.config.revision
            or surface.resource_kind != "network_endpoint"
            or surface.actor_id != "anonymous"
            or self.store.surface(self.policy.engagement_id, spec.surface_id) != surface
            or broker.surface != surface
        ):
            raise NetworkProofDenied("network_observation_exact_context_required")
        self.policy.check_surface(surface)
        transport = counters(broker)
        relay = self.runner.proxy_address.rsplit(":", 1)[-1] if self.engine == "nmap" else ""
        observation = parse_native(self.engine, raw.get("stdout", ""), surface, transport, relay)
        frame = {
            "schema": VERSION,
            "job_id": job["id"],
            "attempt": job["attempt"],
            "owner": job["owner"],
            "spec": asdict(spec),
            "surface": asdict(surface),
            "engine": self.engine,
            "binary_sha256": self.runner.config.binary.sha256,
            "tool_version": self.runner.config.version,
            "template_version": self.runner.config.revision,
            "stdout": raw.get("stdout", ""),
            "relay_port": relay,
            "namespace": attestations,
            "transport": transport,
            "observation": observation,
            "probe_sha256": PROBE_SHA256 if self.engine == "nmap" else "",
            "license_sha256": NMAP_LICENSE_SHA256 if self.engine == "nmap" else "",
        }
        if len(json_text(frame).encode()) > MAX_PROOF_BYTES:
            raise NetworkProofDenied("network_observation_proof_byte_limit")
        with self.store._lock:
            if (
                self.store.db.execute(
                    "SELECT count(*) FROM rj_network_native_proof WHERE engagement=?",
                    (self.policy.engagement_id,),
                ).fetchone()[0]
                >= MAX_PROOFS
            ):
                raise CapacityExceeded("network_observation_proof_quota")
        ref = self.store.evidence_put(
            self.policy.engagement_id, frame, job_id=job["id"], kind="network_native_result"
        )
        with self.store.transaction() as db:
            self._running(job, spec)
            db.execute(
                "INSERT INTO rj_network_native_proof VALUES(?,?,?,?,?,?,?,NULL,NULL,NULL)",
                (
                    self.policy.engagement_id,
                    job["id"],
                    job["attempt"],
                    job["owner"],
                    json_text(asdict(spec)),
                    ref,
                    stable_key(frame),
                ),
            )
        self.pending = (job, broker, ref)
        return ref

    def seal(self, job: dict[str, Any], spec: JobSpec, transport_ref: str) -> tuple[str, str]:
        self._running(job, spec)
        pending = self.pending
        if pending is None or pending[0] != job:
            raise NetworkProofDenied("network_observation_owned_capture_required")
        broker, native_ref = pending[1:]
        guard = getattr(self.runner, "resource_cleanup_verified", None)
        if (
            not callable(guard)
            or guard() is not True
            or not broker.closed
            or broker.tasks
            or broker.writers
            or broker.server is not None
            or self.runner.broker is not None
            or self.runner.boundary is not None
            or self.runner.workspace is not None
            or self.runner.payload is not None
        ):
            raise NetworkProofDenied("network_observation_verified_cleanup_required")
        with self.store._lock:
            native, digest, _created = owned_evidence(
                self.store.db,
                self.policy.engagement_id,
                job["id"],
                native_ref,
                "network_native_result",
            )
            transport, transport_digest, _ = owned_evidence(
                self.store.db,
                self.policy.engagement_id,
                job["id"],
                transport_ref,
                self.engine
                + ("_service_transport" if self.engine == "nmap" else "_network_transport"),
            )
        final = counters(broker)
        if (
            transport.get("admission_closed") is not True
            or final != native["transport"]
            or any(transport.get(key) != value for key, value in final.items())
            or transport.get("binary_sha256") != native["binary_sha256"]
            or transport.get("tool_version") != native["tool_version"]
        ):
            raise NetworkProofDenied("network_observation_final_transport_mismatch")
        value = {
            "schema": VERSION,
            "job_id": job["id"],
            "attempt": job["attempt"],
            "owner": job["owner"],
            "native_ref": native_ref,
            "native_digest": digest,
            "transport_ref": transport_ref,
            "transport_digest": transport_digest,
            "cleanup_verified": True,
        }
        seal_ref = self.store.evidence_put(
            self.policy.engagement_id,
            value,
            job_id=job["id"],
            kind="network_native_cleanup_seal",
        )
        with self.store.transaction() as db:
            self._running(job, spec)
            changed = db.execute(
                "UPDATE rj_network_native_proof SET seal_ref=?,seal_digest=?,transport_ref=? "
                "WHERE engagement=? AND job_id=? AND attempt=? AND seal_ref IS NULL",
                (
                    seal_ref,
                    stable_key(value),
                    transport_ref,
                    self.policy.engagement_id,
                    job["id"],
                    job["attempt"],
                ),
            ).rowcount
            if changed != 1:
                raise NetworkProofDenied("network_observation_duplicate_or_stale_seal")
        self.pending = None
        return native_ref, seal_ref


def _verify_nmap_prerequisite(
    db: sqlite3.Connection,
    store: AssessmentStore,
    policy: EngagementPolicy,
    surface: Surface,
    evidence_ref: str,
) -> None:
    if not isinstance(evidence_ref, str) or not 1 <= len(evidence_ref) <= 128:
        raise PolicyDenied("nmap_current_open_observation_required")
    row = db.execute(
        "SELECT e.payload,e.created_at,j.spec,j.result,j.surface_id FROM rj_evidence e "
        "JOIN rj_job j ON j.id=e.job_id AND j.engagement=e.engagement "
        "WHERE e.id=? AND e.engagement=? AND e.kind='naabu_network' "
        "AND j.execution_status='succeeded' AND j.coverage_status='completed'",
        (evidence_ref, policy.engagement_id),
    ).fetchone()
    if row is None or not time.time() - 300 <= row[1] <= time.time():
        raise PolicyDenied("nmap_current_open_observation_required")
    producer = json.loads(row[2])
    result = json.loads(row[3])
    proof = json.loads(row[0])
    prior_row = db.execute(
        "SELECT payload FROM rj_surface WHERE engagement=? AND id=?",
        (policy.engagement_id, row[4]),
    ).fetchone()
    if prior_row is None:
        raise PolicyDenied("nmap_open_observation_identity_mismatch")
    prior = Surface(**json.loads(prior_row[0]))
    observation = proof.get("observation", {})
    if (
        producer.get("capability") != "naabu_ports"
        or producer.get("policy_revision") != policy.revision
        or evidence_ref not in result.get("summary", {}).get("evidence_refs", [])
        or prior.resource_kind != "network_endpoint"
        or prior.asset_ref != surface.asset_ref
        or (prior.network_address, prior.network_port)
        != (surface.network_address, surface.network_port)
        or proof.get("tool") != "naabu"
        or proof.get("tool_version") != "2.6.1"
        or proof.get("connected", 0) < 1
        or proof.get("refused", 0) != 0
        or observation
        != {"address": surface.network_address, "port": surface.network_port, "state": "open"}
    ):
        raise PolicyDenied("nmap_open_observation_identity_mismatch")
    store.inventory.require_surface_active(db, policy, row[4])


def commit_service_inventory(  # noqa: PLR0911, PLR0912, PLR0915 - explicit atomic proof gates
    store: AssessmentStore,
    db: sqlite3.Connection,
    job: sqlite3.Row | dict[str, Any],
    result: Any,
) -> bool:
    """Promote an imported TCP service to observed only from sealed native+transport proof."""
    schema_db(db)
    proof = db.execute(
        "SELECT owner,spec,native_ref,native_digest,seal_ref,seal_digest,transport_ref "
        "FROM rj_network_native_proof WHERE engagement=? AND job_id=? AND attempt=?",
        (job["engagement"], job["id"], job["attempt"]),
    ).fetchone()
    if (
        proof is None
        or proof["owner"] != job["owner"]
        or proof["spec"] != job["spec"]
        or not proof["seal_ref"]
        or not proof["seal_digest"]
        or not proof["transport_ref"]
    ):
        return False
    try:
        from redjohn.assessment.policy import EngagementPolicy  # noqa: PLC0415

        eng = db.execute(
            "SELECT policy,owner,revision,stopped FROM rj_engagement WHERE id=?",
            (job["engagement"],),
        ).fetchone()
        if eng is None or eng["stopped"]:
            return False
        policy = EngagementPolicy.from_mapping(json.loads(eng["policy"]))
        if eng["owner"] != policy.owner_id or eng["revision"] != policy.revision:
            return False
        spec = JobSpec(**json.loads(job["spec"]))
        if (
            spec.capability != job["capability"]
            or spec.capability not in {"naabu_ports", "nmap_services"}
            or spec.policy_revision != policy.revision
            or not spec.idempotent
            or spec.surface_id != job["surface_id"]
        ):
            return False
        surface_row = db.execute(
            "SELECT payload FROM rj_surface WHERE engagement=? AND id=?",
            (policy.engagement_id, spec.surface_id),
        ).fetchone()
        if surface_row is None:
            return False
        surface = Surface(**json.loads(surface_row[0]))
        if surface.resource_kind != "network_endpoint" or surface.actor_id != "anonymous":
            return False
        policy.check_surface(surface)
        asset = store.inventory._get_asset(db, policy, surface.asset_ref)
        if (
            asset["kind"] != "ip_address"
            or asset["state"] != "active"
            or asset["locator"] != surface.network_address
        ):
            return False
        store.inventory.require_surface_active(db, policy, spec.surface_id)
        engine = "nmap" if spec.capability == "nmap_services" else "naabu"
        native, native_digest, _ = owned_evidence(
            db,
            policy.engagement_id,
            job["id"],
            proof["native_ref"],
            "network_native_result",
            proof["native_digest"],
        )
        seal, _, _ = owned_evidence(
            db,
            policy.engagement_id,
            job["id"],
            proof["seal_ref"],
            "network_native_cleanup_seal",
            proof["seal_digest"],
        )
        transport_kind = (
            "nmap_service_transport" if engine == "nmap" else "naabu_network_transport"
        )
        transport, transport_digest, _ = owned_evidence(
            db,
            policy.engagement_id,
            job["id"],
            proof["transport_ref"],
            transport_kind,
        )
        expected_seal = {
            "schema": VERSION,
            "job_id": job["id"],
            "attempt": job["attempt"],
            "owner": job["owner"],
            "native_ref": proof["native_ref"],
            "native_digest": native_digest,
            "transport_ref": proof["transport_ref"],
            "transport_digest": transport_digest,
            "cleanup_verified": True,
        }
        if (
            seal != expected_seal
            or native.get("schema") != VERSION
            or native.get("job_id") != job["id"]
            or native.get("attempt") != job["attempt"]
            or native.get("owner") != job["owner"]
            or native.get("spec") != asdict(spec)
            or native.get("surface") != asdict(surface)
            or native.get("engine") != engine
            or transport.get("admission_closed") is not True
            or transport.get("binary_sha256") != native.get("binary_sha256")
            or transport.get("tool_version") != native.get("tool_version")
        ):
            return False
        namespace_proof(native.get("namespace"))
        if not isinstance(native.get("transport"), dict) or any(
            transport.get(key) != value for key, value in native["transport"].items()
        ):
            return False
        observation = parse_native(
            engine,
            native.get("stdout", ""),
            surface,
            native["transport"],
            native.get("relay_port", ""),
        )
        if observation != native.get("observation") or observation.get("state") != "open":
            return False
        summary = result.summary if isinstance(getattr(result, "summary", None), dict) else {}
        evidence_list = summary.get("evidence_refs", [])
        if not isinstance(evidence_list, list):
            return False
        if engine == "naabu":
            if (
                getattr(result, "coverage_status", None) != "completed"
                or not evidence_list
                or not isinstance(evidence_list[0], str)
            ):
                return False
            naabu_doc, _, _ = owned_evidence(
                db, policy.engagement_id, job["id"], evidence_list[0], "naabu_network"
            )
            if naabu_doc.get("observation") != {
                "address": surface.network_address,
                "port": surface.network_port,
                "state": "open",
            }:
                return False
            refs = (
                evidence_list[0],
                proof["native_ref"],
                proof["transport_ref"],
                proof["seal_ref"],
            )
        else:
            if (
                getattr(result, "coverage_status", None) != "partial"
                or summary.get("service_observed") is not True
                or summary.get("service", {}).get("name") != observation["protocol_name"]
                or set(spec.options) != {"open_evidence_ref"}
            ):
                return False
            open_ref = spec.options["open_evidence_ref"]
            _verify_nmap_prerequisite(db, store, policy, surface, open_ref)
            refs = (
                open_ref,
                proof["native_ref"],
                proof["transport_ref"],
                proof["seal_ref"],
            )
    except (NetworkProofDenied, PolicyDenied, ValueError, TypeError, KeyError):
        return False
    if (
        db.execute(
            "SELECT count(*) FROM rj_network_service_observation WHERE engagement=?",
            (policy.engagement_id,),
        ).fetchone()[0]
        >= MAX_PROOFS
    ):
        raise CapacityExceeded("network_observation_service_quota")
    service_id = store.inventory._service(
        db, policy, surface.asset_ref, "tcp", int(surface.network_port), "observed", refs
    )
    obs_id = stable_key([policy.engagement_id, job["id"], job["attempt"], service_id])
    payload = {
        "schema": VERSION,
        "engagement_id": policy.engagement_id,
        "job_id": job["id"],
        "attempt": job["attempt"],
        "capability": spec.capability,
        "engine": engine,
        "asset_id": surface.asset_ref,
        "service_id": service_id,
        "address": surface.network_address,
        "port": int(surface.network_port),
        "protocol": "tcp",
        "state": "open",
        "protocol_name": observation["protocol_name"],
        "service_label": (
            {"ssh": "SSH service", "http": "HTTP service"}.get(observation["protocol_name"] or "")
        ),
        "product_version_status": (
            "not_determined_by_narrow_profile" if engine == "nmap" else "not_probed_by_port_scan"
        ),
        "evidence_refs": list(refs),
        "native_ref": proof["native_ref"],
        "transport_ref": proof["transport_ref"],
        "seal_ref": proof["seal_ref"],
        "observed_at": time.time(),
    }
    db.execute(
        "INSERT INTO rj_network_service_observation VALUES(?,?,?,?,?,?)",
        (
            obs_id,
            policy.engagement_id,
            job["id"],
            job["attempt"],
            service_id,
            json_text(payload),
        ),
    )
    store._audit(
        db,
        policy.engagement_id,
        "network_service_observed",
        {
            "job_id": job["id"],
            "attempt": job["attempt"],
            "service_id": service_id,
            "engine": engine,
            "protocol_name": observation["protocol_name"],
        },
        f"net-obs:{job['id']}:{job['attempt']}",
    )
    return True


def service_observations(
    store: AssessmentStore,
    policy: EngagementPolicy,
    *,
    service_id: str = "",
    limit: int = 50,
    after: str = "",
) -> list[dict[str, Any]]:
    store.inventory._page(limit, after)
    schema(store)
    with store._lock:
        store.inventory._fence(store.db, policy)
        rows = store.db.execute(
            "SELECT id,job_id,attempt,service_id,payload FROM rj_network_service_observation "
            "WHERE engagement=? AND id>? AND (?='' OR service_id=?) ORDER BY id LIMIT ?",
            (policy.engagement_id, after, service_id, service_id, limit),
        ).fetchall()
    return [
        {
            "id": row["id"],
            "job_id": row["job_id"],
            "attempt": row["attempt"],
            "service_id": row["service_id"],
            "payload": json.loads(row["payload"]),
        }
        for row in rows
    ]

