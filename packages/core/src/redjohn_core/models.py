"""Canonical RedJohn domain models (contract anchor).

Single source of truth for the RedJohn API contract ``v1`` and the RunEvent
envelope. rj-cli, rj-desktop (via generated TS client) and rj-cloud all bind
to these models. Changes here are contract changes: bump CONTRACT_VERSION in
this package and regenerate ``rj-cli/contracts/*`` via the schema exporter.

No TUI/Electron/Next.js/Stripe imports allowed in this package.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


def utcnow() -> datetime:
    return datetime.now(UTC)


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:24]}"


class RJModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RunStatus(str, Enum):
    CREATED = "created"        # configured, not started
    STARTING = "starting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"        # stopped by user
    COMPLETED = "completed"
    FAILED = "failed"


class AgentStatus(str, Enum):
    PENDING = "pending"        # created, capacity not yet reserved
    QUEUED = "queued"          # waiting for capacity slot
    RUNNING = "running"
    WAITING = "waiting"        # blocked on child agent / evidence / dependency
    COMPLETE = "complete"
    FAILED = "failed"
    STOPPED = "stopped"


class AgentRole(str, Enum):
    COORDINATOR = "coordinator"
    SPECIALIST = "specialist"
    WORKER = "worker"


class MessageStatus(str, Enum):
    QUEUED = "queued"
    DELIVERED = "delivered"
    READ = "read"
    FAILED = "failed"


class ToolInvocationStatus(str, Enum):
    STARTED = "started"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    UNKNOWN = "unknown"        # executor lost track; never silently retried


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OBSERVATION = "observation"    # raw observation, no claim
    SUSPECTED = "suspected"        # suspected issue, unverified
    VERIFIED = "verified"          # verified finding with evidence
    READY_FOR_REVIEW = "ready_for_review"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class TargetKind(str, Enum):
    DOMAIN = "domain"
    URL = "url"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    HOSTNAME = "hostname"
    LOCAL_PROJECT = "local_project"
    GITHUB_REPOSITORY = "github_repository"


class PentestTargetKind(str, Enum):
    LOCAL_PROJECT = "local_project"
    GITHUB_REPOSITORY = "github_repository"
    WEB_APPLICATION = "web_application"


class ScanMode(str, Enum):
    LOW = "low"
    STANDARD = "standard"
    HIGH = "high"
    DEEP = "deep"


class VerificationStatus(str, Enum):
    UNVERIFIED = "unverified"
    PENDING = "pending"
    VERIFIED = "verified"
    REJECTED = "rejected"


class ServiceState(str, Enum):
    LIVE = "live"                      # fresh, authorized, usable connection
    STARTING = "starting"
    DEGRADED = "degraded"
    DOWN = "down"
    NOT_CONFIGURED = "not_configured"


class MCPTransport(str, Enum):
    STDIO = "stdio"
    STREAMABLE_HTTP = "streamable_http"


class SkillEnvironment(str, Enum):
    LOCAL = "local"
    CLOUD_WORKER = "cloud_worker"
    ANY = "any"


class RunEnvironment(str, Enum):
    LOCAL = "local"                    # rj-cli / rj-desktop local engine
    CLOUD_MANAGED = "cloud_managed"    # provider-managed cloud worker


# ---------------------------------------------------------------------------
# Core resources
# ---------------------------------------------------------------------------

class Workspace(RJModel):
    workspace_id: str = Field(default_factory=lambda: new_id("ws"))
    name: str
    slug: str
    kind: Literal["local", "cloud"] = "local"
    created_at: datetime = Field(default_factory=utcnow)


class Project(RJModel):
    project_id: str = Field(default_factory=lambda: new_id("prj"))
    workspace_id: str
    name: str
    description: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class Target(RJModel):
    target_id: str = Field(default_factory=lambda: new_id("tgt"))
    project_id: str
    value: str                          # e.g. app.acme.test, 192.168.1.10
    kind: TargetKind
    verification: VerificationStatus = VerificationStatus.UNVERIFIED
    note: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class ScopePolicy(RJModel):
    """Versioned, run-pinned scope. A running run's scope cannot be expanded
    by the model; only a new version + explicit user action creates changes."""
    scope_id: str = Field(default_factory=lambda: new_id("scp"))
    project_id: str
    version: int = 1
    allowed_targets: list[str] = Field(default_factory=list)  # values or CIDRs
    allowed_tools: list[str] = Field(default_factory=list)    # server-qualified
    denied_tools: list[str] = Field(default_factory=list)
    max_agents: int = 24
    max_concurrent_agents: int = 6
    max_depth: int = 3
    notes: str = ""
    created_at: datetime = Field(default_factory=utcnow)


class AgentLimits(RJModel):
    """Hard defaults from the product spec; cloud clamps further by plan."""
    max_concurrent_agents: int = 6
    max_total_agents: int = 24
    max_delegation_depth: int = 3      # coordinator depth is 0
    time_budget_seconds: int | None = None
    token_budget: int | None = None


class Run(RJModel):
    run_id: str = Field(default_factory=lambda: new_id("run"))
    workspace_id: str
    project_id: str
    name: str
    ref: str = ""                      # short human ref, e.g. "RJ-024" (per-workspace sequence)
    task: str = ""                     # user task description
    scan_mode: ScanMode = ScanMode.STANDARD
    authorized_target: str | None = None
    target_kind: PentestTargetKind | None = None
    session_project: bool = False      # project belongs only to this desktop session
    archived_at: datetime | None = None
    status: RunStatus = RunStatus.CREATED
    scope: ScopePolicy                 # pinned snapshot at creation
    limits: AgentLimits = Field(default_factory=AgentLimits)
    environment: RunEnvironment = RunEnvironment.LOCAL
    idempotency_key: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None


class Agent(RJModel):
    agent_id: str = Field(default_factory=lambda: new_id("agt"))
    run_id: str
    parent_agent_id: str | None = None
    role: AgentRole = AgentRole.SPECIALIST
    name: str                          # display name, e.g. "Web"
    task: str
    status: AgentStatus = AgentStatus.PENDING
    depth: int = 0                     # coordinator = 0
    allowed_targets: list[str] = Field(default_factory=list)  # ⊆ parent scope
    allowed_tools: list[str] = Field(default_factory=list)    # ⊆ parent tools
    time_budget_seconds: int | None = None
    token_budget: int | None = None
    current_activity: str = ""
    ov_session_uri: str | None = None  # OpenViking session reference
    seq_cursor: int = 0                # last event seq emitted for this agent
    created_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None


class AgentMessage(RJModel):
    message_id: str = Field(default_factory=lambda: new_id("msg"))
    run_id: str
    from_agent_id: str                 # "user" for operator-originated
    to_agent_id: str                   # explicit recipient; no implicit fan-out
    correlation_id: str | None = None
    kind: Literal["instruction", "result", "query", "broadcast"] = "instruction"
    body: str
    summary_ref: str | None = None     # short result summary for sharing
    evidence_refs: list[str] = Field(default_factory=list)
    status: MessageStatus = MessageStatus.QUEUED
    idempotency_key: str | None = None  # sender-supplied dedup key
    created_at: datetime = Field(default_factory=utcnow)
    delivered_at: datetime | None = None


class ToolInvocation(RJModel):
    invocation_id: str = Field(default_factory=lambda: new_id("inv"))
    run_id: str
    agent_id: str
    tool: str                          # server-qualified: "mcp:<conn>:<tool>" or "builtin:<name>"
    args: dict[str, Any] = Field(default_factory=dict)  # structured, never shell string
    status: ToolInvocationStatus = ToolInvocationStatus.STARTED
    attempt: int = 1
    exit_code: int | None = None
    output_ref: str | None = None      # evidence id of captured output
    evidence_refs: list[str] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    error: str | None = None


class TerminalSession(RJModel):
    terminal_id: str = Field(default_factory=lambda: new_id("trm"))
    run_id: str
    agent_id: str | None = None
    kind: Literal["agent_log", "pty"] = "agent_log"
    authorized_user: str | None = None  # pty stdin requires explicit grant
    cols: int = 80
    rows: int = 24
    created_at: datetime = Field(default_factory=utcnow)
    closed_at: datetime | None = None


class Finding(RJModel):
    finding_id: str = Field(default_factory=lambda: new_id("fnd"))
    run_id: str
    code: str                          # human code, e.g. "F-008" (per-run sequence)
    title: str
    severity: FindingSeverity
    status: FindingStatus = FindingStatus.OBSERVATION
    target: str = ""
    source_agent_id: str | None = None
    description: str = ""
    evidence_refs: list[str] = Field(default_factory=list)
    remediation: str = ""
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class Evidence(RJModel):
    evidence_id: str = Field(default_factory=lambda: new_id("evd"))
    run_id: str
    sha256: str
    mime: str
    size_bytes: int
    source: str                        # tool invocation / agent / upload
    storage_ref: str                   # local file key or object key
    access: Literal["workspace", "run", "restricted"] = "run"
    redacted: bool = False
    created_at: datetime = Field(default_factory=utcnow)


class SkillRef(RJModel):
    skill_id: str = Field(default_factory=lambda: new_id("skl"))
    name: str
    version: str
    description: str = ""
    source: str = ""                   # repo/package origin
    ov_uri: str | None = None          # OpenViking content URI (runtime store)
    content_hash: str = ""
    required_tools: list[str] = Field(default_factory=list)
    environments: list[SkillEnvironment] = Field(default_factory=lambda: [SkillEnvironment.ANY])
    input_schema: dict[str, Any] = Field(default_factory=dict)
    output_schema: dict[str, Any] = Field(default_factory=dict)
    execution_rules: str = ""          # human rules; NOT an authorization grant


class MCPConnection(RJModel):
    mcp_id: str = Field(default_factory=lambda: new_id("mcp"))
    name: str
    transport: MCPTransport
    command: list[str] = Field(default_factory=list)   # stdio
    env: dict[str, str] = Field(default_factory=dict)  # stdio (secrets redacted)
    url: str | None = None                               # streamable_http
    status: ServiceState = ServiceState.NOT_CONFIGURED
    tools: list[str] = Field(default_factory=list)     # qualified "mcp:<name>:<tool>"
    error: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class ServiceStatus(RJModel):
    service: str                       # "api" | "openviking" | "mcp:<id>" | "worker" | "billing"
    state: ServiceState
    detail: str = ""
    latency_ms: int | None = None
    checked_at: datetime = Field(default_factory=utcnow)


class Report(RJModel):
    report_id: str = Field(default_factory=lambda: new_id("rpt"))
    run_id: str
    format: Literal["html", "json", "pdf"] = "html"
    storage_ref: str = ""
    created_at: datetime = Field(default_factory=utcnow)


# ---------------------------------------------------------------------------
# API envelopes
# ---------------------------------------------------------------------------

class ErrorBody(RJModel):
    code: str                          # typed, e.g. "scope_violation"
    message: str
    details: dict[str, Any] = Field(default_factory=dict)
    request_id: str | None = None


class ErrorResponse(RJModel):
    error: ErrorBody


class ListPage(RJModel):
    """Cursor pagination envelope; never trust client ordering."""
    items: list[Any]
    next_cursor: str | None = None
    total: int | None = None
