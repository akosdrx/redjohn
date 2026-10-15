/**
 * UI-facing view-model types. These intentionally mirror the API contract
 * enums (rj-cli/contracts/openapi.yaml) but keep @redjohn/ui free of any
 * generated-code or host-app dependency so the same components can be used
 * from the Electron renderer and a future Next.js app.
 */

export type ServiceState = "live" | "starting" | "degraded" | "down" | "not_configured";

export type RunStatus =
  | "created"
  | "starting"
  | "running"
  | "stopping"
  | "stopped"
  | "completed"
  | "failed";

export type AgentStatus =
  | "pending"
  | "queued"
  | "running"
  | "waiting"
  | "complete"
  | "failed"
  | "stopped";

export type AgentRole = "coordinator" | "specialist" | "worker";

export type FindingSeverity = "critical" | "high" | "medium" | "low" | "info";

export type FindingStatus =
  | "observation"
  | "suspected"
  | "verified"
  | "ready_for_review"
  | "resolved"
  | "false_positive";

export type TargetKind = "domain" | "url" | "ipv4" | "ipv6" | "cidr" | "hostname" | "local_project" | "github_repository";

export type RunEnvironment = "local" | "cloud_managed";

export interface AgentRow {
  agentId: string;
  name: string;
  role?: AgentRole | undefined;
  /** Current activity description (falls back to task). */
  activity: string;
  status: AgentStatus;
  /** Primary target label shown in the terminal header, if known. */
  target?: string | undefined;
  /** Short handle shown in the terminal, e.g. "agent-03". */
  handle?: string | undefined;
}

export interface FindingRow {
  findingId: string;
  severity: FindingSeverity;
  status: FindingStatus;
  title: string;
  description?: string | undefined;
  target?: string | undefined;
  agentName?: string | undefined;
  createdAt?: string | undefined;
}

export interface TargetRow {
  targetId: string;
  value: string;
  kind: TargetKind;
  note?: string | undefined;
  verified?: boolean | undefined;
}

export interface SkillRow {
  skillId: string;
  name: string;
  description?: string | undefined;
  version?: string | undefined;
}

export interface ServiceIndicator {
  service: string;
  state: ServiceState;
  detail?: string | undefined;
}

export interface RunSummary {
  runId: string;
  name: string;
  status: RunStatus;
  /** Short external id shown under the title, e.g. "RJ-024". */
  ref?: string | undefined;
}
