/** Mappers: generated contract types → @redjohn/ui view models. */
import type { AgentRow, FindingRow } from "@redjohn/ui";
import type { Agent, Finding } from "./api";

export function toAgentRow(a: Agent): AgentRow {
  return {
    agentId: a.agent_id,
    name: a.name,
    role: a.role,
    activity: a.current_activity || a.task,
    status: a.status,
    target: a.allowed_targets?.[0],
    handle: shortHandle(a.agent_id),
  };
}

export function toFindingRow(f: Finding, agentName?: string): FindingRow {
  return {
    findingId: f.finding_id,
    severity: f.severity,
    status: f.status,
    title: f.title,
    description: f.description,
    target: f.target,
    agentName,
    createdAt: f.created_at,
  };
}

/** "agent-03"-style short handle from an agent id. */
export function shortHandle(agentId: string): string {
  const m = /(\d+)$/.exec(agentId);
  if (m) return `agent-${m[1]!.padStart(2, "0")}`;
  return agentId.slice(0, 8);
}
