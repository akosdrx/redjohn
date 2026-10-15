/**
 * useRunStream: hydrates from the snapshot, then applies live RunEvents.
 *  - Updates TanStack Query caches (run / agents / findings / status).
 *  - Feeds terminal chunks + synthesized activity lines into LiveTerminal.
 */
import { useEffect, useRef } from "react";
import { useQueryClient, type QueryClient } from "@tanstack/react-query";
import { colors, formatLogLine, type AgentRow } from "@redjohn/ui";
import type { Agent, ApiClient, Finding, Run, RunEvent, RunSnapshot } from "./api";
import { ApiError } from "./api";
import { RunStream, type StreamState } from "./ws";
import { toAgentRow } from "./mappers";

export const qk = {
  runs: ["runs"] as const,
  run: (id: string) => ["run", id] as const,
  agents: (id: string) => ["agents", id] as const,
  findings: (id: string) => ["findings", id] as const,
  status: ["status"] as const,
};

export function agentSgrTag(agentName: string, colorHex: string): string {
  const rgb = hexToRgb(colorHex);
  if (!rgb) return agentName.toUpperCase();
  const [r, g, b] = rgb;
  return `\x1b[38;2;${r};${g};${b}m${agentName.toUpperCase()}\x1b[0m`;
}

function hexToRgb(hex: string): [number, number, number] | null {
  const m = /^#([0-9a-f]{6})$/i.exec(hex);
  if (!m) return null;
  const v = parseInt(m[1]!, 16);
  return [(v >> 16) & 255, (v >> 8) & 255, v & 255];
}

export function colorForAgent(agentId: string, agents: AgentRow[]): string {
  const idx = agents.findIndex((a) => a.agentId === agentId);
  return colors.agentTags[(idx < 0 ? 0 : idx) % colors.agentTags.length]!;
}

/* ------------------------- event data parsers ------------------------- */
/* The contract types `data` as a generic object; these guards narrow the  */
/* shapes defined in rj-cli/contracts/run-event.schema.json.               */

function asRecord(x: unknown): Record<string, unknown> | null {
  return typeof x === "object" && x !== null ? (x as Record<string, unknown>) : null;
}

export function terminalChunk(ev: RunEvent): { agentId: string | null; chunk: string } | null {
  if (ev.type !== "terminal.output") return null;
  const d = asRecord(ev.data);
  const chunk = d?.chunk;
  if (typeof chunk !== "string") return null;
  const agentId = typeof d?.agent_id === "string" ? d.agent_id : (ev.agent_id ?? null);
  return { agentId, chunk };
}

export function toolOutputChunk(ev: RunEvent): { agentId: string | null; chunk: string } | null {
  if (ev.type !== "tool.invocation.output") return null;
  const d = asRecord(ev.data);
  const chunk = d?.chunk;
  if (typeof chunk !== "string" || !chunk) return null;
  return { agentId: ev.agent_id ?? null, chunk };
}

const INTERNAL_ACTIVITIES = new Set([
  "memory message synchronized",
  "memory session created",
  "OpenViking memory synchronized",
]);

function isInternalActivity(d: Record<string, unknown>): boolean {
  if (d.internal === true) return true;
  const act =
    typeof d.activity === "string"
      ? d.activity
      : typeof d.current_activity === "string"
        ? d.current_activity
        : "";
  if (INTERNAL_ACTIVITIES.has(act)) return true;
  if (/^model turn \d+$/i.test(act)) return true;
  return false;
}

function formatToolStart(tool: string, args: unknown): string {
  const a = asRecord(args);
  if (!a) return `▶ ${tool}`;
  if (tool === "builtin:exec" && Array.isArray(a.argv)) {
    return `▶ ${tool} $ ${a.argv.map(String).join(" ")}`;
  }
  if (tool === "builtin:http_get" && typeof a.url === "string") {
    return `▶ ${tool} GET ${a.url}`;
  }
  const entries = Object.entries(a)
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .slice(0, 4)
    .map(([k, v]) => {
      const raw = typeof v === "string" ? v : JSON.stringify(v);
      const short = raw.length > 100 ? `${raw.slice(0, 100)}…` : raw;
      return `${k}=${short}`;
    });
  return entries.length > 0 ? `▶ ${tool} (${entries.join(", ")})` : `▶ ${tool}`;
}

function activityLine(ev: RunEvent): { agentId: string | null; text: string } | null {
  const d = asRecord(ev.data) ?? {};
  const agentId = ev.agent_id ?? (typeof d.agent_id === "string" ? d.agent_id : null);
  switch (ev.type) {
    case "agent.activity": {
      if (isInternalActivity(d)) return null;
      const text =
        typeof d.message === "string" && d.message.trim()
          ? d.message
          : typeof d.current_activity === "string" && d.current_activity.trim()
            ? d.current_activity
            : typeof d.activity === "string" && d.activity.trim()
              ? d.activity
              : null;
      return text ? { agentId, text } : null;
    }
    case "agent.status": {
      const status = typeof d.status === "string" ? d.status : null;
      return status ? { agentId, text: `status → ${status}` } : null;
    }
    case "tool.invocation.started": {
      const tool = typeof d.tool === "string" ? d.tool : "tool";
      return { agentId, text: formatToolStart(tool, d.args) };
    }
    case "tool.invocation.completed": {
      const tool = typeof d.tool === "string" ? d.tool : "tool";
      const status = typeof d.status === "string" ? d.status : "completed";
      const exitCode = typeof d.exit_code === "number" ? ` (exit ${d.exit_code})` : "";
      const err = typeof d.error === "string" && d.error ? ` — ${d.error}` : "";
      return { agentId, text: `■ ${tool} ${status}${exitCode}${err}` };
    }
    case "finding.created": {
      const title = typeof d.title === "string" ? d.title : "finding";
      const sev = typeof d.severity === "string" ? d.severity : "";
      return { agentId, text: `Finding [${sev.toUpperCase()}] ${title}` };
    }
    case "agent.message": {
      const from = typeof d.from_agent_id === "string" ? d.from_agent_id : "?";
      const to = typeof d.to_agent_id === "string" ? d.to_agent_id : "?";
      const body = typeof d.body === "string" ? d.body : "";
      return body ? { agentId, text: `✉ ${from} → ${to}: ${body}` } : null;
    }
    default:
      return null;
  }
}

export const TERMINAL_HISTORY_EVENT_WINDOW = 2000;
const HISTORY_PAGE_SIZE = 200; // The engine's maximum REST event page.
const MAX_REPLAY_CHARACTERS = 2 * 1024 * 1024;

interface TerminalOutput {
  agentId: string | null;
  chunk: string;
}

function terminalOutput(ev: RunEvent, agents: AgentRow[]): TerminalOutput | null {
  const raw = terminalChunk(ev) ?? toolOutputChunk(ev);
  if (raw) return raw;
  const line = activityLine(ev);
  if (!line) return null;
  const name = agentName(line.agentId, agents);
  const color = colorForAgent(line.agentId ?? "", agents);
  // Pass the plain name; formatLogLine pads/truncates it, then colorizes the
  // result — colorizing first would be mangled by its uppercase/slice.
  const chunk = `${formatLogLine(ev.occurred_at, name, line.text, (tag) => agentSgrTag(tag, color))}\n`;
  return { agentId: line.agentId, chunk };
}

/** Keep recent replay output bounded even when an individual tool emits a huge chunk. */
class TerminalReplayBuffer {
  items: TerminalOutput[] = [];
  truncated = false;
  private characters = 0;

  append(output: TerminalOutput): void {
    this.items.push(output);
    this.characters += output.chunk.length;
    while (this.items.length > TERMINAL_HISTORY_EVENT_WINDOW || this.characters > MAX_REPLAY_CHARACTERS) {
      const first = this.items[0]!;
      const excess = this.characters - MAX_REPLAY_CHARACTERS;
      this.truncated = true;
      if (this.items.length <= TERMINAL_HISTORY_EVENT_WINDOW && excess < first.chunk.length) {
        this.items[0] = { ...first, chunk: first.chunk.slice(excess) };
        this.characters -= excess;
      } else {
        this.items.shift();
        this.characters -= first.chunk.length;
      }
    }
  }
}

/** Read a bounded tail through the captured snapshot cursor, never replaying old cache state. */
export async function recentTerminalHistory(
  api: ApiClient,
  runId: string,
  throughSeq: number,
  agents: () => AgentRow[],
  stopped: () => boolean,
): Promise<{ items: TerminalOutput[]; truncated: boolean }> {
  const buffer = new TerminalReplayBuffer();
  let afterSeq = Math.max(0, throughSeq - TERMINAL_HISTORY_EVENT_WINDOW);
  const seen = new Set<string>();
  // One extra request permits recovering a retained-history starting cursor.
  for (let pageIndex = 0; pageIndex <= TERMINAL_HISTORY_EVENT_WINDOW / HISTORY_PAGE_SIZE; pageIndex++) {
    if (stopped() || afterSeq >= throughSeq) break;
    let page: Awaited<ReturnType<ApiClient["getRunEvents"]>>;
    try {
      page = await api.getRunEvents(runId, afterSeq, HISTORY_PAGE_SIZE);
    } catch (error) {
      const available = error instanceof ApiError ? error.details?.min_available_seq : undefined;
      if (error instanceof ApiError && error.status === 410 && typeof available === "number" && available > afterSeq + 1) {
        afterSeq = available - 1;
        buffer.truncated = true;
        continue;
      }
      throw error;
    }
    if (stopped()) break;
    const before = afterSeq;
    for (const ev of [...page.items].sort((a, b) => a.seq - b.seq)) {
      if (ev.run_id !== runId || ev.seq <= afterSeq || ev.seq > throughSeq) continue;
      afterSeq = ev.seq;
      if (seen.has(ev.event_id)) continue;
      seen.add(ev.event_id);
      const output = terminalOutput(ev, agents());
      if (output) buffer.append(output);
    }
    // `page.cursor` is the server high-water mark, not the last event of
    // this page. Never use it to skip events or include post-snapshot output.
    if (afterSeq <= before || !page.items.length) break;
  }
  return { items: buffer.items, truncated: buffer.truncated || throughSeq > TERMINAL_HISTORY_EVENT_WINDOW };
}

/* --------------------------- cache reducers --------------------------- */

export function applyEventToCaches(qc: QueryClient, runId: string, ev: RunEvent): void {
  const d = asRecord(ev.data) ?? {};
  switch (ev.type) {
    case "tool.invocation.started": {
      const agentId = ev.agent_id ?? (typeof d.agent_id === "string" ? d.agent_id : null);
      const tool = typeof d.tool === "string" ? d.tool : null;
      if (agentId && tool) {
        qc.setQueryData<{ items: Agent[] }>(qk.agents(runId), (old) =>
          old
            ? {
                items: old.items.map((a) =>
                  a.agent_id === agentId ? { ...a, current_activity: `Running ${tool}` } : a,
                ),
              }
            : old,
        );
      }
      break;
    }
    case "tool.invocation.completed": {
      void qc.invalidateQueries({ queryKey: ["evidence", runId] });
      break;
    }
    case "run.status": {
      const status = typeof d.status === "string" ? d.status : undefined;
      if (status) {
        qc.setQueryData<Run>(qk.run(runId), (old) => (old ? { ...old, status: status as Run["status"] } : old));
      }
      if ("archived_at" in d) qc.setQueryData<Run>(qk.run(runId), (old) => old ? { ...old, archived_at: typeof d.archived_at === "string" ? d.archived_at : null } : old);
      void qc.invalidateQueries({ queryKey: qk.runs });
      break;
    }
    case "agent.status":
    case "agent.activity": {
      if (ev.type === "agent.activity" && isInternalActivity(d)) break;
      const agentId = ev.agent_id ?? (typeof d.agent_id === "string" ? d.agent_id : null);
      if (!agentId) break;
      const current = qc.getQueryData<{ items: Agent[] }>(qk.agents(runId));
      if (!current?.items.some((agent) => agent.agent_id === agentId)) {
        // A status event announces new agents but need not carry the full
        // Agent contract. Fetch the authoritative row before rendering it.
        void qc.invalidateQueries({ queryKey: qk.agents(runId) });
        break;
      }
      qc.setQueryData<{ items: Agent[] }>(qk.agents(runId), (old) => {
        if (!old) return old;
        const agentId = ev.agent_id ?? (typeof d.agent_id === "string" ? d.agent_id : null);
        if (!agentId) return old;
        return {
          items: old.items.map((a) => {
            if (a.agent_id !== agentId) return a;
            const next = { ...a };
            if (typeof d.status === "string") next.status = d.status as Agent["status"];
            const activity =
              typeof d.current_activity === "string"
                ? d.current_activity
                : typeof d.activity === "string"
                  ? d.activity
                  : undefined;
            if (activity !== undefined) next.current_activity = activity;
            return next;
          }),
        };
      });
      break;
    }
    case "finding.created":
    case "finding.updated": {
      // Filtered/complete lists and artifacts have different cache keys.
      void qc.invalidateQueries({ queryKey: qk.findings(runId), predicate: (query) => query.queryKey.length > 2 });
      void qc.invalidateQueries({ queryKey: ["evidence", runId] });
      qc.setQueryData<{ items: Finding[]; next_cursor?: string | null; total?: number | null }>(
        qk.findings(runId),
        (old) => {
          if (!old) return old;
          const id = typeof d.finding_id === "string" ? d.finding_id : null;
          if (!id) return old;
          const idx = old.items.findIndex((f) => f.finding_id === id);
          const base: Finding =
            idx >= 0
              ? { ...old.items[idx]! }
              : {
                  finding_id: id,
                  run_id: runId,
                  code: typeof d.code === "string" ? d.code : "",
                  title: typeof d.title === "string" ? d.title : "",
                  severity: (typeof d.severity === "string" ? d.severity : "info") as Finding["severity"],
                  status: (typeof d.status === "string" ? d.status : "observation") as Finding["status"],
                };
          // An update for a finding outside the cached window must not fabricate
          // a phantom row or inflate the count; the invalidateQueries above will
          // refetch it. Only a genuine creation adds a new row.
          if (idx < 0 && ev.type !== "finding.created") return old;
          if (typeof d.title === "string") base.title = d.title;
          if (typeof d.severity === "string") base.severity = d.severity as Finding["severity"];
          if (typeof d.status === "string") base.status = d.status as Finding["status"];
          if (typeof d.target === "string") base.target = d.target;
          const items = idx >= 0 ? old.items.map((f, i) => (i === idx ? base : f)) : [base, ...old.items];
          return { ...old, items, total: (old.total ?? old.items.length) + (idx >= 0 ? 0 : 1) };
        },
      );
      break;
    }
    case "service.status": {
      void qc.invalidateQueries({ queryKey: qk.status });
      break;
    }
    default:
      break;
  }
}

/* ------------------------------ the hook ------------------------------ */

export interface UseRunStreamArgs {
  api: ApiClient | null;
  runId: string | null;
  snapshot: RunSnapshot | undefined;
  token: string | null;
  agents: AgentRow[];
  onTerminalWrite: (chunk: string, agentId: string | null) => void;
  onStreamState?: (state: StreamState) => void;
}

export function useRunStream({ api, runId, snapshot, token, agents, onTerminalWrite, onStreamState }: UseRunStreamArgs): void {
  const qc = useQueryClient();
  const streamRef = useRef<RunStream | null>(null);
  const agentsRef = useRef(agents);
  const writeRef = useRef(onTerminalWrite);
  const stateRef = useRef(onStreamState);
  const snapshotRef = useRef(snapshot);
  const snapshotRunId = snapshot?.run.run_id ?? null;
  useEffect(() => {
    agentsRef.current = agents;
    writeRef.current = onTerminalWrite;
    stateRef.current = onStreamState;
    snapshotRef.current = snapshot;
  }, [agents, onTerminalWrite, onStreamState, snapshot]);

  useEffect(() => {
    const initial = snapshotRef.current;
    if (!api || !runId || !initial || initial.run.run_id !== runId || !token) return;
    hydrateCaches(qc, runId, initial);
    let stopped = false;
    let loadingHistory = true;
    const pendingLive = new TerminalReplayBuffer();

    const wsBase = apiBaseToWs(api.baseUrl);
    const stream = new RunStream(
      {
        wsUrl: `${wsBase}/pentests/${encodeURIComponent(runId)}/stream`,
        token,
        wsFactory: (url, protocols) => new WebSocket(url, protocols) as never,
        replay: (afterSeq) => api.getRunEvents(runId, afterSeq),
        resnapshot: async () => {
          const snap = await api.getRunSnapshot(runId);
          hydrateCaches(qc, runId, snap);
          return { cursor: snap.cursor };
        },
        onEvent: (ev) => {
          // Defensively drop a frame for a different run before it is written
          // into THIS run's caches/terminal (the REST history path guards the
          // same way). applyEventToCaches would otherwise stamp it with runId.
          if (ev.run_id && ev.run_id !== runId) return;
          applyEventToCaches(qc, runId, ev);
          const output = terminalOutput(ev, agentsRef.current);
          if (!output) return;
          if (loadingHistory) pendingLive.append(output);
          else writeRef.current(output.chunk, output.agentId);
        },
        onState: (s) => stateRef.current?.(s),
      },
      initial.cursor,
    );
    streamRef.current = stream;
    stream.connect();
    // Connect immediately so live delivery is protected by the server's
    // replay/live handoff. Hold only terminal writes until older output is
    // ready; live cache updates must keep their latest state throughout.
    void recentTerminalHistory(api, runId, initial.cursor, () => agentsRef.current, () => stopped)
      .then((history) => {
        if (stopped) return;
        if (history.truncated) writeRef.current("[Showing recent saved terminal output.]\n", null);
        for (const output of history.items) writeRef.current(output.chunk, output.agentId);
      })
      .catch(() => {
        if (!stopped) writeRef.current("[Saved terminal output could not be loaded. Live updates will continue.]\n", null);
      })
      .finally(() => {
        if (stopped) return;
        if (pendingLive.truncated) writeRef.current("[Earlier buffered output omitted.]\n", null);
        for (const output of pendingLive.items) writeRef.current(output.chunk, output.agentId);
        loadingHistory = false;
      });
    return () => {
      stopped = true;
      stream.stop();
      streamRef.current = null;
    };
  }, [api, runId, token, snapshotRunId, qc]);
}

function agentName(agentId: string | null, agents: AgentRow[]): string {
  if (!agentId) return "sys";
  return agents.find((a) => a.agentId === agentId)?.name ?? "agent";
}

/** Derive the WS base from the client's loopback HTTP base URL. */
function apiBaseToWs(baseUrl: string): string {
  return baseUrl.replace(/^http/, "ws");
}

/** Hydrate query caches from a snapshot (initial load + 410 resync). */
export function hydrateCaches(qc: QueryClient, runId: string, snap: RunSnapshot): void {
  qc.setQueryData(qk.run(runId), snap.run);
  qc.setQueryData(qk.agents(runId), { items: snap.agents });
  if (snap.findings) {
    qc.setQueryData<{ items: Finding[]; next_cursor?: string | null; total?: number | null }>(
      qk.findings(runId),
      (old) => ({
        items: snap.findings!,
        next_cursor: old?.next_cursor ?? null,
        total: old?.total != null ? Math.max(old.total, snap.findings!.length) : snap.findings!.length,
      }),
    );
  }
}

export { toAgentRow };
