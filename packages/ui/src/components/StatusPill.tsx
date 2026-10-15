import type { ReactNode } from "react";
import { cn } from "../utils.js";
import { strings } from "../strings.js";
import type { AgentStatus, FindingSeverity, RunStatus, ServiceState } from "../types.js";

type Tone = "live" | "busy" | "idle" | "down" | "neutral";

const toneClasses: Record<Tone, { wrap: string; dot: string; icon: ReactNode }> = {
  live: {
    wrap: "bg-rj-live/10 text-rj-live border-rj-live/30",
    dot: "bg-rj-live",
    icon: null,
  },
  busy: {
    wrap: "bg-rj-starting/10 text-rj-starting border-rj-starting/30",
    dot: "bg-rj-starting",
    icon: null,
  },
  idle: {
    wrap: "bg-rj-idle/10 text-rj-text-2 border-rj-idle/30",
    dot: "bg-rj-idle",
    icon: null,
  },
  down: {
    wrap: "bg-rj-down/10 text-rj-down border-rj-down/30",
    dot: "bg-rj-down",
    icon: null,
  },
  neutral: {
    wrap: "bg-rj-idle/10 text-rj-text-2 border-rj-border-strong",
    dot: "bg-rj-text-3",
    icon: null,
  },
};

const serviceTone: Record<ServiceState, Tone> = {
  live: "live",
  starting: "busy",
  degraded: "busy",
  down: "down",
  not_configured: "neutral",
};

const agentTone: Record<AgentStatus, Tone> = {
  running: "live",
  waiting: "live",
  queued: "busy",
  pending: "busy",
  complete: "idle",
  stopped: "idle",
  failed: "down",
};

const runTone: Record<RunStatus, Tone> = {
  running: "live",
  starting: "busy",
  created: "busy",
  stopping: "busy",
  stopped: "idle",
  completed: "idle",
  failed: "down",
};

export interface StatusPillProps {
  state: ServiceState | AgentStatus | RunStatus;
  kind?: "service" | "agent" | "run";
  /** Override the displayed label. */
  label?: string;
  size?: "sm" | "md";
  className?: string;
}

/**
 * Status pill — dot + label (+ distinct tone). Never color alone:
 * the textual label is always visible.
 */
export function StatusPill({ state, kind = "service", label, size = "md", className }: StatusPillProps) {
  const tone =
    (kind === "service"
      ? serviceTone[state as ServiceState]
      : kind === "agent"
        ? agentTone[state as AgentStatus]
        : runTone[state as RunStatus]) ?? "neutral";
  const text = label ?? (strings.status as Record<string, string>)[state] ?? state;
  // The engine is a separately-versioned process; an unknown/forward state must
  // render as a neutral pill, never crash the renderer (there is no boundary).
  const c = toneClasses[tone] ?? toneClasses.neutral;
  return (
    <span
      role="status"
      aria-label={`${kind} status: ${text}`}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border font-medium whitespace-nowrap",
        size === "sm" ? "px-1.5 py-px text-[10px]" : "px-2 py-0.5 text-[11px]",
        c.wrap,
        className,
      )}
    >
      <span aria-hidden="true" className={cn("inline-block rounded-full", size === "sm" ? "size-1" : "size-1.5", c.dot)} />
      {text}
    </span>
  );
}

const severityClasses: Record<FindingSeverity, string> = {
  critical: "bg-rj-critical/15 text-rj-critical border-rj-critical/40",
  high: "bg-rj-high/15 text-rj-high border-rj-high/40",
  medium: "bg-rj-medium/15 text-rj-medium border-rj-medium/40",
  low: "bg-rj-low/15 text-rj-low border-rj-low/40",
  info: "bg-rj-info/15 text-rj-info border-rj-info/40",
};

export function SeverityPill({ severity, className }: { severity: FindingSeverity; className?: string }) {
  const label = severity.charAt(0).toUpperCase() + severity.slice(1);
  return (
    <span
      aria-label={`severity: ${label}`}
      className={cn(
        "inline-flex items-center rounded border px-1.5 py-px text-[10px] font-semibold uppercase tracking-wide whitespace-nowrap",
        severityClasses[severity],
        className,
      )}
    >
      {label}
    </span>
  );
}
