import { strings } from "../strings.js";
import type { FindingRow, FindingStatus } from "../types.js";
import { Chip } from "./primitives.js";
import { SeverityPill } from "./StatusPill.js";
import { cn } from "../utils.js";

/** Distinct visual treatment for the finding lifecycle (not color alone). */
const statusStyle: Record<FindingStatus, { label: string; className: string }> = {
  observation: { label: strings.findings.statusLabels.observation, className: "text-rj-text-3" },
  suspected: { label: strings.findings.statusLabels.suspected, className: "text-rj-medium" },
  verified: { label: strings.findings.statusLabels.verified, className: "text-rj-live" },
  ready_for_review: { label: strings.findings.statusLabels.ready_for_review, className: "text-rj-low" },
  resolved: { label: strings.findings.statusLabels.resolved, className: "text-rj-live" },
  false_positive: { label: strings.findings.statusLabels.false_positive, className: "text-rj-text-3 line-through" },
};

export function FindingStatusLabel({ status }: { status: FindingStatus }) {
  // Tolerate an unknown/forward status from the engine rather than throwing
  // during render (no error boundary exists).
  const s = statusStyle[status] ?? { label: status, className: "text-rj-text-3" };
  return <span className={cn("text-[11px] font-medium", s.className)}>{s.label}</span>;
}

export interface FindingsTableProps {
  findings: FindingRow[];
  total?: number;
  onViewAll?: () => void;
  onOpenFinding?: (findingId: string) => void;
  onTriageFinding?: (findingId: string, status: FindingStatus) => void;
  triageBusy?: boolean;
  showStatus?: boolean;
}

/** Severity pill + finding + target chip + agent. */
export function FindingsTable({
  findings,
  total,
  onViewAll,
  onOpenFinding,
  onTriageFinding,
  triageBusy = false,
  showStatus = false,
}: FindingsTableProps) {
  if (findings.length === 0) {
    return <p className="px-3 py-4 text-[12px] text-rj-text-3">{strings.findings.empty}</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left">
        <thead>
          <tr className="text-[10px] uppercase tracking-wide text-rj-text-3">
            <th scope="col" className="px-3 py-1.5 font-medium">{strings.findings.colSeverity}</th>
            <th scope="col" className="px-3 py-1.5 font-medium">{strings.findings.colFinding}</th>
            <th scope="col" className="px-3 py-1.5 font-medium">{strings.findings.colTarget}</th>
            <th scope="col" className="px-3 py-1.5 font-medium">{strings.findings.colAgent}</th>
            {showStatus && <th scope="col" className="px-3 py-1.5 font-medium">{strings.findings.colStatus}</th>}
            {onTriageFinding && <th scope="col" className="px-3 py-1.5 text-right font-medium">Triage</th>}
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr
              key={f.findingId}
              tabIndex={onOpenFinding ? 0 : undefined}
              className={cn(
                "border-t border-rj-border align-top",
                onOpenFinding && "cursor-pointer hover:bg-rj-panel-hover focus-visible:outline-2 focus-visible:outline-rj-accent",
              )}
              onClick={onOpenFinding ? () => onOpenFinding(f.findingId) : undefined}
              onKeyDown={
                onOpenFinding
                  ? (e) => {
                      if (e.target === e.currentTarget && (e.key === "Enter" || e.key === " ")) {
                        e.preventDefault();
                        onOpenFinding(f.findingId);
                      }
                    }
                  : undefined
              }
            >
              <td className="px-3 py-2"><SeverityPill severity={f.severity} /></td>
              <td className="max-w-0 px-3 py-2">
                <div className="truncate text-[12px] font-medium text-rj-text" title={f.title}>{f.title}</div>
                {f.description && (
                  <div className="mt-0.5 line-clamp-2 text-[11px] text-rj-text-3">{f.description}</div>
                )}
              </td>
              <td className="px-3 py-2">{f.target ? <Chip>{f.target}</Chip> : <span className="text-rj-text-3">—</span>}</td>
              <td className="px-3 py-2 text-[12px] text-rj-text-2">{f.agentName ?? "—"}</td>
              {showStatus && <td className="px-3 py-2"><FindingStatusLabel status={f.status} /></td>}
              {onTriageFinding && (
                <td className="px-3 py-2 text-right" onClick={(e) => e.stopPropagation()}>
                  <span className="inline-flex shrink-0 gap-1">
                    <button
                      type="button"
                      disabled={triageBusy || f.status === "verified"}
                      aria-pressed={f.status === "verified"}
                      className={cn(
                        "cursor-pointer rounded border px-2 py-0.5 text-[11px] transition-colors disabled:cursor-default disabled:opacity-50",
                        f.status === "verified"
                          ? "border-rj-live bg-rj-live/15 font-medium text-rj-live"
                          : "border-rj-border-strong text-rj-live hover:bg-rj-panel-hover",
                      )}
                      onClick={() => onTriageFinding(f.findingId, "verified")}
                    >
                      Verify
                    </button>
                    <button
                      type="button"
                      disabled={triageBusy || f.status === "false_positive"}
                      aria-pressed={f.status === "false_positive"}
                      className={cn(
                        "cursor-pointer rounded border px-2 py-0.5 text-[11px] transition-colors disabled:cursor-default disabled:opacity-50",
                        f.status === "false_positive"
                          ? "border-rj-border-strong bg-rj-panel-sunken font-medium text-rj-text-2"
                          : "border-rj-border-strong text-rj-text-3 hover:bg-rj-panel-hover",
                      )}
                      onClick={() => onTriageFinding(f.findingId, "false_positive")}
                    >
                      False positive
                    </button>
                  </span>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {onViewAll && total != null && total > findings.length && (
        <div className="border-t border-rj-border px-3 py-2 text-right">
          <button type="button" onClick={onViewAll} className="cursor-pointer text-[11px] text-rj-text-2 hover:text-rj-accent">
            {strings.findings.viewAll(total)}
          </button>
        </div>
      )}
    </div>
  );
}
