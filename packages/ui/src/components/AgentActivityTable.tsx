import { cn } from "../utils.js";
import { strings } from "../strings.js";
import type { AgentRow } from "../types.js";
import { StatusPill } from "./StatusPill.js";

function RoleIcon({ name }: { name: string }) {
  const initial = name.trim().charAt(0).toUpperCase() || "?";
  return (
    <span
      aria-hidden="true"
      className="flex size-5 shrink-0 items-center justify-center rounded border border-rj-border-strong bg-rj-panel-sunken text-[10px] font-semibold text-rj-text-2"
    >
      {initial}
    </span>
  );
}

export interface AgentActivityTableProps {
  agents: AgentRow[];
  selectedAgentId?: string | null;
  onSelect?: (agentId: string) => void;
  emptyHint?: string;
}

/** Agent / current task / status table; selected row gets a red left border. */
export function AgentActivityTable({ agents, selectedAgentId, onSelect, emptyHint }: AgentActivityTableProps) {
  if (agents.length === 0) {
    return <p className="px-3 py-4 text-[12px] text-rj-text-3">{emptyHint ?? strings.agents.empty}</p>;
  }
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-left">
        <thead>
          <tr className="text-[10px] uppercase tracking-wide text-rj-text-3">
            <th scope="col" className="px-3 py-1.5 font-medium">{strings.agents.colAgent}</th>
            <th scope="col" className="px-3 py-1.5 font-medium">{strings.agents.colTask}</th>
            <th scope="col" className="px-3 py-1.5 font-medium">{strings.agents.colStatus}</th>
          </tr>
        </thead>
        <tbody>
          {agents.map((a) => {
            const selected = a.agentId === selectedAgentId;
            return (
              <tr
                key={a.agentId}
                onClick={() => onSelect?.(a.agentId)}
                aria-selected={selected}
                tabIndex={onSelect ? 0 : undefined}
                onKeyDown={
                  onSelect
                    ? (e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          onSelect(a.agentId);
                        }
                      }
                    : undefined
                }
                className={cn(
                  "border-t border-rj-border text-[12px] transition-colors",
                  onSelect && "cursor-pointer",
                  selected
                    ? "bg-rj-accent-subtle/60 shadow-[inset_2px_0_0_0_var(--color-rj-accent)]"
                    : "hover:bg-rj-panel-hover",
                )}
              >
                <td className="px-3 py-2">
                  <span className="flex items-center gap-2 font-medium text-rj-text">
                    <RoleIcon name={a.name} />
                    {a.name}
                  </span>
                </td>
                <td className="max-w-0 truncate px-3 py-2 text-rj-text-2" title={a.activity}>
                  {a.activity}
                </td>
                <td className="px-3 py-2">
                  <StatusPill kind="agent" state={a.status} size="sm" />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
