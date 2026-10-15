import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Button,
  Chip,
  Dialog,
  EmptyState,
  ErrorState,
  FindingStatusLabel,
  FindingsTable,
  LoadingState,
  Panel,
  Select,
  SeverityPill,
  strings,
  type FindingStatus,
  type FindingSeverity,
} from "@redjohn/ui";
import { useEngine } from "../lib/engine";
import { useUiStore } from "../store/ui";
import { qk } from "../lib/runStream";
import { toFindingRow } from "../lib/mappers";
import { listAll } from "../lib/api";

const SEVERITY_OPTIONS: Array<{ value: FindingSeverity; label: string }> = [
  { value: "critical", label: "Critical" },
  { value: "high", label: "High" },
  { value: "medium", label: "Medium" },
  { value: "low", label: "Low" },
  { value: "info", label: "Info" },
];

export function FindingsPage() {
  const { api } = useEngine();
  const qc = useQueryClient();
  const runId = useUiStore((s) => s.selectedRunId);
  const [severity, setSeverity] = useState<string>("");
  const [status, setStatus] = useState<string>("");
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const agentsQuery = useQuery({
    queryKey: qk.agents(runId ?? "none"),
    queryFn: () => api!.listAgents(runId!),
    enabled: !!api && !!runId,
  });
  const findingsQuery = useQuery({
    queryKey: [...(runId ? qk.findings(runId) : ["findings", "none"]), severity, status, "page"],
    queryFn: async () => ({
      items: await listAll((cursor) =>
        api!.listRunFindings(runId!, {
          limit: 200,
          ...(cursor ? { cursor } : {}),
          ...(severity ? { severity: severity as FindingSeverity } : {}),
          ...(status ? { status: status as FindingStatus } : {}),
        }),
      ),
    }),
    enabled: !!api && !!runId,
  });

  const update = useMutation({
    mutationFn: ({ findingId, status }: { findingId: string; status: FindingStatus }) =>
      api!.updateFinding(findingId, { status }),
    onSuccess: async () => {
      if (runId) await qc.invalidateQueries({ queryKey: qk.findings(runId) });
    },
  });

  const agentNameById = useMemo(
    () => new Map((agentsQuery.data?.items ?? []).map((a) => [a.agent_id, a.name])),
    [agentsQuery.data],
  );

  const rows = useMemo(
    () =>
      (findingsQuery.data?.items ?? []).map((f) =>
        toFindingRow(f, f.source_agent_id ? agentNameById.get(f.source_agent_id) : undefined),
      ),
    [findingsQuery.data, agentNameById],
  );

  const selectedFinding = useMemo(
    () => (findingsQuery.data?.items ?? []).find((f) => f.finding_id === selectedFindingId) ?? null,
    [findingsQuery.data, selectedFindingId],
  );

  if (!runId) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <EmptyState title={strings.run.selectPrompt} />
      </div>
    );
  }

  return (
    <div data-testid="findings-page" className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3">
      <header className="flex items-center justify-between">
        <h1 className="text-[15px] font-semibold text-rj-text">{strings.nav.findings}</h1>
        <div className="flex items-center gap-2">
          <Select value={severity} onChange={(e) => setSeverity(e.target.value)} aria-label="Filter by severity" className="w-36">
            <option value="">All severities</option>
            {SEVERITY_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>{opt.label}</option>
            ))}
          </Select>
          <Select value={status} onChange={(e) => setStatus(e.target.value)} aria-label="Filter by status" className="w-40">
            <option value="">All statuses</option>
            {Object.entries(strings.findings.statusLabels).map(([k, v]) => (
              <option key={k} value={k}>{v}</option>
            ))}
          </Select>
        </div>
      </header>

      {update.isError && (
        <p role="alert" className="text-[12px] text-rj-down">
          Could not update the finding: {String(update.error)}
        </p>
      )}

      <Panel padded={false}>
        {findingsQuery.isPending ? (
          <LoadingState />
        ) : findingsQuery.isError ? (
          <ErrorState detail={String(findingsQuery.error)} onRetry={() => findingsQuery.refetch()} />
        ) : (
          <FindingsTable
            findings={rows}
            showStatus
            onOpenFinding={(findingId) => setSelectedFindingId(findingId)}
            onTriageFinding={(findingId, nextStatus) => update.mutate({ findingId, status: nextStatus })}
            triageBusy={update.isPending}
          />
        )}
      </Panel>

      <Dialog
        open={selectedFinding !== null}
        onClose={() => setSelectedFindingId(null)}
        title={selectedFinding?.title ?? "Finding detail"}
        width={640}
      >
        {selectedFinding && (
          <div className="flex flex-col gap-4 text-[13px]">
            <div className="flex flex-wrap items-center gap-2">
              <SeverityPill severity={selectedFinding.severity} />
              <FindingStatusLabel status={selectedFinding.status} />
              {selectedFinding.code && <Chip>{selectedFinding.code}</Chip>}
              {selectedFinding.target && <Chip>{selectedFinding.target}</Chip>}
              {selectedFinding.source_agent_id && (
                <span className="text-[12px] text-rj-text-3">
                  Agent: {agentNameById.get(selectedFinding.source_agent_id) ?? selectedFinding.source_agent_id}
                </span>
              )}
            </div>

            {selectedFinding.description && (
              <div>
                <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wide text-rj-text-3">Description</h3>
                <p className="whitespace-pre-wrap break-words rounded border border-rj-border bg-rj-panel-sunken p-3 text-[12px] text-rj-text-2">
                  {selectedFinding.description}
                </p>
              </div>
            )}

            {selectedFinding.remediation && (
              <div>
                <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wide text-rj-text-3">Remediation</h3>
                <p className="whitespace-pre-wrap break-words rounded border border-rj-border bg-rj-panel-sunken p-3 text-[12px] text-rj-text-2">
                  {selectedFinding.remediation}
                </p>
              </div>
            )}

            {selectedFinding.evidence_refs && selectedFinding.evidence_refs.length > 0 && (
              <div>
                <h3 className="mb-1 text-[11px] font-medium uppercase tracking-wide text-rj-text-3">Evidence</h3>
                <div className="flex flex-wrap gap-1.5">
                  {selectedFinding.evidence_refs.map((eid) => (
                    <Chip key={eid}>{eid}</Chip>
                  ))}
                </div>
              </div>
            )}

            <div className="flex items-center justify-between border-t border-rj-border pt-3">
              <div className="flex gap-2">
                <Button
                  size="sm"
                  variant={selectedFinding.status === "verified" ? "primary" : "outline"}
                  disabled={update.isPending || selectedFinding.status === "verified"}
                  onClick={() => update.mutate({ findingId: selectedFinding.finding_id, status: "verified" })}
                >
                  Verify finding
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={update.isPending || selectedFinding.status === "false_positive"}
                  onClick={() => update.mutate({ findingId: selectedFinding.finding_id, status: "false_positive" })}
                >
                  Mark false positive
                </Button>
              </div>
              <Button size="sm" variant="ghost" onClick={() => setSelectedFindingId(null)}>
                Close
              </Button>
            </div>
          </div>
        )}
      </Dialog>
    </div>
  );
}
