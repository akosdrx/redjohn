import { useQuery } from "@tanstack/react-query";
import { EmptyState, ErrorState, LoadingState, Panel, strings } from "@redjohn/ui";
import { useEngine } from "../lib/engine";
import { useUiStore } from "../store/ui";
import { listAll } from "../lib/api";

export function ArtifactsPage() {
  const { api } = useEngine();
  const runId = useUiStore((s) => s.selectedRunId);

  const evidenceQuery = useQuery({
    queryKey: ["evidence", runId],
    queryFn: () => listAll((cursor) => api!.listRunEvidence(runId!, { limit: 200, ...(cursor ? { cursor } : {}) })),
    enabled: !!api && !!runId,
  });

  if (!runId) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <EmptyState title={strings.run.selectPrompt} />
      </div>
    );
  }
  if (evidenceQuery.isPending) return <LoadingState />;
  if (evidenceQuery.isError) return <ErrorState detail={String(evidenceQuery.error)} onRetry={() => evidenceQuery.refetch()} />;

  const items = evidenceQuery.data ?? [];

  return (
    <div data-testid="artifacts-page" className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3">
      <h1 className="text-[15px] font-semibold text-rj-text">{strings.artifacts.title}</h1>
      <Panel padded={false}>
        {items.length === 0 ? (
          <EmptyState title={strings.artifacts.empty} />
        ) : (
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="text-[10px] uppercase tracking-wide text-rj-text-3">
                <th scope="col" className="px-3 py-1.5 font-medium">{strings.artifacts.colName}</th>
                <th scope="col" className="px-3 py-1.5 font-medium">{strings.artifacts.colSource}</th>
                <th scope="col" className="px-3 py-1.5 font-medium">{strings.artifacts.colSize}</th>
                <th scope="col" className="px-3 py-1.5 font-medium">{strings.artifacts.colHash}</th>
              </tr>
            </thead>
            <tbody>
              {items.map((e) => (
                <tr key={e.evidence_id} className="border-t border-rj-border text-[12px]">
                  <td className="px-3 py-2 font-mono text-rj-text">{e.evidence_id}</td>
                  <td className="px-3 py-2 text-rj-text-2">{e.source}</td>
                  <td className="px-3 py-2 text-rj-text-2">{formatBytes(e.size_bytes)}</td>
                  <td className="max-w-0 truncate px-3 py-2 font-mono text-[11px] text-rj-text-3" title={e.sha256}>{e.sha256 ? `${e.sha256.slice(0, 16)}…` : "—"}</td>
                </tr>
              ))}

            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}
