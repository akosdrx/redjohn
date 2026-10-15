import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, EmptyState, ErrorState, LoadingState, Panel, Select, Spinner, strings } from "@redjohn/ui";
import { useEngine } from "../lib/engine";
import { useUiStore } from "../store/ui";
import { listAll } from "../lib/api";

export function ReportsPage() {
  const { api } = useEngine();
  const qc = useQueryClient();
  const runId = useUiStore((s) => s.selectedRunId);
  const [format, setFormat] = useState<"html" | "json" | "pdf">("html");
  const capabilities = useQuery({ queryKey: ["capabilities"], queryFn: () => api!.getCapabilities(), enabled: !!api });
  const formats = capabilities.data?.reports ?? ["html", "json"];
  const effectiveFormat = formats.includes(format) ? format : (formats[0] ?? "html");

  const reportsQuery = useQuery({
    queryKey: ["reports", runId],
    queryFn: () => listAll((cursor) => api!.listReports(runId!, cursor)),
    enabled: !!api && !!runId,
  });

  const create = useMutation({
    mutationFn: () => api!.createReport(runId!, effectiveFormat),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["reports", runId] });
    },
  });
  const download = useMutation({ mutationFn: (report: NonNullable<typeof reportsQuery.data>[number]) => api!.downloadReport(report) });

  if (!runId) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <EmptyState title={strings.run.selectPrompt} />
      </div>
    );
  }

  return (
    <div data-testid="reports-page" className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-3">
      <header className="flex items-center justify-between">
        <h1 className="text-[15px] font-semibold text-rj-text">{strings.reports.title}</h1>
        <div className="flex items-center gap-2">
          <Select value={effectiveFormat} onChange={(e) => setFormat(e.target.value as "html" | "json" | "pdf")} aria-label={strings.reports.format} className="w-28">
            {formats.map((f) => <option key={f} value={f}>{f.toUpperCase()}</option>)}
          </Select>
          <Button variant="primary" onClick={() => create.mutate()} disabled={create.isPending}>
            {create.isPending ? <Spinner className="size-3" /> : null}
            {strings.reports.generate}
          </Button>
        </div>
      </header>

      {create.isError && <ErrorState detail={String(create.error)} onRetry={() => create.mutate()} />}
      {download.isError && <ErrorState detail={String(download.error)} />}

      <Panel padded={false}>
        {reportsQuery.isError ? (
          <ErrorState detail={String(reportsQuery.error)} onRetry={() => reportsQuery.refetch()} />
        ) : reportsQuery.isLoading ? (
          <LoadingState />
        ) : (reportsQuery.data?.length ?? 0) === 0 ? (
          <EmptyState title={strings.reports.empty} />
        ) : (
          <table className="w-full border-collapse text-left">
            <thead>
              <tr className="text-[10px] uppercase tracking-wide text-rj-text-3">
                <th scope="col" className="px-3 py-1.5 font-medium">{strings.reports.colId}</th>
                <th scope="col" className="px-3 py-1.5 font-medium">{strings.reports.colFormat}</th>
                <th scope="col" className="px-3 py-1.5 font-medium">{strings.reports.colCreated}</th>
                <th scope="col" className="px-3 py-1.5 font-medium">Download</th>
              </tr>
            </thead>
            <tbody>
              {reportsQuery.data!.map((r) => (
                <tr key={r.report_id} className="border-t border-rj-border text-[12px]">
                  <td className="px-3 py-2 font-mono text-rj-text">{r.report_id}</td>
                  <td className="px-3 py-2 uppercase text-rj-text-2">{r.format}</td>
                  <td className="px-3 py-2 text-rj-text-2">{new Date(r.created_at).toLocaleString()}</td>
                  <td className="px-3 py-2"><Button size="sm" variant="outline" disabled={download.isPending} onClick={() => download.mutate(r)}>Download</Button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Panel>
    </div>
  );
}
