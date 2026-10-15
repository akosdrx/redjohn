import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Logo, NewPentestDialog, Button, ErrorState, StatusPill, cn, type NewPentestValues } from "@redjohn/ui";
import logoUrl from "@redjohn/ui/assets/redjohn-logo.png";
import { useEngine } from "../lib/engine";
import { useUiStore } from "../store/ui";
import { qk } from "../lib/runStream";
import { listAll } from "../lib/api";
import { sessionTarget } from "../lib/sessionTarget";

export type NavPage = "pentests" | "settings";

export function Sidebar({ page, onNavigate }: { page: NavPage; onNavigate: (page: NavPage) => void }) {
  const { api, info } = useEngine();
  const qc = useQueryClient();
  const [dialogOpen, setDialogOpen] = useState(false);
  const [archived, setArchived] = useState(false);
  const selectedRunId = useUiStore((state) => state.selectedRunId);
  const selectRun = useUiStore((state) => state.selectRun);
  const status = useQuery({ queryKey: qk.status, queryFn: () => api!.getStatus(), enabled: !!api, refetchInterval: 5_000 });
  const memory = status.data?.services.find((service) => service.service === "openviking");
  const runs = useQuery({
    queryKey: [...qk.runs, { archived }],
    queryFn: () => listAll((cursor) => api!.listRuns({ limit: 100, archived, ...(cursor ? { cursor } : {}) })),
    enabled: !!api,
    refetchInterval: 10_000,
  });
  const create = useMutation({
    mutationFn: (values: NewPentestValues) => api!.createRun({ name: values.name, task: values.task, authorized_target: values.authorizedTarget, target_kind: values.targetKind, scan_mode: values.scanMode }),
    onSuccess: async (run) => {
      qc.setQueryData(qk.run(run.run_id), run);
      selectRun(run.run_id); setArchived(false); onNavigate("pentests");
      await qc.invalidateQueries({ queryKey: qk.runs });
    },
  });
  useEffect(() => {
    if (!archived && !selectedRunId && runs.data?.length) selectRun(runs.data[0]!.run_id);
  }, [archived, selectedRunId, runs.data, selectRun]);
  return <aside aria-label="Pentest navigation" className="flex w-[232px] shrink-0 flex-col border-r border-rj-border bg-rj-sidebar">
    <div className="px-4 py-4"><Logo src={logoUrl} /></div>
    <div className="px-3 pb-4"><Button variant="primary" className="w-full" onClick={() => setDialogOpen(true)}><span aria-hidden="true">+</span> New pentest</Button></div>
    <div className="flex items-center justify-between px-4 pb-2">
      <span className="text-[11px] font-semibold uppercase tracking-wide text-rj-text-2">{archived ? "Archived pentests" : "Pentests"}</span>
      <button type="button" aria-label={archived ? "Show current pentests" : "Show archived pentests"} aria-pressed={archived} title={archived ? "Current pentests" : "Archive"} onClick={() => setArchived(!archived)} className="rounded p-1 text-rj-text-2 hover:bg-rj-panel-hover hover:text-rj-text">
        <svg width="15" height="15" viewBox="0 0 16 16" aria-hidden="true"><path d="M2 5h12v9H2zM1 2h14v3H1zM6 8h4" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinejoin="round" /></svg>
      </button>
    </div>
    <nav aria-label={archived ? "Archived pentests" : "Pentests"} className="min-h-0 flex-1 overflow-y-auto px-2 pb-2">
      {runs.isError && <ErrorState detail={String(runs.error)} onRetry={() => runs.refetch()} />}
      {runs.isPending && <p className="px-3 py-2 text-[12px] text-rj-text-2">Loading pentests…</p>}
      {runs.data?.length === 0 && <p className="px-3 py-2 text-[12px] text-rj-text-2">{archived ? "No archived pentests." : "Create your first pentest."}</p>}
      {runs.data?.map((run) => <button key={run.run_id} type="button" onClick={() => { selectRun(run.run_id); onNavigate("pentests"); }} aria-current={page === "pentests" && run.run_id === selectedRunId ? "page" : undefined}
        className={cn("mb-1 flex w-full flex-col gap-1 rounded-md px-3 py-2 text-left", page === "pentests" && run.run_id === selectedRunId ? "bg-rj-accent-subtle text-rj-text" : "text-rj-text-2 hover:bg-rj-panel-hover")}>
        <span className="flex w-full items-center gap-2 text-[13px]"><span aria-hidden="true" className={cn("size-1.5 shrink-0 rounded-full", run.status === "running" ? "bg-rj-live" : run.status === "starting" || run.status === "stopping" ? "bg-rj-starting" : "bg-rj-idle")} /><span className="truncate">{run.name}</span></span>
        <span className="truncate pl-3.5 text-[11px] text-rj-text-2" title={sessionTarget(run).value}>{sessionTarget(run).label} · {sessionTarget(run).value}</span>
      </button>)}
    </nav>
    <div className="border-t border-rj-border p-2">
      <button type="button" className="mb-2 flex w-full items-center justify-between gap-2 rounded px-2 py-1 text-[11px] text-rj-text-2 hover:bg-rj-panel-hover" title={memory?.detail ?? "Checking local memory"} onClick={() => window.dispatchEvent(new CustomEvent("redjohn:navigate", { detail: { page: "settings", section: "memory" } }))}>
        <span>OpenViking</span><StatusPill kind="service" size="sm" state={status.isError ? "down" : memory?.state ?? "starting"} />
      </button>
      <div role="status" aria-label={`Engine ${info.state === "running" && !status.isError ? "online" : "offline"}`} className="mb-2 flex items-center gap-2 px-2 text-[11px]">
        <span className={info.state === "running" && !status.isError ? "text-rj-live" : "text-rj-down"}>Engine</span><span aria-hidden="true" className={cn("size-1.5 rounded-full", info.state === "running" && !status.isError ? "bg-rj-live" : "bg-rj-down")} />
      </div>
      {memory?.state !== "live" && <p className="mb-2 line-clamp-3 px-2 text-[11px] text-rj-text-2" role="status">{memory?.state === "not_configured" ? "Configure memory in Settings." : memory?.detail ?? (status.isError ? "Memory status unavailable." : "Checking local memory…")}</p>}
      <Button className="w-full justify-start" aria-current={page === "settings" ? "page" : undefined} onClick={() => onNavigate("settings")}>
      <svg width="15" height="15" viewBox="0 0 15 15" aria-hidden="true"><circle cx="7.5" cy="7.5" r="2.2" fill="none" stroke="currentColor" strokeWidth="1.3" /><path d="M7.5 1.5v1.8M7.5 11.7v1.8M1.5 7.5h1.8M11.7 7.5h1.8M3.3 3.3l1.3 1.3M10.4 10.4l1.3 1.3M3.3 11.7l1.3-1.3M10.4 4.6l1.3-1.3" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" /></svg>
      Settings
    </Button></div>
    <NewPentestDialog open={dialogOpen} onClose={() => setDialogOpen(false)} onSubmit={async (values) => { await create.mutateAsync(values); }} />
  </aside>;
}
