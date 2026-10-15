import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AgentActivityTable,
  Button,
  EmptyState,
  ErrorState,
  FindingsTable,
  LiveTerminal,
  LoadingState,
  MessageComposer,
  Panel,
  StatusPill,
  strings,
  cn,
  type LiveTerminalHandle,
  type ServiceIndicator,
} from "@redjohn/ui";
import { useEngine } from "../lib/engine";
import { bridge } from "../bridge";
import { useUiStore } from "../store/ui";
import { hydrateCaches, qk, useRunStream } from "../lib/runStream";
import { toAgentRow, toFindingRow } from "../lib/mappers";
import { sessionTarget } from "../lib/sessionTarget";
import type { StreamState } from "../lib/ws";

export function WorkspacePage({ embedded = false }: { embedded?: boolean }) {
  const { api } = useEngine();
  const selectedRunId = useUiStore((s) => s.selectedRunId);
  const runs = useQuery({ queryKey: qk.runs, queryFn: () => api!.listRuns({ limit: 50 }), enabled: !!api && !embedded });

  // Auto-select the most recent run when none is selected.
  useEffect(() => {
    if (!embedded && !selectedRunId && runs.data?.items.length) {
      useUiStore.getState().selectRun(runs.data.items[0]!.run_id);
    }
  }, [selectedRunId, runs.data, embedded]);

  if (!embedded && runs.isPending) return <LoadingState />;
  if (!embedded && runs.isError) return <ErrorState detail={String(runs.error)} onRetry={() => runs.refetch()} />;
  if (!selectedRunId) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <EmptyState title={strings.run.selectPrompt} />
      </div>
    );
  }
  return <RunDetail key={selectedRunId} runId={selectedRunId} embedded={embedded} />;
}

function RunDetail({ runId, embedded }: { runId: string; embedded: boolean }) {
  const { api, token } = useEngine();
  const qc = useQueryClient();
  const termRef = useRef<LiveTerminalHandle | null>(null);
  const [streamState, setStreamState] = useState<StreamState>("connecting");

  const follow = useUiStore((s) => s.terminalFollow);
  const setFollow = useUiStore((s) => s.setTerminalFollow);
  const maximized = useUiStore((s) => s.terminalMaximized);
  const setMaximized = useUiStore((s) => s.setTerminalMaximized);
  const selectedAgentId = useUiStore((s) => s.selectedAgentByRun[runId] ?? null);
  const selectAgent = useUiStore((s) => s.selectAgent);

  const snapshotQuery = useQuery({
    queryKey: ["snapshot", runId],
    queryFn: async () => {
      const snap = await api!.getRunSnapshot(runId);
      hydrateCaches(qc, runId, snap);
      return snap;
    },
    enabled: !!api,
  });

  const runQuery = useQuery({
    queryKey: qk.run(runId),
    queryFn: () => api!.getRun(runId),
    enabled: !!api && !!snapshotQuery.data,
    initialData: snapshotQuery.data?.run,
  });
  const controlRun = useMutation({
    mutationFn: (action: "start" | "stop") => action === "start" ? api!.startRun(runId) : api!.stopRun(runId),
    onSuccess: async (updatedRun) => {
      qc.setQueryData(qk.run(runId), updatedRun);
      await Promise.all([
        qc.invalidateQueries({ queryKey: qk.runs }),
        qc.invalidateQueries({ queryKey: qk.agents(runId) }),
      ]);
    },
    onError: () => { void qc.invalidateQueries({ queryKey: qk.run(runId) }); },
  });

  const agentsQuery = useQuery({
    queryKey: qk.agents(runId),
    queryFn: () => api!.listAgents(runId),
    enabled: !!api && !!snapshotQuery.data,
    initialData: snapshotQuery.data ? { items: snapshotQuery.data.agents } : undefined,
  });
  const findingsQuery = useQuery({
    queryKey: qk.findings(runId),
    queryFn: () => api!.listRunFindings(runId, { limit: 50 }),
    enabled: !!api && !!snapshotQuery.data,
  });
  const statusQuery = useQuery({
    queryKey: qk.status,
    queryFn: () => api!.getStatus(),
    enabled: !!api,
    refetchInterval: 5_000,
  });
  const agents = useMemo(() => (agentsQuery.data?.items ?? []).map(toAgentRow), [agentsQuery.data]);
  const agentNameById = useMemo(
    () => new Map((agentsQuery.data?.items ?? []).map((a) => [a.agent_id, a.name])),
    [agentsQuery.data],
  );
  const findings = useMemo(
    () =>
      (findingsQuery.data?.items ?? []).map((f) =>
        toFindingRow(f, f.source_agent_id ? agentNameById.get(f.source_agent_id) : undefined),
      ),
    [findingsQuery.data, agentNameById],
  );

  const run = runQuery.data ?? snapshotQuery.data?.run ?? null;
  const runTargetLabel = run ? sessionTarget(run).value : undefined;

  useRunStream({
    api,
    runId,
    snapshot: snapshotQuery.data,
    token,
    agents,
    onStreamState: setStreamState,
    onTerminalWrite: (chunk, agentId) => termRef.current?.write(chunk, agentId),
  });

  const services: ServiceIndicator[] = useMemo(() => {
    const list = statusQuery.isError ? [] : statusQuery.data?.services ?? snapshotQuery.data?.services ?? [];
    return list.map((s) => ({ service: s.service, state: s.state, detail: s.detail }));
  }, [snapshotQuery.data, statusQuery.data, statusQuery.isError]);

  function serviceState(name: string): ServiceIndicator | undefined {
    return services.find((s) => s.service.toLowerCase().includes(name.toLowerCase()));
  }

  if (snapshotQuery.isPending) return <LoadingState />;
  if (snapshotQuery.isError) {
    return <ErrorState detail={String(snapshotQuery.error)} onRetry={() => snapshotQuery.refetch()} />;
  }

  const runningCount = agents.filter((a) => a.status === "running").length;
  const apiState = serviceState("api")?.state ?? (statusQuery.isError ? "down" : statusQuery.isSuccess ? "live" : "starting");
  const ovState = serviceState("openviking")?.state ?? "not_configured";

  async function sendMessage(agentId: string, body: string): Promise<void> {
    await api!.postMessage(runId, { to_agent_id: agentId, body });
  }

  const openFindingsView = () => {
    useUiStore.getState().selectRun(runId);
    window.dispatchEvent(new CustomEvent("redjohn:navigate", { detail: "findings" }));
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      {/* Top bar */}
      <header className={cn("flex shrink-0 items-center justify-between gap-3 border-b border-rj-border px-4", embedded ? "h-10" : "h-14")}>
        <div className="flex min-w-0 items-center gap-3">
          {!embedded && <h1 className="truncate text-[15px] font-semibold text-rj-text">{run?.name ?? "…"}</h1>}
          {!embedded && run && <StatusPill kind="run" state={run.status} />}
          {!embedded && run?.status === "created" && (
            <Button size="sm" disabled={controlRun.isPending} onClick={() => controlRun.mutate("start")}>
              {controlRun.isPending ? strings.status.starting : strings.run.start}
            </Button>
          )}
          {!embedded && (run?.status === "running" || run?.status === "starting") && (
            <Button variant="outline" size="sm" disabled={controlRun.isPending} onClick={() => controlRun.mutate("stop")}>
              {controlRun.isPending ? strings.status.stopping : strings.run.stop}
            </Button>
          )}
        </div>
        <div className="flex shrink-0 items-center gap-2">
          <ServiceBadge label={strings.services.api} state={apiState} />
          <ServiceBadge label={strings.services.openviking} state={ovState} />
          <Button size="sm" variant="outline" onClick={() => window.dispatchEvent(new CustomEvent("redjohn:navigate", { detail: { page: "settings", section: "tools" } }))}>Tools →</Button>
          <Button size="sm" variant="outline" onClick={() => window.dispatchEvent(new CustomEvent("redjohn:navigate", { detail: { page: "settings", section: "skills" } }))}>Skills →</Button>
        </div>
      </header>

      {controlRun.isError && (
        <p role="alert" className="border-b border-rj-border px-4 py-2 text-[12px] text-rj-down">
          {controlRun.error.message}
        </p>
      )}

      <div className="relative flex min-h-0 flex-1">
        {/* Center */}
        <div className="flex min-w-0 flex-1 flex-col gap-3 overflow-y-auto p-3">
          {!maximized && (
            <div className="grid min-h-60 lg:h-60 min-h-0 shrink-0 grid-cols-2 gap-3 max-lg:grid-cols-1">
              <Panel
                title={strings.agents.title}
                headerRight={<span className="text-[11px]">{strings.agents.runningCount(runningCount)}</span>}
                className="overflow-y-auto"
              >
                <AgentActivityTable
                  agents={agents}
                  selectedAgentId={selectedAgentId}
                  onSelect={(id) => selectAgent(runId, id === selectedAgentId ? null : id)}
                />
                {agents.length > 0 && (
                  <p className="px-3 py-1.5 text-[11px] text-rj-text-3">{strings.agents.selectHint}</p>
                )}
              </Panel>
              <Panel title={strings.findings.title} className="overflow-y-auto">
                <FindingsTable
                  findings={findings.slice(0, 5)}
                  total={findingsQuery.data?.total ?? findings.length}
                  onOpenFinding={() => openFindingsView()}
                  onViewAll={openFindingsView}
                />
              </Panel>
            </div>
          )}

          {/* Live terminal — largest panel */}
          <Panel className="min-h-[300px] flex-1 overflow-hidden" padded={false}>
            <LiveTerminal
              ref={termRef}
              className="h-full"
              agents={agents}
              selectedAgentId={selectedAgentId}
              onSelectAgent={(id) => selectAgent(runId, id)}
              {...(runTargetLabel && runTargetLabel !== "—" ? { targetLabel: runTargetLabel } : {})}
              streaming={streamState === "live"}
              follow={follow}
              onFollowChange={setFollow}
              maximized={maximized}
              onToggleMaximize={() => setMaximized(!maximized)}
              onOpenLogs={() => void bridge.openLogs()}
              composer={
                <MessageComposer
                  agents={agents}
                  recipientId={selectedAgentId}
                  onRecipientChange={(id) => selectAgent(runId, id)}
                  onSend={sendMessage}
                  disabled={!run || (run.status !== "running" && run.status !== "starting")}
                />
              }
            />
          </Panel>
        </div>
      </div>
    </div>
  );
}

function ServiceBadge({ label, state }: { label: string; state: ServiceIndicator["state"] }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px]",
        state === "live"
          ? "border-rj-live/30 bg-rj-live/10 text-rj-live"
          : state === "degraded" || state === "starting"
            ? "border-rj-starting/30 bg-rj-starting/10 text-rj-starting"
            : state === "down"
              ? "border-rj-down/30 bg-rj-down/10 text-rj-down"
              : "border-rj-border-strong text-rj-text-3",
      )}
    >
      <span
        aria-hidden="true"
        className={cn(
          "inline-block size-1.5 rounded-full",
          state === "live"
            ? "bg-rj-live"
            : state === "degraded" || state === "starting"
              ? "bg-rj-starting"
              : state === "down"
                ? "bg-rj-down"
                : "bg-rj-idle",
        )}
      />
      {label} {state === "live" ? strings.status.live : state === "not_configured" ? strings.status.not_configured : strings.status[state]}
    </span>
  );
}
