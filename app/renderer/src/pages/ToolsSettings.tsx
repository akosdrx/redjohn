import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, ErrorState, LoadingState, Panel } from "@redjohn/ui";
import { useEngine } from "../lib/engine";

export function ToolsSettings() {
  const { api } = useEngine();
  const qc = useQueryClient();
  const tools = useQuery({ queryKey: ["native-tools"], queryFn: () => api!.listNativeTools(), enabled: !!api });
  const [results, setResults] = useState<Record<string, string>>({});
  const check = useMutation({
    mutationFn: async (id: string) => ({ id, ...(await api!.checkNativeTool(id)) }),
    onSuccess: ({ id, detail }) => setResults((previous) => ({ ...previous, [id]: detail })),
  });
  const download = useMutation({
    mutationFn: () => api!.provisionTools(),
    onSuccess: (data) => qc.setQueryData(["native-tools"], data),
  });
  const items = tools.data?.items ?? [];
  const pending = items.filter((tool) => !tool.available && tool.downloadable).length;
  return <Panel title="Assessment tools" padded>
    <p className="mb-3 text-[12px] text-rj-text-2">Assessment tools start inside each pentest. The lightweight scanners are downloaded on demand; heavier tools (Metasploit, ZAP, browser) are optional and reused from your system when installed.</p>
    <div className="mb-4 flex items-center gap-2">
      <Button size="sm" variant="primary" disabled={download.isPending || !pending} onClick={() => download.mutate()}>
        {download.isPending ? "Downloading…" : pending ? `Download ${pending} scanner${pending === 1 ? "" : "s"}` : "Scanners installed"}
      </Button>
      {download.isError && <span role="alert" className="text-[11px] text-rj-down">{String(download.error)}</span>}
    </div>
    {tools.isPending ? <LoadingState /> : tools.isError ? <ErrorState detail={String(tools.error)} onRetry={() => tools.refetch()} /> : <ul className="grid grid-cols-2 gap-3 max-lg:grid-cols-1">
      {items.map((tool) => <li key={tool.id} className="rounded-md border border-rj-border p-3">
        <div className="flex items-center gap-3"><div className="min-w-0 flex-1"><strong className="block text-[13px]">{tool.name}</strong><span className="text-[11px] text-rj-text-3">{tool.available ? tool.origin === "system" ? "Installed on this computer" : `Downloaded${tool.version ? ` · ${tool.version.replace(/^v/, "")}` : ""}` : tool.downloadable ? "Available to download" : "Install separately to enable"}</span></div>
          <span className={`size-2 shrink-0 rounded-full ${tool.available ? "bg-rj-live" : tool.downloadable ? "bg-rj-starting" : "bg-rj-down"}`} aria-label={tool.available ? "Available" : tool.downloadable ? "Downloadable" : "Unavailable"} />
          <Button size="sm" variant="outline" disabled={!tool.available || check.isPending} onClick={() => check.mutate(tool.id)}>{check.isPending && check.variables === tool.id ? "Checking…" : "Check"}</Button>
        </div>
        {results[tool.id] && <p role="status" className="mt-2 text-[11px] text-rj-text-2">{results[tool.id]}</p>}
      </li>)}
    </ul>}
    {check.isError && <ErrorState detail={String(check.error)} />}
  </Panel>;
}
