import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, ErrorState, Field, Input, LoadingState, Panel, Select, StatusPill } from "@redjohn/ui";
import { useEngine } from "../lib/engine";
import type { MemoryConfig } from "../lib/api";
import { connectionName, modelName } from "../lib/modelNames";

export function MemorySettings() {
  const { api } = useEngine();
  const [message, setMessage] = useState("");
  const config = useQuery({ queryKey: ["memory-config"], queryFn: () => api!.getMemoryConfig(), enabled: !!api });
  if (config.isPending) return <LoadingState />;
  if (config.isError) return <ErrorState detail={String(config.error)} onRetry={() => config.refetch()} />;
  const saved = (config.data.server_models ?? {}) as Record<string, unknown>;
  const formKey = [
    config.data.provider_connection_id ?? "",
    config.data.language_model ?? "",
    typeof saved.embedding_base_url === "string" ? saved.embedding_base_url : "",
    typeof saved.embedding_model === "string" ? saved.embedding_model : "",
    typeof saved.embedding_dimension === "number" ? String(saved.embedding_dimension) : "",
  ].join("|");
  return <MemoryForm key={formKey} initial={config.data} message={message} setMessage={setMessage} />;
}

function isLocalEndpoint(rawUrl: string): boolean {
  try {
    const u = new URL(rawUrl.trim());
    return u.hostname === "127.0.0.1" || u.hostname === "localhost" || u.hostname === "::1" || u.hostname === "[::1]";
  } catch {
    return false;
  }
}

function MemoryForm({ initial, message, setMessage }: { initial: MemoryConfig; message: string; setMessage: (msg: string) => void }) {
  const { api } = useEngine();
  const qc = useQueryClient();
  const providers = useQuery({ queryKey: ["providers"], queryFn: () => api!.listProviders() });
  const catalog = useQuery({ queryKey: ["provider-catalog"], queryFn: () => api!.getProviderCatalog() });
  const status = useQuery({ queryKey: ["status"], queryFn: () => api!.getStatus(), refetchInterval: 2000 });
  const [connectionId, setConnectionId] = useState(initial.provider_connection_id ?? "");
  const [model, setModel] = useState(initial.language_model ?? "");
  const saved = (initial.server_models ?? {}) as Record<string, unknown>;
  const savedEmbedUrl = typeof saved.embedding_base_url === "string" ? saved.embedding_base_url : "";
  const savedEmbedModel = typeof saved.embedding_model === "string" ? saved.embedding_model : "";
  const savedEmbedDim = typeof saved.embedding_dimension === "number" ? saved.embedding_dimension : undefined;
  const [embedUrl, setEmbedUrl] = useState(savedEmbedUrl);
  const [embedModel, setEmbedModel] = useState(savedEmbedModel);
  const [embedDim, setEmbedDim] = useState(String(savedEmbedDim ?? 1536));
  const [embedKey, setEmbedKey] = useState("");
  const connection = providers.data?.items?.find((item) => item.id === connectionId);
  const customModels = useQuery({ queryKey: ["custom-provider-models", connectionId], queryFn: () => api!.discoverProviderModels({ id: connection!.id, base_url: connection!.base_url }), enabled: connection?.provider === "custom" });
  const codex = useQuery({ queryKey: ["codex-auth"], queryFn: () => api!.getCodexStatus(), enabled: connection?.provider === "codex" });
  const listed = connection?.provider === "codex" ? codex.data?.models : connection?.provider === "custom" ? customModels.data : catalog.data?.providers.find((item) => item.id === connection?.provider)?.models;
  const models = listed?.length ? listed : connection ? [{ id: connection.model, name: connectionName(connection, catalog.data) }] : [];
  const memory = status.data?.services.find((service) => service.service === "openviking");
  const busy = memory?.state === "starting";
  useEffect(() => {
    if (memory?.state === "live") void qc.invalidateQueries({ queryKey: ["memory-config"] });
  }, [memory?.state, qc]);
  const update = async () => { await qc.invalidateQueries({ queryKey: ["memory-config"] }); await qc.invalidateQueries({ queryKey: ["status"] }); };
  // A key is only required when configuring a non-local embedding endpoint
  // without an existing saved endpoint URL.
  const keyRequired = !(savedEmbedUrl && embedUrl.trim() === savedEmbedUrl) && !isLocalEndpoint(embedUrl);
  const parsedDim = Number(embedDim);
  const validDim = embedDim.trim() !== "" && Number.isInteger(parsedDim) && parsedDim > 0;
  const setup = useMutation({
    mutationFn: () => api!.setupMemory({
      provider_connection_id: connectionId,
      model: model || connection?.model || "",
      embedding_base_url: embedUrl.trim(),
      embedding_model: embedModel.trim(),
      embedding_dimension: parsedDim,
      ...(embedKey.trim() ? { embedding_api_key: embedKey.trim() } : {}),
    }),
    onSuccess: async () => { setEmbedKey(""); setMessage("Memory configuration saved. Preparing OpenViking…"); await update(); },
  });
  const restart = useMutation({ mutationFn: () => api!.startLocalMemory(), onSuccess: update });
  const check = useMutation({ mutationFn: () => api!.checkMemory(), onSuccess: update });
  const canSave = !!connection && !!embedUrl.trim() && !!embedModel.trim() && validDim && (!keyRequired || !!embedKey.trim()) && !setup.isPending && !busy;
  return <Panel title="OpenViking memory" padded>
    <div className="flex max-w-xl flex-col gap-4">
      <p className="text-[12px] text-rj-text-2">Memory runs a local OpenViking server on this computer. Its language and embedding models call external APIs — there is no local model runtime to download.</p>

      <div className="flex flex-col gap-3">
        <h3 className="text-[12px] font-semibold text-rj-text-2">Language model</h3>
        <p className="text-[11px] text-rj-text-3">Uses a connection added in Providers; its saved API key or OAuth login is reused automatically.</p>
        {providers.isError && <ErrorState detail={String(providers.error)} onRetry={() => providers.refetch()} />}
        {!providers.data?.items?.length ? <Button variant="outline" onClick={() => window.dispatchEvent(new CustomEvent("redjohn:navigate", { detail: { page: "settings", section: "providers" } }))}>Add provider connection</Button> : <>
          <Field label="Provider connection"><Select aria-label="Memory provider" value={connectionId} onChange={(event) => { const item = providers.data?.items?.find((p) => p.id === event.target.value); setConnectionId(event.target.value); setModel(item?.model ?? ""); }}>
            <option value="" disabled>Choose a provider</option>{(providers.data.items ?? []).map((item) => <option key={item.id} value={item.id}>{item.label} · {connectionName(item, catalog.data)}</option>)}
          </Select></Field>
          {connection && <Field label="Memory model"><Select aria-label="Memory model" value={model || connection.model} onChange={(event) => setModel(event.target.value)}>
            {models.map((item) => <option key={item.id} value={item.id}>{modelName(item.id, catalog.data, connection.provider) === item.id ? item.name : modelName(item.id, catalog.data, connection.provider)}</option>)}
          </Select></Field>}
          {customModels.isError && <ErrorState detail={String(customModels.error)} onRetry={() => customModels.refetch()} />}
        </>}
      </div>

      <div className="flex flex-col gap-3 border-t border-rj-border pt-3">
        <h3 className="text-[12px] font-semibold text-rj-text-2">Embedding model</h3>
        <p className="text-[11px] text-rj-text-3">An OpenAI-compatible embeddings endpoint. Many LLM providers (e.g. Anthropic) do not serve embeddings, so this is a separate credential. Changing the model or dimension requires a fresh memory workspace.</p>
        <Field label="Embeddings base URL"><Input aria-label="Embeddings base URL" value={embedUrl} placeholder="https://api.openai.com/v1" onChange={(event) => setEmbedUrl(event.target.value)} /></Field>
        <Field label="Embeddings model"><Input aria-label="Embeddings model" value={embedModel} placeholder="text-embedding-3-small" onChange={(event) => setEmbedModel(event.target.value)} /></Field>
        <Field label="Embeddings dimension" error={!validDim ? "Must be a positive integer." : undefined}><Input aria-label="Embeddings dimension" type="number" min={1} value={embedDim} onChange={(event) => setEmbedDim(event.target.value)} /></Field>
        <Field label="Embeddings API key" hint={keyRequired ? "Local endpoints may use a placeholder key." : "Leave empty to keep the saved key."}><Input aria-label="Embeddings API key" type="password" autoComplete="off" value={embedKey} onChange={(event) => setEmbedKey(event.target.value)} /></Field>
      </div>

      <Button variant="primary" disabled={!canSave} onClick={() => setup.mutate()}>{setup.isPending ? "Saving…" : "Save memory configuration"}</Button>
      {setup.isError && <ErrorState detail={String(setup.error)} />}
      {message && memory?.state !== "live" && <p role="status" className="text-[12px] text-rj-text-2">{message}</p>}

      <div className="flex flex-wrap items-center gap-2 border-t border-rj-border pt-3">
        <StatusPill kind="service" state={memory?.state ?? "not_configured"} />
        <Button variant="outline" disabled={!initial.configured || restart.isPending || busy} onClick={() => restart.mutate()}>{restart.isPending ? "Restarting…" : "Restart OpenViking"}</Button>
        <Button variant="outline" disabled={check.isPending} onClick={() => check.mutate()}>{check.isPending ? "Checking…" : "Check OpenViking connection"}</Button>
      </div>
      {memory && <p role="status" className="text-[12px] text-rj-text-2">{memory.state === "not_configured" ? "Configure the language and embedding models and save to enable OpenViking." : memory.detail}</p>}
      {check.data && <p role="status" className="text-[12px] text-rj-text-2">{check.data.detail}</p>}
      {restart.isError && <ErrorState detail={String(restart.error)} />}{check.isError && <ErrorState detail={String(check.error)} />}
    </div>
  </Panel>;
}
