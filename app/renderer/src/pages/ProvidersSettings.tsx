import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, Dialog, EmptyState, ErrorState, Field, Input, LoadingState, Panel, Select } from "@redjohn/ui";
import { useEngine } from "../lib/engine";
import type { ProviderConnection } from "../lib/api";
import { connectionName, modelName } from "../lib/modelNames";

type Step = "provider" | "auth" | "model";
const empty = { id: "", label: "", provider: "", model: "", base_url: "", api_key: "" };

export function ProvidersSettings() {
  const { api } = useEngine();
  const qc = useQueryClient();
  const catalog = useQuery({ queryKey: ["provider-catalog"], queryFn: () => api!.getProviderCatalog(), enabled: !!api });
  const connections = useQuery({ queryKey: ["providers"], queryFn: () => api!.listProviders(), enabled: !!api });
  const [step, setStep] = useState<Step>("provider");
  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const [modelSearch, setModelSearch] = useState("");
  const [form, setForm] = useState(empty);
  const [message, setMessage] = useState("");
  useEffect(() => {
    if (!message) return;
    const timer = setTimeout(() => setMessage(""), 4000);
    return () => clearTimeout(timer);
  }, [message]);
  const provider = catalog.data?.providers.find((item) => item.id === form.provider);
  const isOAuth = form.provider === "codex";
  const codex = useQuery({ queryKey: ["codex-auth"], queryFn: () => api!.getCodexStatus(), enabled: !!api && isOAuth && open, refetchInterval: (query) => query.state.data?.login?.state === "pending" ? 2000 : false });
  const refresh = useMutation({ mutationFn: () => api!.refreshProviderCatalog(), onSuccess: (data) => qc.setQueryData(["provider-catalog"], data) });
  const login = useMutation({ mutationFn: () => api!.startCodexLogin(), onSuccess: () => qc.invalidateQueries({ queryKey: ["codex-auth"] }) });
  const logout = useMutation({ mutationFn: () => api!.logoutCodex(), onSuccess: () => qc.invalidateQueries({ queryKey: ["codex-auth"] }) });
  const discovery = useMutation({ mutationFn: () => api!.discoverProviderModels({ base_url: form.base_url, ...(form.id ? { id: form.id } : {}), ...(form.api_key ? { api_key: form.api_key } : {}) }), onSuccess: (models) => { if (models.length) { setForm((value) => ({ ...value, model: value.model || models[0]!.id })); setStep("model"); } } });
  const save = useMutation({ mutationFn: () => api!.saveProvider({ ...form, id: form.id || undefined, api_key: form.api_key || undefined }), onSuccess: async () => { setForm(empty); setOpen(false); setMessage("Provider connection saved."); await qc.invalidateQueries({ queryKey: ["providers"] }); } });
  const action = useMutation({ mutationFn: async ({ type, id }: { type: "use" | "delete" | "check"; id: string }) => {
    if (type === "use") { await api!.activateProvider(id); return "Model selected for the engine."; }
    if (type === "delete") { await api!.deleteProvider(id); return "Connection removed."; }
    return (await api!.checkProvider(id)).detail;
  }, onSuccess: async (result) => { setMessage(result); await qc.invalidateQueries({ queryKey: ["providers"] }); } });
  const models = isOAuth ? codex.data?.models ?? [] : form.provider === "custom" ? discovery.data ?? [] : provider?.models ?? [];
  const filteredModels = models.filter((item) => item.id === form.model || item.name.toLowerCase().includes(modelSearch.toLowerCase()));
  function choose(id: string) {
    const item = catalog.data?.providers.find((candidate) => candidate.id === id);
    setForm({ ...empty, provider: id, base_url: item?.base_url ?? "" }); setStep("auth"); discovery.reset(); save.reset(); setModelSearch("");
  }
  function edit(item: ProviderConnection) { setForm({ id: item.id, label: item.label, provider: item.provider, model: item.model, base_url: item.base_url, api_key: "" }); setStep("auth"); setOpen(true); discovery.reset(); save.reset(); }
  if (catalog.isPending || connections.isPending) return <LoadingState />;
  if (catalog.isError || connections.isError) return <ErrorState detail={String(catalog.error || connections.error)} onRetry={() => { void catalog.refetch(); void connections.refetch(); }} />;
  const auth = codex.data?.login;
  const list = catalog.data.providers.filter((item) => !(item.id === "codex" && catalog.data.providers.some((p) => p.id === "openai")) && item.name.toLowerCase().includes(search.toLowerCase()));
  return <div className="flex flex-col gap-3">
    <div>
      <Button variant="primary" onClick={() => { setForm(empty); setSearch(""); setStep("provider"); setOpen(true); }}>Add provider connection</Button>
    </div>
    <Panel title="Connected models" padded>
      {!connections.data.items?.length && <EmptyState title="No provider connections yet." />}
      <ul className="flex flex-col gap-2">{(connections.data.items ?? []).map((item) => <li key={item.id} className="flex flex-wrap items-center gap-2 rounded-md border border-rj-border p-3">
        <div className="min-w-0 flex-1"><strong className="block break-words text-[13px]">{connectionName(item, catalog.data)}</strong><span className="text-[12px] text-rj-text-2">{item.label} · {item.auth_method === "oauth" ? "Subscription" : "API key"}</span>{connections.data.active_provider === item.id && <span className="ml-2 text-[11px] text-rj-live">In use</span>}</div>
        <Button size="sm" variant="outline" onClick={() => edit(item)}>Edit</Button>
        <Button size="sm" variant="outline" disabled={action.isPending} onClick={() => action.mutate({ type: "check", id: item.id })} title="Sends a small model request.">Check connection</Button>
        <Button size="sm" variant="outline" disabled={action.isPending || connections.data.active_provider === item.id} onClick={() => action.mutate({ type: "use", id: item.id })}>Use</Button>
        <Button size="sm" variant="ghost" disabled={action.isPending || connections.data.active_provider === item.id} onClick={() => action.mutate({ type: "delete", id: item.id })}>Remove</Button>
      </li>)}</ul>
      {message && <p role="status" className="mt-3 text-[12px] text-rj-live">{message}</p>}{action.isError && <ErrorState detail={String(action.error)} />}
    </Panel>
    <Dialog open={open} onClose={() => { setOpen(false); setForm(empty); }} title={step === "provider" ? "Connect a provider" : provider?.name ?? "Provider connection"} width={600}>
      <div className="flex flex-col gap-4">
        {step === "provider" ? <>
          <Input aria-label="Search providers" placeholder="Search providers…" value={search} onChange={(event) => setSearch(event.target.value)} />
          <ul aria-label="Provider list" className="max-h-80 overflow-y-auto">{list.map((item) => <li key={item.id}><button data-provider={item.id} type="button" className="flex w-full items-center justify-between rounded px-3 py-3 text-left text-[13px] hover:bg-rj-panel-hover focus-visible:outline-2 focus-visible:outline-rj-accent" onClick={() => choose(item.id)}>
            <span>{item.id === "openai" ? "OpenAI" : item.name}</span><span className="text-[11px] text-rj-text-3">{item.id === "openai" || item.id === "codex" ? "API key / subscription" : "API key"}</span>
          </button></li>)}</ul>
        </> : <>
          <Button size="sm" variant="ghost" className="self-start" onClick={() => setStep(step === "model" ? "auth" : "provider")}>Back</Button>
          {step === "auth" ? <>
            {(form.provider === "openai" || isOAuth) && <Field label="Authentication"><Select aria-label="Authentication method" value={isOAuth ? "oauth" : "api_key"} onChange={(event) => { const id = event.target.value === "oauth" ? "codex" : "openai"; const item = catalog.data.providers.find((p) => p.id === id); setForm({ ...empty, provider: id, base_url: item?.base_url ?? "" }); }}><option value="api_key">API key</option><option value="oauth">ChatGPT subscription (OAuth)</option></Select></Field>}
            {isOAuth ? <>
              <p className="text-[12px] text-rj-text-2">Sign in with your ChatGPT subscription.</p>
              {codex.isPending ? <LoadingState /> : codex.isError ? <ErrorState detail={String(codex.error)} /> : !codex.data.available ? <p className="text-[12px]">The official Codex CLI is required for subscription sign-in.</p> : codex.data.authenticated ? <p role="status" className="text-[12px] text-rj-live">Signed in{codex.data.plan ? ` · ${codex.data.plan}` : ""}</p> : <Button variant="primary" disabled={login.isPending} onClick={() => login.mutate()}>Sign in with Codex</Button>}
              {auth?.state === "pending" && <p role="status" className="text-[12px]">Open <a className="text-rj-link underline" href={auth.verificationUrl} target="_blank" rel="noreferrer">the sign-in page</a> and enter <strong className="select-all">{auth.userCode}</strong>. Waiting for sign-in…</p>}
              {auth?.state === "failed" && <p role="alert" className="text-[12px] text-rj-down">Sign-in failed or expired. Try again.</p>}
              {(codex.data?.authenticated || auth?.state === "pending") && <Button variant="ghost" disabled={logout.isPending} onClick={() => logout.mutate()}>{auth?.state === "pending" ? "Cancel sign-in" : "Sign out"}</Button>}
              {login.isError && <ErrorState detail={String(login.error)} />}{logout.isError && <ErrorState detail={String(logout.error)} />}
            </> : <>
              {form.provider === "custom" && <><Field label="Connection name"><Input aria-label="Connection name" value={form.label} placeholder="My endpoint" onChange={(event) => setForm({ ...form, label: event.target.value })} /></Field><Field label="API base URL"><Input aria-label="API base URL" value={form.base_url} placeholder="https://example.com/v1" onChange={(event) => setForm({ ...form, base_url: event.target.value })} /></Field></>}
              <Field label="API key" hint={form.id ? "Leave empty to keep your saved key." : form.provider === "custom" ? "Optional for local endpoints." : "Stored in your encrypted local profile."}><Input aria-label="Provider API key" type="password" autoComplete="off" value={form.api_key} onChange={(event) => setForm({ ...form, api_key: event.target.value })} /></Field>
            </>}
            <Button variant="primary" disabled={discovery.isPending || (isOAuth ? !codex.data?.authenticated : !form.api_key && !form.id && form.provider !== "custom")} onClick={() => {
              if (form.provider === "custom") discovery.mutate();
              else { setForm((value) => ({ ...value, model: value.model || models[0]?.id || "" })); setStep("model"); }
            }}>{discovery.isPending ? "Loading models…" : "Continue"}</Button>
            {discovery.isSuccess && !discovery.data.length && <p role="alert" className="text-[12px] text-rj-down">This endpoint returned no models.</p>}{discovery.isError && <ErrorState detail={String(discovery.error)} />}
          </> : <>
            {models.length > 15 && <Input aria-label="Search models" placeholder="Search models…" value={modelSearch} onChange={(event) => setModelSearch(event.target.value)} />}
            <Field label="Model"><Select aria-label="Provider model" value={form.model} onChange={(event) => setForm({ ...form, model: event.target.value })}>
              <option value="" disabled>Choose a model</option>{filteredModels.map((item) => <option value={item.id} key={item.id}>{item.name !== item.id ? item.name : modelName(item.id, catalog.data, form.provider)}</option>)}
            </Select></Field>
            {!models.length && <p className="text-[12px] text-rj-text-2">No models loaded. Refresh the model list and try again.</p>}
            {form.provider !== "custom" && !isOAuth && <Button variant="ghost" disabled={refresh.isPending} onClick={() => refresh.mutate()}>Refresh models</Button>}
            <Button variant="primary" disabled={save.isPending || !form.model} onClick={() => save.mutate()}>{save.isPending ? "Saving…" : "Save connection"}</Button>
            {save.isError && <ErrorState detail={String(save.error)} />}{refresh.isError && <ErrorState detail={String(refresh.error)} />}
          </>}
        </>}
      </div>
    </Dialog>
  </div>;
}
