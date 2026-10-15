import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Button, ErrorState, Field, Input, LoadingState, Panel } from "@redjohn/ui";
import { useEngine } from "../lib/engine";

export function NvdSettings() {
  const { api } = useEngine();
  const qc = useQueryClient();
  const [key, setKey] = useState("");
  const [saved, setSaved] = useState(false);
  const config = useQuery({ queryKey: ["nvd-config"], queryFn: () => api!.getNvdConfig() });
  const change = useMutation({ mutationFn: (remove: boolean) => remove ? api!.clearNvdKey() : api!.saveNvdKey(key.trim()), onSuccess: async (data) => { setKey(""); setSaved(true); qc.setQueryData(["nvd-config"], data); } });
  return <Panel title="NIST NVD vulnerability intelligence" padded>
    <div className="flex max-w-xl flex-col gap-3">
      <p className="text-[12px] text-rj-text-2">NIST NVD vulnerability intelligence works with an optional free API key.</p>
      <p className="text-[12px] text-rj-text-2">Without a key 5 req/30sec<br />With free key 50 req/30sec</p>
      <a className="text-[12px] text-rj-link underline" href="https://nvd.nist.gov/developers/request-an-api-key" target="_blank" rel="noreferrer">Get a free NVD API key</a>
      {config.isPending ? <LoadingState /> : config.isError ? <ErrorState detail={String(config.error)} onRetry={() => config.refetch()} /> : <>
        <Field label="NVD API key" hint={config.data.key_configured ? "Key configured. It is never returned to the interface." : "Optional. Saved in your encrypted local profile."}><Input aria-label="NVD API key" type="password" autoComplete="off" value={key} onChange={(event) => { setKey(event.target.value); setSaved(false); }} /></Field>
        <div className="flex gap-2"><Button variant="primary" disabled={!key.trim() || change.isPending} onClick={() => change.mutate(false)}>{change.isPending ? "Saving…" : "Save API key"}</Button>{config.data.key_configured && <Button variant="ghost" disabled={change.isPending} onClick={() => change.mutate(true)}>Remove API key</Button>}</div>
      </>}
      {saved && <p role="status" className="text-[12px] text-rj-live">NVD settings saved.</p>}{change.isError && <ErrorState detail={String(change.error)} />}
    </div>
  </Panel>;
}
