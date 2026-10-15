import { useState, type ReactNode } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Button, ErrorState, LoadingState } from "@redjohn/ui";
import { useEngine } from "../lib/engine";

export function MemoryReadyGate({ children }: { children: ReactNode }) {
  const { api } = useEngine();
  const [ready, setReady] = useState(false);
  const config = useQuery({
    queryKey: ["memory-config"],
    queryFn: () => api!.getMemoryConfig(),
    enabled: !!api && !ready,
  });
  const isUnconfigured = config.data?.configured === false;
  const status = useQuery({
    queryKey: ["status"],
    queryFn: () => api!.getStatus(),
    enabled: !!api && !!config.data?.configured && !ready,
    refetchInterval: ready ? false : 500,
  });
  const isMemoryLive = status.data?.services.some(
    (service) => service.service === "openviking" && service.state === "live",
  ) === true;
  const effectiveReady = ready || isUnconfigured || isMemoryLive;
  const retry = useMutation({
    mutationFn: () => api!.autoStartMemory(),
    onSuccess: async () => {
      await config.refetch();
      await status.refetch();
    },
  });
  const memory = status.data?.services.find((service) => service.service === "openviking");
  if (effectiveReady) return children;
  const openMemorySettings = () => {
    setReady(true);
    window.dispatchEvent(new CustomEvent("redjohn:navigate", { detail: { page: "settings", section: "memory" } }));
  };
  const error =
    config.error ||
    status.error ||
    (memory?.state === "down" || memory?.state === "not_configured" ? memory.detail : null);
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-3 p-6">
      {error ? (
        <>
          <ErrorState title="OpenViking could not start" detail={String(error)} />
          <div className="flex gap-2">
            <Button disabled={retry.isPending} onClick={() => retry.mutate()}>
              Retry connection
            </Button>
            <Button onClick={openMemorySettings}>Open memory settings</Button>
          </div>
        </>
      ) : (
        <>
          <LoadingState label={memory?.detail || "Loading OpenViking…"} />
          {/* Never trap the user behind a long or stuck memory startup (e.g. a first
              multi-GB model download, or a service wedged in "starting"/"degraded").
              Memory startup is asynchronous by design, so always allow continuing. */}
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => setReady(true)}>
              Continue to app
            </Button>
            <Button variant="ghost" onClick={openMemorySettings}>
              Memory settings
            </Button>
          </div>
        </>
      )}
      {retry.isError && <ErrorState detail={String(retry.error)} />}
    </div>
  );
}
