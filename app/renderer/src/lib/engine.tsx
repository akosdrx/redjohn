/**
 * Engine context: base URL + token from the secure bridge, the typed API
 * client, and live engine status. Renders troubleshooting states when the
 * engine is down.
 */
import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { createApiClient, type ApiClient } from "./api";
import { bridge, type EngineInfoDto } from "../bridge";

export interface EngineContextValue {
  info: EngineInfoDto;
  api: ApiClient | null;
  token: string | null;
}

const EngineContext = createContext<EngineContextValue | null>(null);

export function EngineProvider({ children }: { children: ReactNode }) {
  const [info, setInfo] = useState<EngineInfoDto | null>(null);
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    let mounted = true;
    let hasLiveStatus = false;
    // Generation guard: a later status transition (e.g. "stopped" clearing the
    // token) must not be clobbered by an earlier in-flight getToken() resolving
    // afterwards, which would install a stale token and cause a 401 storm.
    let statusGen = 0;
    const applyStatus = (i: EngineInfoDto): void => {
      const gen = ++statusGen;
      if (i.state === "running") {
        // Keep state as "starting" until the token IPC resolves so App never
        // flashes the engine-down error screen while token fetch is in flight.
        setInfo((prev) => (prev?.state === "running" ? i : { ...i, state: "starting" }));
        void bridge
          .getToken()
          .then((t) => {
            if (!mounted || statusGen !== gen) return;
            if (t) {
              setToken(t);
              setInfo(i);
            } else {
              setToken(null);
              setInfo({ ...i, state: "failed", detail: i.detail ?? "Engine authentication token is unavailable." });
            }
          })
          .catch(() => {
            if (!mounted || statusGen !== gen) return;
            setToken(null);
            setInfo({ ...i, state: "failed", detail: "Could not read the engine authentication token." });
          });
      } else {
        setToken(null);
        setInfo(i);
      }
    };
    const unsub = bridge.onEngineStatus((i) => {
      if (!mounted) return;
      hasLiveStatus = true;
      applyStatus(i);
    });
    async function boot(): Promise<void> {
      try {
        const i = await bridge.getEngineInfo();
        if (!mounted || hasLiveStatus) return;
        applyStatus(i);
      } catch {
        // Without this, an IPC rejection leaves `info` null forever and the
        // provider renders nothing — a blank window with no diagnostics. Fall
        // back to a "failed" state so the app's engine-unavailable UI appears.
        if (mounted && !hasLiveStatus) {
          setInfo({ state: "failed", baseUrl: null, profileDir: "", pid: null, attached: false, detail: "Could not reach the engine." });
        }
      }
    }
    void boot();
    return () => {
      mounted = false;
      unsub();
    };
  }, []);

  // Keep the API client's identity stable across engine status messages that do
  // not change the base URL or token. `info` is a fresh object on every
  // `engine:status` event, so memoizing the client on `info` rebuilt it (and
  // tore down + replayed the run stream) on every transition. Depend only on
  // the fields the client actually uses.
  const baseUrl = info?.baseUrl ?? null;
  const api = useMemo<ApiClient | null>(
    () => (baseUrl && token ? createApiClient({ baseUrl, getToken: () => token }) : null),
    [baseUrl, token],
  );
  const value = useMemo<EngineContextValue | null>(
    () => (info ? { info, api, token } : null),
    [info, api, token],
  );

  if (!value) return null; // brief boot; App shows its own loading state before this
  return <EngineContext.Provider value={value}>{children}</EngineContext.Provider>;
}

export function useEngine(): EngineContextValue {
  const ctx = useContext(EngineContext);
  if (!ctx) throw new Error("useEngine outside EngineProvider");
  return ctx;
}
