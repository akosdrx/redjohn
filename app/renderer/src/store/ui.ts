/**
 * Local UI state only (panel sizes, selection, follow). Persisted via the
 * preload prefs bridge (electron-store) with localStorage as dev fallback.
 * Secrets are NEVER stored here.
 */
import { create } from "zustand";
import { bridge } from "../bridge";

interface UiState {
  selectedRunId: string | null;
  /** Selected agent per run (null = "All agents" tab). */
  selectedAgentByRun: Record<string, string | null>;
  terminalFollow: boolean;
  terminalMaximized: boolean;

  selectRun: (runId: string | null) => void;
  forgetRun: (runId: string) => void;
  selectAgent: (runId: string, agentId: string | null) => void;
  setTerminalFollow: (follow: boolean) => void;
  setTerminalMaximized: (max: boolean) => void;
  hydrate: () => Promise<void>;
}

const LS_KEY = "redjohn-ui-prefs";

interface Persisted {
  selectedRunId: string | null;
  selectedAgentByRun: Record<string, string | null>;
  terminalFollow: boolean;
  terminalMaximized: boolean;
}

function loadPersisted(): Partial<Persisted> {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (raw) return JSON.parse(raw) as Partial<Persisted>;
  } catch {
    /* ignore */
  }
  return {};
}

function persistLocal(state: Persisted): void {
  try {
    localStorage.setItem(LS_KEY, JSON.stringify(state));
  } catch {
    /* ignore */
  }
}

function persistPref<K extends keyof Persisted>(key: K, value: Persisted[K]): void {
  // Best-effort mirror into electron-store (UI prefs only). A persistence
  // failure (e.g. read-only userData) must not surface as an unhandled
  // rejection across the IPC bridge.
  void bridge.setPref(key, value).catch(() => {});
}

function snapshot(s: UiState): Persisted {
  return {
    selectedRunId: s.selectedRunId,
    selectedAgentByRun: s.selectedAgentByRun,
    terminalFollow: s.terminalFollow,
    terminalMaximized: s.terminalMaximized,
  };
}

export const useUiStore = create<UiState>((set, get) => ({
  selectedRunId: null,
  selectedAgentByRun: {},
  terminalFollow: true,
  terminalMaximized: false,

  selectRun: (runId) => {
    set({ selectedRunId: runId });
    persistLocal(snapshot(get()));
    persistPref("selectedRunId", runId);
  },
  forgetRun: (runId) => {
    const prevRunId = get().selectedRunId;
    set((state) => {
      const selectedAgentByRun = { ...state.selectedAgentByRun };
      delete selectedAgentByRun[runId];
      return { selectedAgentByRun, selectedRunId: state.selectedRunId === runId ? null : state.selectedRunId };
    });
    const next = snapshot(get());
    persistLocal(next);
    persistPref("selectedAgentByRun", next.selectedAgentByRun);
    if (prevRunId === runId) {
      persistPref("selectedRunId", next.selectedRunId);
    }
  },
  selectAgent: (runId, agentId) => {
    set((s) => ({ selectedAgentByRun: { ...s.selectedAgentByRun, [runId]: agentId } }));
    const next = snapshot(get());
    persistLocal(next);
    persistPref("selectedAgentByRun", next.selectedAgentByRun);
  },
  setTerminalFollow: (follow) => {
    set({ terminalFollow: follow });
    persistLocal(snapshot(get()));
    persistPref("terminalFollow", follow);
  },
  setTerminalMaximized: (max) => {
    set({ terminalMaximized: max });
    persistLocal(snapshot(get()));
    persistPref("terminalMaximized", max);
  },

  hydrate: async () => {
    const local = loadPersisted();
    set({
      selectedRunId: local.selectedRunId ?? null,
      selectedAgentByRun: local.selectedAgentByRun ?? {},
      terminalFollow: local.terminalFollow ?? true,
      terminalMaximized: local.terminalMaximized ?? false,
    });
    // Prefer electron-store values when available (single truth in the app).
    const [runId, agents, follow, maximized] = await Promise.all([
      bridge.getPref("selectedRunId"),
      bridge.getPref("selectedAgentByRun"),
      bridge.getPref("terminalFollow"),
      bridge.getPref("terminalMaximized"),
    ]);
    set({
      ...(typeof runId === "string" || runId === null ? { selectedRunId: runId } : {}),
      ...(agents && typeof agents === "object" ? { selectedAgentByRun: agents as Record<string, string | null> } : {}),
      ...(typeof follow === "boolean" ? { terminalFollow: follow } : {}),
      ...(typeof maximized === "boolean" ? { terminalMaximized: maximized } : {}),
    });
  },
}));
