/**
 * UI-only preferences store (window bounds, panel sizes, selection, follow).
 * Secrets are NEVER stored here — engine secrets go through the engine
 * settings endpoint only.
 */
import Store from "electron-store";

export interface UiPrefs {
  windowBounds?: { x?: number; y?: number; width: number; height: number };
  terminalFollow?: boolean;
  terminalMaximized?: boolean;
  selectedRunId?: string | null;
  selectedAgentByRun?: Record<string, string | null>;
}

const ALLOWED_KEYS = new Set<keyof UiPrefs>([
  "windowBounds",
  "terminalFollow",
  "terminalMaximized",
  "selectedRunId",
  "selectedAgentByRun",
]);

export class PrefsStore {
  private store: Store<UiPrefs>;

  constructor(cwd?: string) {
    this.store = new Store<UiPrefs>({ name: "ui-prefs", ...(cwd ? { cwd } : {}) });
  }

  get<K extends keyof UiPrefs>(key: K): UiPrefs[K] | undefined {
    if (!ALLOWED_KEYS.has(key)) return undefined;
    return this.store.get(key);
  }

  set<K extends keyof UiPrefs>(key: K, value: UiPrefs[K]): boolean {
    // The ALLOWED_KEYS allowlist is the guarantee that no secret is ever
    // persisted here: only these fixed UI-only keys are accepted. (A previous
    // "defense in depth" check tested the key *name* against a secret pattern,
    // which no allowed key can ever match — dead code — so it is removed.)
    if (!ALLOWED_KEYS.has(key)) return false;
    if (value === undefined) {
      this.store.delete(key);
    } else {
      this.store.set(key, value);
    }
    return true;
  }
}
