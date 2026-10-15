/**
 * Typed access to the preload bridge. In a plain browser (vite-only dev)
 * a no-op fallback is provided so the renderer still boots for UI work.
 */
import type { RedJohnBridge } from "../../preload/index";

declare global {
  interface Window {
    redjohn?: RedJohnBridge;
  }
}

export type EngineInfoDto = {
  state: "stopped" | "starting" | "running" | "stopping" | "failed";
  baseUrl: string | null;
  profileDir: string;
  pid: number | null;
  attached: boolean;
  detail: string | null;
};

const fallback: RedJohnBridge = {
  platform: "browser",
  getEngineInfo: () =>
    Promise.resolve({
      state: "stopped",
      baseUrl: null,
      profileDir: "",
      pid: null,
      attached: false,
      detail: "preload bridge unavailable (browser dev mode)",
    }),
  getToken: () => Promise.resolve(null),
  restartEngine: () => fallback.getEngineInfo(),
  onEngineStatus: () => () => {},
  // `undefined` = "no stored value", so hydrate() keeps the localStorage value
  // in browser-dev mode instead of clobbering it (a stored `null` would apply).
  getPref: () => Promise.resolve(undefined),
  setPref: () => Promise.resolve(false),
  openLogs: () => Promise.resolve(),
  quitAndStopEngine: () => Promise.resolve(),
  quitKeepEngine: () => Promise.resolve(),
};

export const bridge: RedJohnBridge = typeof window !== "undefined" && window.redjohn ? window.redjohn : fallback;
export const isElectron = typeof window !== "undefined" && !!window.redjohn;
