/**
 * Preload — the ONLY bridge between renderer and main.
 * contextIsolation + sandbox are on; this file is built as CJS.
 * Exposes a narrow, typed API as window.redjohn. No generic invoke.
 */
import { contextBridge, ipcRenderer, type IpcRendererEvent } from "electron";

export interface EngineInfoDto {
  state: "stopped" | "starting" | "running" | "stopping" | "failed";
  baseUrl: string | null;
  profileDir: string;
  pid: number | null;
  attached: boolean;
  detail: string | null;
}

const CHANNELS = {
  engineGetInfo: "engine:get-info",
  engineGetToken: "engine:get-token",
  engineRestart: "engine:restart",
  prefsGet: "prefs:get",
  prefsSet: "prefs:set",
  logsOpen: "logs:open",
  quitStopEngine: "app:quit-stop-engine",
  quitKeepEngine: "app:quit-keep-engine",
  engineStatus: "engine:status",
} as const;

const api = {
  platform: process.platform as string,
  getEngineInfo: (): Promise<EngineInfoDto> => ipcRenderer.invoke(CHANNELS.engineGetInfo),
  getToken: (): Promise<string | null> => ipcRenderer.invoke(CHANNELS.engineGetToken),
  restartEngine: (): Promise<EngineInfoDto> => ipcRenderer.invoke(CHANNELS.engineRestart),

  onEngineStatus: (cb: (info: EngineInfoDto) => void): (() => void) => {
    const listener = (_e: IpcRendererEvent, info: EngineInfoDto): void => cb(info);
    ipcRenderer.on(CHANNELS.engineStatus, listener);
    return () => ipcRenderer.removeListener(CHANNELS.engineStatus, listener);
  },

  getPref: (key: string): Promise<unknown> => ipcRenderer.invoke(CHANNELS.prefsGet, key),
  setPref: (key: string, value: unknown): Promise<boolean> => ipcRenderer.invoke(CHANNELS.prefsSet, key, value),

  openLogs: (): Promise<void> => ipcRenderer.invoke(CHANNELS.logsOpen),
  quitAndStopEngine: (): Promise<void> => ipcRenderer.invoke(CHANNELS.quitStopEngine),
  quitKeepEngine: (): Promise<void> => ipcRenderer.invoke(CHANNELS.quitKeepEngine),
};

export type RedJohnBridge = typeof api;

contextBridge.exposeInMainWorld("redjohn", api);
