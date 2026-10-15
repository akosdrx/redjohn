/**
 * IPC handlers — narrow typed bridge. Every handler validates the sender
 * frame against the renderer origin. There is intentionally NO generic
 * "invoke anything" channel.
 */
import { app, dialog, ipcMain, shell, type BrowserWindow, type IpcMainInvokeEvent } from "electron";
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import type { EngineManager, EngineInfo } from "./engine.js";
import { isTrustedSender } from "./security.js";
import type { PrefsStore, UiPrefs } from "./prefs.js";

export interface IpcContext {
  engine: EngineManager;
  prefs: PrefsStore;
  rendererOrigin: string;
  getWindow: () => BrowserWindow | null;
  /** Ask the engine for active run count; null when unknown. */
  countActiveRuns: () => Promise<number | null>;
  /** The quit-stop/quit-keep channels exist only for the native smoke test. */
  smokeTest: boolean;
}

export const IPC = {
  engineGetInfo: "engine:get-info",
  engineGetToken: "engine:get-token",
  engineRestart: "engine:restart",
  prefsGet: "prefs:get",
  prefsSet: "prefs:set",
  logsOpen: "logs:open",
  quitStopEngine: "app:quit-stop-engine",
  quitKeepEngine: "app:quit-keep-engine",
  // main -> renderer
  engineStatus: "engine:status",
} as const;

function guard(event: IpcMainInvokeEvent, rendererOrigin: string): void {
  if (!isTrustedSender(event.senderFrame?.url ?? "", rendererOrigin)) {
    throw new Error("untrusted IPC sender");
  }
}

export function registerIpc(ctx: IpcContext): void {
  ipcMain.handle(IPC.engineGetInfo, (e): EngineInfo => {
    guard(e, ctx.rendererOrigin);
    return ctx.engine.getInfo();
  });

  ipcMain.handle(IPC.engineGetToken, (e): string | null => {
    guard(e, ctx.rendererOrigin);
    return ctx.engine.getToken();
  });

  ipcMain.handle(IPC.engineRestart, async (e): Promise<EngineInfo> => {
    guard(e, ctx.rendererOrigin);
    await ctx.engine.stop();
    return ctx.engine.start();
  });

  ipcMain.handle(IPC.prefsGet, (e, key: keyof UiPrefs) => {
    guard(e, ctx.rendererOrigin);
    // Return the raw value: `undefined` means "unset", distinct from a stored
    // `null`. Collapsing both to `null` made hydrate() overwrite a valid
    // localStorage selection on first run (and every browser-dev reload).
    return ctx.prefs.get(key);
  });

  ipcMain.handle(IPC.prefsSet, (e, key: keyof UiPrefs, value: UiPrefs[keyof UiPrefs]) => {
    guard(e, ctx.rendererOrigin);
    return ctx.prefs.set(key, value);
  });

  ipcMain.handle(IPC.logsOpen, async (e) => {
    guard(e, ctx.rendererOrigin);
    const dir = join(ctx.engine.getInfo().profileDir, "logs");
    try {
      mkdirSync(dir, { recursive: true });
    } catch {
      /* ignore if read-only or already exists */
    }
    await shell.openPath(dir);
  });

  // These hard-exit the app (bypassing the close dialog / stop-or-keep choice)
  // and exist only to drive the native smoke test. Registering them in normal
  // builds would hand any renderer script a way to force-quit; gate them.
  if (ctx.smokeTest) {
    ipcMain.handle(IPC.quitStopEngine, async (e) => {
      guard(e, ctx.rendererOrigin);
      await ctx.engine.stop();
      app.exit(0);
    });

    ipcMain.handle(IPC.quitKeepEngine, (e) => {
      guard(e, ctx.rendererOrigin);
      app.exit(0);
    });
  }
}

/**
 * Install window-close semantics: when the user closes the window while
 * the engine runs active work, ask whether to stop the engine or leave it
 * running in the background (no orphans, explicit choice).
 */
let beforeQuitInstalled = false;
/** An app quit is in progress; the window-close handler must not intercept it. */
let quitting = false;
/** The user explicitly chose to leave the spawned engine running in the background. */
let keepEngineAlive = false;

export function installCloseSemantics(win: BrowserWindow, ctx: IpcContext): void {
  // Reset `keepEngineAlive` whenever a new window is created (e.g. macOS dock
  // reopen after previously choosing "Keep engine running").
  keepEngineAlive = false;

  // `before-quit` is process-global: register it once even though this runs
  // per window (e.g. on macOS dock reopen), or listeners would accumulate.
  // On ANY real app quit (Cmd+Q, menu Quit, OS logout) a spawned engine is
  // stopped first so quitting never orphans it — unless the user explicitly
  // chose to keep it running. Attached (foreign) engines are never killed here.
  if (!beforeQuitInstalled) {
    beforeQuitInstalled = true;
    app.on("before-quit", (event) => {
      if (quitting || keepEngineAlive) return;
      const info = ctx.engine.getInfo();
      if (info.attached || (info.state !== "running" && info.state !== "starting")) return;
      event.preventDefault();
      quitting = true;
      void ctx.engine.stop().finally(() => app.quit());
    });
  }

  // Per-window latch so a resolved dialog can let THIS window close without the
  // handler re-intercepting. Using a module-global here (the previous bug) left
  // the dialog permanently disabled for every later window after the first quit
  // or close — e.g. on macOS dock reopen.
  let allowClose = false;
  let closePromptInFlight = false;
  win.on("close", (event) => {
    if (allowClose || quitting) return;
    const info = ctx.engine.getInfo();
    if ((info.state !== "running" && info.state !== "starting") || info.attached) return; // attached engines are left alone
    event.preventDefault();
    if (closePromptInFlight) return;
    closePromptInFlight = true;
    void (async () => {
      try {
        const active = await ctx.countActiveRuns();
        if (win.isDestroyed()) return;
        const unknown = active === null;
        const hasWork = (active ?? 0) > 0;
        // Fail-safe: an unknown count (timeout / error / no token) must NOT be
        // treated as "no work". Always offer Cancel and make the non-destructive
        // "Keep engine running" the default unless the engine is known-idle.
        const choice = await dialog.showMessageBox(win, {
          type: "question",
          buttons: ["Keep engine running", "Stop engine and quit", "Cancel"],
          defaultId: hasWork || unknown ? 0 : 1,
          cancelId: 2,
          title: "Quit RedJohn",
          message: hasWork
            ? `${active} pentest${active === 1 ? " is" : "s are"} still running.`
            : unknown
              ? "Could not confirm whether pentests are still running."
              : "The local engine is running.",
          detail: hasWork
            ? "Stopping the engine halts all active pentests. Keeping it running leaves the engine and its runs alive in the background."
            : unknown
              ? "The engine did not answer in time. Stopping it would halt any pentests that may still be running."
              : "You can stop the engine or leave it running in the background.",
        });
        if (choice.response === 2) return; // cancel
        if (choice.response === 1) {
          // Stop the engine and quit the WHOLE app, so "and quit" is honoured on
          // macOS too (where closing the last window does not quit the app).
          quitting = true;
          await ctx.engine.stop();
          app.quit();
          return;
        }
        // Keep engine running: close this window only. On macOS the app stays in
        // the dock; the detached engine survives for re-attach on next launch.
        keepEngineAlive = true;
        allowClose = true;
        if (!win.isDestroyed()) win.close();
      } finally {
        closePromptInFlight = false;
      }
    })();
  });
}
