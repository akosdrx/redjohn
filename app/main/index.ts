/**
 * Electron main entry: window management + engine lifecycle + IPC wiring.
 */
import { app, BrowserWindow, screen } from "electron";
import { isAbsolute, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { EngineManager } from "./engine.js";
import { makeDeps } from "./engine-node.js";
import { registerIpc, installCloseSemantics, IPC, type IpcContext } from "./ipc.js";
import { PrefsStore, type UiPrefs } from "./prefs.js";
import { hardenWindow, installCspHeaders } from "./security.js";

const here = fileURLToPath(new URL(".", import.meta.url));
// Dev-only renderer override (e.g. http://localhost:5173). NEVER honoured in a
// packaged build: a production app must not load an arbitrary origin, which
// would inherit the preload bridge (engine token, restart/quit) and the relaxed
// dev CSP.
const VITE_DEV_URL = app.isPackaged ? null : (process.env.REDJOHN_RENDERER_URL ?? null);

// Automated native acceptance uses an invisible, isolated app window. No
// production profile or UI preferences are read by the smoke-test process.
const smokeTest = app.commandLine.hasSwitch("redjohn-smoke-test");
if (smokeTest) {
  const userData = app.commandLine.getSwitchValue("user-data-dir");
  if (!isAbsolute(userData)) throw new Error("smoke test requires an absolute --user-data-dir");
  app.setPath("userData", userData);
}

let mainWindow: BrowserWindow | null = null;

function rendererOrigin(): string {
  // Dev: the Vite origin. Prod: the file:// URL of the bundled renderer
  // directory, so only documents inside it are trusted for IPC/navigation
  // (a bare "file://" would trust every local file on disk).
  return VITE_DEV_URL ?? pathToFileURL(join(here, "../renderer/")).href;
}

/**
 * Validate persisted window bounds. The prefs store accepts arbitrary JSON for
 * its values (and the file can be hand-edited or corrupted), so a stored
 * NaN/string/negative or an off-screen rectangle must never reach the
 * BrowserWindow constructor. Returns only finite, sane values, and drops x/y
 * (centring the window) when the saved position no longer intersects a display.
 */
function validateBounds(bounds: UiPrefs["windowBounds"]): { width: number; height: number; x?: number; y?: number } {
  const fallback = { width: 1440, height: 900 };
  const finite = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
  if (!bounds || typeof bounds !== "object") return fallback;
  if (!finite(bounds.width) || !finite(bounds.height) || bounds.width < 400 || bounds.height < 300) return fallback;
  const size = { width: Math.min(bounds.width, 20000), height: Math.min(bounds.height, 20000) };
  if (!finite(bounds.x) || !finite(bounds.y)) return size;
  const rect = { x: bounds.x, y: bounds.y, ...size };
  const onScreen = screen.getAllDisplays().some((d) => {
    const a = d.workArea;
    return rect.x < a.x + a.width && rect.x + rect.width > a.x && rect.y < a.y + a.height && rect.y + rect.height > a.y;
  });
  return onScreen ? { ...size, x: bounds.x, y: bounds.y } : size;
}

async function createWindow(prefs: PrefsStore, ctx: IpcContext): Promise<void> {
  const bounds = validateBounds(prefs.get("windowBounds"));
  const win = new BrowserWindow({
    width: bounds.width,
    height: bounds.height,
    ...(bounds.x != null && bounds.y != null ? { x: bounds.x, y: bounds.y } : {}),
    minWidth: 960,
    minHeight: 600,
    title: "RedJohn",
    show: !smokeTest,
    backgroundColor: "#13181d",
    titleBarStyle: process.platform === "darwin" ? "hiddenInset" : "default",
    ...(process.platform === "darwin" ? { trafficLightPosition: { x: 14, y: 12 } } : {}),
    webPreferences: {
      preload: join(here, "../preload/index.cjs"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      spellcheck: false,
    },
  });
  mainWindow = win;

  let boundsTimer: ReturnType<typeof setTimeout> | null = null;
  // Drop the reference when the window is destroyed so IPC window handlers and
  // the status broadcaster never operate on a destroyed BrowserWindow.
  win.on("closed", () => {
    if (boundsTimer !== null) {
      clearTimeout(boundsTimer);
      boundsTimer = null;
    }
    if (mainWindow === win) mainWindow = null;
  });

  win.on("resized", persistBounds);
  win.on("moved", persistBounds);
  function persistBounds(): void {
    if (boundsTimer !== null) clearTimeout(boundsTimer);
    boundsTimer = setTimeout(() => {
      boundsTimer = null;
      if (!win.isDestroyed()) prefs.set("windowBounds", win.getBounds());
    }, 150);
  }

  hardenWindow(win, ctx.rendererOrigin);
  installCloseSemantics(win, ctx);

  if (VITE_DEV_URL) {
    await win.loadURL(VITE_DEV_URL);
  } else {
    await win.loadFile(join(here, "../renderer/index.html"));
  }
}

async function main(): Promise<void> {
  installCspHeaders(VITE_DEV_URL);

  const prefs = new PrefsStore();
  const engine = new EngineManager({
    ...makeDeps({
      isPackaged: app.isPackaged,
      resourcesPath: process.resourcesPath,
      env: { ...process.env, RJ_MEMORY_AUTO_START: process.env.RJ_MEMORY_AUTO_START ?? "0" },
    }),
    onState: (info) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send(IPC.engineStatus, info);
      }
    },
  });

  // IPC handlers are process-global (ipcMain) and must be registered exactly
  // once, not per window — re-registering on macOS dock reopen would throw.
  const ctx: IpcContext = {
    engine,
    prefs,
    rendererOrigin: rendererOrigin(),
    getWindow: () => mainWindow,
    smokeTest,
    countActiveRuns: async () => {
      const info = engine.getInfo();
      const token = engine.getToken();
      if (!info.baseUrl || !token) return null;
      try {
        const res = await fetch(`${info.baseUrl}/pentests?status=running&limit=1`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(2000),
        });
        if (!res.ok) return null;
        const page = (await res.json()) as { total?: number | null; items?: unknown[] };
        return page.total ?? page.items?.length ?? 0;
      } catch {
        return null;
      }
    },
  };
  registerIpc(ctx);

  // Start the engine (attach or spawn) before showing the window so the
  // renderer gets a real state immediately; failures surface in the UI. The
  // promise is observed so an unexpected rejection cannot become an unhandled
  // rejection (start() already funnels known failures into the "failed" state).
  void engine.start().catch(() => {
    /* surfaced via engine state */
  });

  await createWindow(prefs, ctx);

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      void createWindow(prefs, ctx);
    }
  });
}

// Single-instance guard (packaged builds only): prevents two end-user launches
// from racing to spawn engines against the same profile. Dev and the native
// smoke test may intentionally run several instances (isolated profiles), so it
// is not enforced there.
if (app.isPackaged && !app.requestSingleInstanceLock()) {
  app.quit();
} else {
  app.on("second-instance", () => {
    const win = mainWindow;
    if (win) {
      if (win.isMinimized()) win.restore();
      win.focus();
    }
  });
  app.whenReady().then(() => {
    main().catch((err) => {
      // No window exists yet if this throws; show a diagnostic and exit cleanly
      // rather than dying as a silent unhandled rejection.
      console.error("RedJohn failed to start:", err);
      app.exit(1);
    });
  });
}

app.on("window-all-closed", () => {
  // macOS convention: keep the app (and engine) alive until explicit quit.
  if (process.platform !== "darwin") app.quit();
});
