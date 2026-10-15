import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";

/**
 * Engine lifecycle manager — pure logic + injected side effects so the state
 * machine is unit-testable without Electron.
 *
 * Resolution order for the engine command:
 *   1. REDJOHN_ENGINE_CMD (dev override; split on whitespace)
 *   2. Documented dev default: ["python", "-m", "redjohn_core.serve"]
 *   3. Packaged builds: <resourcesPath>/engine/redjohn-engine[.exe]
 *
 * The engine binds loopback only (--host 127.0.0.1). The per-profile
 * profile.lock (in the profile directory) carries {port, token, pid}; if a
 * live profile.lock is found we attach instead of spawning (per-profile lock
 * respect). The token is never placed in URLs or logs.
 */

export type EngineState = "stopped" | "starting" | "running" | "stopping" | "failed";

export interface EngineInfo {
  state: EngineState;
  /** Base URL including /api/v1, loopback only. */
  baseUrl: string | null;
  profileDir: string;
  pid: number | null;
  /** True when attached to an engine we did not spawn. */
  attached: boolean;
  detail: string | null;
}

export interface ProfileLock {
  port: number;
  token: string;
  pid?: number;
  started_at?: string;
}

export interface EngineManagerDeps {
  spawn: (argv: string[], opts: { cwd?: string; env: Record<string, string> }) => EngineChild;
  readProfileLock: (profileDir: string) => ProfileLock | null;
  isProcessAlive: (pid: number) => boolean;
  /** Probe GET /status with the token; resolves true when the engine answers. */
  probe: (baseUrl: string, token: string) => Promise<boolean>;
  /** Ask both attached and newly spawned engines to provision local memory. */
  bootstrapMemory?: (baseUrl: string, token: string) => Promise<void>;
  /** Find a free loopback port. */
  freePort: () => Promise<number>;
  isPackaged: boolean;
  resourcesPath: string;
  env: Record<string, string | undefined>;
  now?: () => number;
  sleep?: (ms: number) => Promise<void>;
  onState?: (info: EngineInfo) => void;
}

export interface EngineChild {
  pid: number | undefined;
  onExit: (cb: (code: number | null, signal: string | null) => void) => void;
  onError?: (cb: (error: Error) => void) => void;
  kill: (signal: "SIGTERM" | "SIGKILL") => boolean;
}

export const DEFAULT_DEV_ENGINE_CMD = ["python", "-m", "redjohn_core.serve"];
export const ENGINE_BIN_NAME = process.platform === "win32" ? "redjohn-engine.exe" : "redjohn-engine";
export const API_BASE_PATH = "/api/v1";

const READY_TIMEOUT_MS = 30_000;
const STOP_TIMEOUT_MS = 8_000;

export function parseCommandArgs(input: string): string[] {
  const args: string[] = [];
  let current = "";
  let inToken = false;
  let quote: "'" | '"' | null = null;

  for (let i = 0; i < input.length; i++) {
    const ch = input[i]!;
    if (quote === "'") {
      if (ch === "'") {
        quote = null;
      } else {
        current += ch;
      }
      continue;
    }
    if (quote === '"') {
      if (ch === '"') {
        quote = null;
      } else if (ch === "\\" && i + 1 < input.length && (input[i + 1] === '"' || input[i + 1] === "\\")) {
        current += input[++i]!;
      } else {
        current += ch;
      }
      continue;
    }
    if (/\s/.test(ch)) {
      if (inToken) {
        args.push(current);
        current = "";
        inToken = false;
      }
      continue;
    }
    inToken = true;
    if (ch === "'" || ch === '"') {
      quote = ch;
    } else if (ch === "\\" && i + 1 < input.length && (/\s/.test(input[i + 1]!) || input[i + 1] === "'" || input[i + 1] === '"')) {
      current += input[++i]!;
    } else {
      current += ch;
    }
  }
  if (inToken) args.push(current);
  return args;
}

export function resolveEngineCommand(deps: Pick<EngineManagerDeps, "isPackaged" | "resourcesPath" | "env">): string[] {
  const fromEnv = deps.env.REDJOHN_ENGINE_CMD?.trim();
  if (fromEnv) {
    const parsed = parseCommandArgs(fromEnv);
    if (parsed.length > 0) return parsed;
  }
  if (deps.isPackaged) {
    const p = join(deps.resourcesPath, "engine", ENGINE_BIN_NAME);
    return [p];
  }
  return [...DEFAULT_DEV_ENGINE_CMD];
}

export class EngineManager {
  private state: EngineState = "stopped";
  private child: EngineChild | null = null;
  private info: EngineInfo;
  private token: string | null = null;
  private stoppingPromise: Promise<void> | null = null;
  /**
   * Monotonic token identifying the current start() attempt. A restart issued
   * during the readiness window sets a new "starting" state, which the stale
   * start()'s loop cannot distinguish from its own by the state string alone —
   * it would then adopt the new engine's lock and report its dead child's pid.
   * Each start() captures this and bails as soon as a newer attempt supersedes it.
   */
  private startGeneration = 0;

  constructor(private deps: EngineManagerDeps) {
    this.info = {
      state: "stopped",
      baseUrl: null,
      profileDir: profileDirFromEnv(deps.env),
      pid: null,
      attached: false,
      detail: null,
    };
  }

  getInfo(): EngineInfo {
    return { ...this.info };
  }

  /** Returns the engine token. Never log it. */
  getToken(): string | null {
    return this.token;
  }

  private setState(state: EngineState, patch?: Partial<EngineInfo>): void {
    this.state = state;
    this.info = { ...this.info, ...patch, state };
    this.deps.onState?.(this.getInfo());
  }

  private async prepareMemory(baseUrl: string, token: string): Promise<string | null> {
    if (this.deps.env.RJ_MEMORY_AUTO_START === "0") return null;
    try {
      await this.deps.bootstrapMemory?.(baseUrl, token);
      return null;
    } catch {
      return "The engine is ready, but automatic local memory startup could not be requested. Check Settings → Memory.";
    }
  }

  /** Attach to a running engine or spawn a new one. Idempotent. */
  async start(): Promise<EngineInfo> {
    if (this.stoppingPromise) {
      await this.stoppingPromise;
    }
    if (this.state === "running" || this.state === "starting") return this.getInfo();
    const gen = ++this.startGeneration;
    this.setState("starting", { detail: null });

    // 1. Respect the per-profile lock: live profile.lock -> attach.
    const existing = this.deps.readProfileLock(this.info.profileDir);
    if (existing) {
      const baseUrl = loopbackBase(existing.port);
      if (await this.deps.probe(baseUrl, existing.token)) {
        if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
        const detail = await this.prepareMemory(baseUrl, existing.token);
        if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
        this.token = existing.token;
        this.setState("running", {
          baseUrl,
          pid: existing.pid ?? null,
          attached: true,
          detail,
        });
        return this.getInfo();
      }
      // Only the core owns lock removal. An unavailable live owner may still
      // be booting; never unlink its lock and launch a second writer.
      if (existing.pid && this.deps.isProcessAlive(existing.pid)) {
        const sleep = this.deps.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
        const now = this.deps.now ?? Date.now;
        const deadline = now() + READY_TIMEOUT_MS;
        while (now() < deadline) {
          if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
          await sleep(250);
          if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
          const currentLock = this.deps.readProfileLock(this.info.profileDir) ?? existing;
          const currentBaseUrl = loopbackBase(currentLock.port);
          if (await this.deps.probe(currentBaseUrl, currentLock.token)) {
            if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
            const detail = await this.prepareMemory(currentBaseUrl, currentLock.token);
            if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
            this.token = currentLock.token;
            this.setState("running", {
              baseUrl: currentBaseUrl,
              pid: currentLock.pid ?? existing.pid,
              attached: true,
              detail,
            });
            return this.getInfo();
          }
          if (!this.deps.isProcessAlive(currentLock.pid ?? existing.pid)) break;
        }
        if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
        if (this.deps.isProcessAlive(existing.pid)) {
          this.setState("failed", { detail: "The profile engine is running but did not become ready; inspect its logs before restarting." });
          return this.getInfo();
        }
      }
    }

    if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();

    // 2. Spawn.
    let port: number;
    try {
      port = await this.deps.freePort();
    } catch (err) {
      if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
      // A loopback bind failure (EMFILE/EADDRNOTAVAIL/EACCES) must surface as a
      // "failed" state, not reject out of the voided start() as an unhandled
      // rejection that can crash the main process.
      this.setState("failed", { detail: err instanceof Error ? err.message : String(err) });
      return this.getInfo();
    }
    if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();

    const argv = [...resolveEngineCommand(this.deps), "--host", "127.0.0.1", "--port", String(port)];
    const env: Record<string, string> = {};
    for (const [k, v] of Object.entries(this.deps.env)) if (typeof v === "string") env[k] = v;
    env.REDJOHN_HOME = this.deps.env.REDJOHN_HOME ?? resolve(this.deps.env.HOME ?? this.deps.env.USERPROFILE ?? homedir(), ".redjohn");
    env.REDJOHN_PROFILE = this.deps.env.REDJOHN_PROFILE ?? "default";
    // The local engine owns memory provisioning. Keep it asynchronous so a
    // first model download cannot prevent the desktop from becoming usable.
    env.RJ_MEMORY_AUTO_START = this.deps.env.RJ_MEMORY_AUTO_START ?? "1";
    env.PYTHONDONTWRITEBYTECODE = this.deps.env.PYTHONDONTWRITEBYTECODE ?? "1";

    let child: EngineChild;
    try {
      child = this.deps.spawn(argv, { env });
    } catch (err) {
      this.setState("failed", { detail: err instanceof Error ? err.message : String(err) });
      return this.getInfo();
    }
    this.child = child;
    child.onError?.((error) => {
      if (this.child !== child || this.startGeneration !== gen) return;
      this.child = null;
      this.token = null;
      this.setState("failed", { detail: error.message, baseUrl: null, pid: null });
    });
    child.onExit((code, signal) => {
      if (this.child !== child || this.startGeneration !== gen) return;
      // Unexpected exit while we consider it running/starting.
      if (this.state === "running" || this.state === "starting") {
        this.token = null;
        this.setState("failed", { detail: `engine exited (code=${code ?? "?"}, signal=${signal ?? "?"})` });
        this.child = null;
      }
    });

    // 3. Wait for readiness: profile.lock appears + probe succeeds.
    // Note: in packaged PyInstaller builds, `child.pid` is the outer bootloader
    // while `sj.pid` in profile.lock is the inner worker process. Match `sj.port === port`
    // (and ignore any pre-existing stale lock from step 1 that had the same port/pid).
    const stalePid = existing?.port === port ? existing.pid : undefined;
    const now = this.deps.now ?? Date.now;
    const sleep = this.deps.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
    const deadline = now() + READY_TIMEOUT_MS;
    while (now() < deadline) {
      if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
      const sj = this.deps.readProfileLock(this.info.profileDir);
      if (sj && sj.port === port && (stalePid === undefined || sj.pid !== stalePid)) {
        const baseUrl = loopbackBase(sj.port);
        if (await this.deps.probe(baseUrl, sj.token)) {
          if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
          this.token = sj.token;
          const detail = await this.prepareMemory(baseUrl, sj.token);
          if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
          this.setState("running", { baseUrl, pid: child.pid ?? sj.pid ?? null, attached: false, detail });
          return this.getInfo();
        }
      }
      await sleep(250);
    }

    if (this.getInfo().state !== "starting" || this.startGeneration !== gen) return this.getInfo();
    // Timeout — stop the child we spawned.
    await this.stop();
    this.setState("failed", { detail: "engine did not become ready within 30s" });
    return this.getInfo();
  }

  /** Orderly stop of an engine we spawned. Safe to call repeatedly. */
  async stop(): Promise<void> {
    if (this.stoppingPromise) return this.stoppingPromise;
    this.startGeneration++;
    this.stoppingPromise = (async () => {
      const child = this.child;
      if (!child) {
        // Attached engine: we do not kill foreign processes via this path.
        this.token = null;
        this.setState("stopped", { baseUrl: null, pid: null, attached: false });
        return;
      }
      this.setState("stopping");
      const sleep = this.deps.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));
      let exited = false;
      child.onExit(() => {
        exited = true;
      });
      try {
        child.kill("SIGTERM");
      } catch {
        exited = true;
      }
      const now = this.deps.now ?? Date.now;
      const deadline = now() + STOP_TIMEOUT_MS;
      while (!exited && now() < deadline) await sleep(100);
      if (!exited) {
        try {
          child.kill("SIGKILL");
        } catch {
          /* gone */
        }
      }
      this.child = null;
      this.token = null;
      this.setState("stopped", { baseUrl: null, pid: null, attached: false });
    })().finally(() => {
      this.stoppingPromise = null;
    });
    return this.stoppingPromise;
  }
}

export function profileDirFromEnv(env: Record<string, string | undefined>): string {
  const home = env.REDJOHN_HOME ?? resolve(env.HOME ?? env.USERPROFILE ?? homedir(), ".redjohn");
  const profile = env.REDJOHN_PROFILE ?? "default";
  // Match pathlib.Path(home) / profile, including absolute profile overrides.
  return isAbsolute(profile) ? resolve(profile) : resolve(home, profile);
}

export function loopbackBase(port: number): string {
  return `http://127.0.0.1:${port}${API_BASE_PATH}`;
}
