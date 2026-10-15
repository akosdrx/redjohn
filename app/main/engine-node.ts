/**
 * Node-bound implementation of EngineManagerDeps (Electron main process).
 * Kept separate from engine.ts so the state machine stays unit-testable.
 */
import { spawn as nodeSpawn } from "node:child_process";
import { createServer } from "node:net";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { EngineChild, EngineManagerDeps, ProfileLock } from "./engine.js";

function profileLockPath(profileDir: string): string {
  return join(profileDir, "profile.lock");
}

export function makeDeps(options: Pick<EngineManagerDeps, "isPackaged" | "resourcesPath"> & { env?: NodeJS.ProcessEnv }): EngineManagerDeps {
  return {
    ...options,
    env: options.env ?? process.env,
    spawn(argv, opts): EngineChild {
      const [cmd, ...args] = argv;
      const grouped = process.platform !== "win32";
      // Never log argv/env — they may lead to the token-bearing profile dir.
      const child = nodeSpawn(cmd!, args, {
        env: opts.env,
        cwd: opts.cwd,
        stdio: ["ignore", "pipe", "pipe"],
        // A frozen engine has a bootloader and an inner engine process. Own
        // their session so forced shutdown reaches both, without using a PID
        // from profile.lock or signalling the desktop's own process group.
        detached: grouped,
      });
      const groupId = child.pid;
      let ownsGroup = grouped && groupId !== undefined;
      const killGroup = (signal: "SIGTERM" | "SIGKILL"): boolean => {
        if (!ownsGroup || groupId === undefined) return false;
        try {
          process.kill(-groupId, signal);
          return true;
        } catch {
          return false;
        }
      };
      child.once("exit", () => {
        // A killed bootloader can leave its inner engine alive. Reap only
        // this spawn's group while its ownership lease is still held, then
        // release it so a later call cannot signal a reused group ID.
        killGroup("SIGKILL");
        ownsGroup = false;
      });
      child.once("error", () => { ownsGroup = false; });
      // Drain stdio so the child never blocks on a full pipe; do not log it
      // here (engine logs go to the profile log directory).
      child.stdout?.resume();
      child.stderr?.resume();
      return {
        pid: child.pid,
        onError: (cb) => child.on("error", cb),
        onExit: (cb) => child.on("exit", (code, signal) => cb(code, signal)),
        kill: (signal) => {
          if (grouped) return killGroup(signal);
          try {
            return child.kill(signal);
          } catch {
            return false;
          }
        },
      };
    },
    readProfileLock(profileDir) {
      try {
        const raw = readFileSync(profileLockPath(profileDir), "utf8");
        const parsed = JSON.parse(raw) as Partial<ProfileLock>;
        if (!Number.isInteger(parsed.port) || !parsed.port || parsed.port < 1 || parsed.port > 65535 || typeof parsed.token !== "string" || !parsed.token) return null;
        const out: ProfileLock = { port: parsed.port, token: parsed.token };
        if (typeof parsed.pid === "number" && Number.isInteger(parsed.pid) && parsed.pid > 0) out.pid = parsed.pid;
        if (typeof parsed.started_at === "string") out.started_at = parsed.started_at;
        return out;
      } catch {
        return null;
      }
    },
    isProcessAlive(pid) {
      try {
        process.kill(pid, 0);
        return true;
      } catch (error) {
        return (error as NodeJS.ErrnoException).code === "EPERM";
      }
    },
    async probe(baseUrl, token) {
      try {
        const res = await fetch(`${baseUrl}/status`, {
          headers: { Authorization: `Bearer ${token}` },
          signal: AbortSignal.timeout(1500),
        });
        return res.ok;
      } catch {
        return false;
      }
    },
    async bootstrapMemory(baseUrl, token) {
      const response = await fetch(`${baseUrl}/integrations/memory/auto-start`, {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` },
        signal: AbortSignal.timeout(5000),
      });
      if (!response.ok) throw new Error("Automatic memory startup request failed");
    },
    freePort() {
      return new Promise((resolve, reject) => {
        const srv = createServer();
        srv.once("error", reject);
        srv.listen(0, "127.0.0.1", () => {
          const addr = srv.address();
          const port = typeof addr === "object" && addr ? addr.port : 0;
          srv.close(() => resolve(port));
        });
      });
    },
  };
}
