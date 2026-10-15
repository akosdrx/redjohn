/** Real forked engine-wrapper regressions; no Electron or user profile. */
import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { EngineManager } from "./engine";
import { makeDeps } from "./engine-node";

const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const resources = fileURLToPath(new URL("../../resources", import.meta.url));
const packagedEngine = join(resources, "engine", "redjohn-engine");

function alive(pid: number): boolean {
  try { process.kill(pid, 0); return true; } catch { return false; }
}

async function waitFor(condition: () => boolean): Promise<void> {
  const deadline = Date.now() + 3000;
  while (!condition() && Date.now() < deadline) await pause(20);
  expect(condition()).toBe(true);
}

async function fixture() {
  const home = await mkdtemp(join(tmpdir(), "redjohn-owned-wrapper-"));
  const workerPath = join(home, "worker.cjs");
  const wrapperPath = join(home, "wrapper.cjs");
  await writeFile(workerPath, `
const fs = require("node:fs");
const http = require("node:http");
const path = require("node:path");
const port = Number(process.argv[process.argv.indexOf("--port") + 1]);
const profile = path.join(process.env.REDJOHN_HOME, process.env.REDJOHN_PROFILE);
process.on("SIGTERM", () => {});
http.createServer((_request, response) => {
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify({ services: [] }));
}).listen(port, "127.0.0.1", () => {
  fs.mkdirSync(profile, { recursive: true });
  fs.writeFileSync(path.join(profile, "profile.lock"), JSON.stringify({
    pid: process.pid, port, token: "isolated-wrapper-test"
  }));
});
`);
  await writeFile(wrapperPath, `
const { spawn } = require("node:child_process");
const path = require("node:path");
process.on("SIGTERM", () => {});
spawn(process.execPath, [path.join(__dirname, "worker.cjs"), ...process.argv.slice(2)], {
  env: process.env, stdio: "ignore"
});
setInterval(() => {}, 1000);
`);
  const deps = makeDeps({ isPackaged: false, resourcesPath: "", env: {
    PATH: process.env.PATH ?? "", HOME: home, REDJOHN_HOME: home, REDJOHN_PROFILE: "isolated",
    REDJOHN_ENGINE_CMD: `${process.execPath} ${wrapperPath}`, RJ_MEMORY_AUTO_START: "0",
  } });
  const manager = new EngineManager(deps);
  let workerPid = 0;
  return {
    manager, deps,
    async start() {
      const info = await manager.start();
      expect(info.state).toBe("running");
      const lock = JSON.parse(await readFile(join(home, "isolated", "profile.lock"), "utf8"));
      workerPid = lock.pid;
      expect(workerPid).not.toBe(info.pid);
      expect(alive(workerPid)).toBe(true);
      return { outerPid: info.pid!, workerPid };
    },
    async cleanup() {
      await manager.stop();
      // RED runs deliberately leave the fixture worker behind. Its exact
      // unique command proves provenance before cleanup; user PIDs are ignored.
      if (workerPid && alive(workerPid)) {
        try {
          const command = execFileSync("/bin/ps", ["-p", String(workerPid), "-o", "command="], { encoding: "utf8" });
          if (command.includes(workerPath)) process.kill(workerPid, "SIGKILL");
        } catch { /* Fixture already exited. */ }
      }
      await rm(home, { recursive: true, force: true });
    },
  };
}

describe("owned engine process group", () => {
  it.skipIf(process.platform === "win32")("forced manager stop kills both wrapper and stubborn engine worker", async () => {
    const run = await fixture();
    try {
      const { outerPid, workerPid } = await run.start();
      // Advance the state-machine deadline while exercising actual OS signals.
      let clock = 0;
      run.deps.now = () => (clock += 10_000);
      await run.manager.stop();
      await waitFor(() => !alive(outerPid) && !alive(workerPid));
      expect(run.manager.getInfo().state).toBe("stopped");
    } finally { await run.cleanup(); }
  }, 40_000);

  it.skipIf(process.platform === "win32")("unexpected wrapper SIGKILL also reaps its surviving engine worker", async () => {
    const run = await fixture();
    try {
      const { outerPid, workerPid } = await run.start();
      process.kill(outerPid, "SIGKILL");
      await waitFor(() => run.manager.getInfo().state === "failed");
      await waitFor(() => !alive(workerPid));
    } finally { await run.cleanup(); }
  }, 40_000);

  it.skipIf(process.platform === "win32" || !existsSync(packagedEngine))(
    "reaps the real frozen inner engine after its outer bootloader is killed", async () => {
      const home = await mkdtemp(join(tmpdir(), "redjohn-frozen-group-"));
      const manager = new EngineManager(makeDeps({ isPackaged: true, resourcesPath: resources, env: {
        PATH: "/usr/bin:/bin", HOME: home, REDJOHN_HOME: home, REDJOHN_PROFILE: "isolated",
        RJ_MODEL_PROVIDER: "fixture", RJ_MEMORY_AUTO_START: "0",
      } }));
      let outerPid = 0;
      let innerPid = 0;
      try {
        const info = await manager.start();
        expect(info.state).toBe("running");
        outerPid = info.pid!;
        innerPid = JSON.parse(await readFile(join(home, "isolated", "profile.lock"), "utf8")).pid;
        expect(innerPid).not.toBe(outerPid);
        process.kill(outerPid, "SIGKILL");
        await waitFor(() => manager.getInfo().state === "failed");
        await waitFor(() => !alive(innerPid));
      } finally {
        await manager.stop();
        // This group came from the isolated owned spawn. A remaining inner
        // member keeps its group ID reserved until cleanup has completed.
        if (outerPid && innerPid && alive(innerPid)) {
          try { process.kill(-outerPid, "SIGKILL"); } catch { /* Already gone. */ }
        }
        await rm(home, { recursive: true, force: true });
      }
    }, 40_000,
  );
});
