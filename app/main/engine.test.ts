/**
 * Engine lifecycle state machine tests — EngineManager with injected deps,
 * no Electron involved.
 */
import { describe, expect, it, vi } from "vitest";
import {
  DEFAULT_DEV_ENGINE_CMD,
  EngineManager,
  loopbackBase,
  resolveEngineCommand,
  type EngineChild,
  type EngineManagerDeps,
} from "../../app/main/engine";

function fakeChild(): EngineChild & { exit: (code: number) => void } {
  let cb: ((code: number | null, signal: string | null) => void) | null = null;
  return {
    pid: 4321,
    onExit: (c) => {
      cb = c;
    },
    kill: vi.fn(() => true),
    exit: (code) => cb?.(code, null),
  };
}

function makeDeps(overrides: Partial<EngineManagerDeps> = {}): EngineManagerDeps {
  return {
    spawn: vi.fn((_argv: string[], _opts: { env: Record<string, string> }) => fakeChild()),
    readProfileLock: vi.fn(() => null),
    isProcessAlive: vi.fn(() => false),
    probe: vi.fn(async () => false),
    freePort: vi.fn(async () => 18720),
    isPackaged: false,
    resourcesPath: "/res",
    env: {},
    ...overrides,
  };
}

describe("resolveEngineCommand", () => {
  it("prefers REDJOHN_ENGINE_CMD", () => {
    const cmd = resolveEngineCommand({ isPackaged: false, resourcesPath: "", env: { REDJOHN_ENGINE_CMD: "uv run redjohn serve" } });
    expect(cmd).toEqual(["uv", "run", "redjohn", "serve"]);
  });
  it("supports quoted executable paths with spaces in REDJOHN_ENGINE_CMD", () => {
    const doubleQuoted = resolveEngineCommand({
      isPackaged: false,
      resourcesPath: "",
      env: { REDJOHN_ENGINE_CMD: '"/Users/Alice Smith/venv/bin/python" -m redjohn_core.serve' },
    });
    expect(doubleQuoted).toEqual(["/Users/Alice Smith/venv/bin/python", "-m", "redjohn_core.serve"]);

    const singleQuoted = resolveEngineCommand({
      isPackaged: false,
      resourcesPath: "",
      env: { REDJOHN_ENGINE_CMD: "'/Users/Alice Smith/venv/bin/python' -m redjohn_core.serve" },
    });
    expect(singleQuoted).toEqual(["/Users/Alice Smith/venv/bin/python", "-m", "redjohn_core.serve"]);

    const winPath = resolveEngineCommand({
      isPackaged: false,
      resourcesPath: "",
      env: { REDJOHN_ENGINE_CMD: '"C:\\Program Files\\Python\\python.exe" -m redjohn_core.serve' },
    });
    expect(winPath).toEqual(["C:\\Program Files\\Python\\python.exe", "-m", "redjohn_core.serve"]);
  });
  it("uses the documented python default in dev", () => {
    expect(resolveEngineCommand({ isPackaged: false, resourcesPath: "", env: {} })).toEqual(DEFAULT_DEV_ENGINE_CMD);
  });
  it("uses the packaged binary under resources/engine in prod", () => {
    const cmd = resolveEngineCommand({ isPackaged: true, resourcesPath: "/res", env: {} });
    expect(cmd[0]).toMatch(/\/res\/engine\/redjohn-engine/);
  });
});

describe("EngineManager", () => {
  it("attaches to a live engine from profile.lock (per-profile lock)", async () => {
    const bootstrapMemory = vi.fn(async () => {});
    const deps = makeDeps({
      readProfileLock: () => ({ port: 9999, token: "t", pid: 111 }),
      probe: vi.fn(async () => true),
      bootstrapMemory,
    });
    const m = new EngineManager(deps);
    const info = await m.start();
    expect(info.state).toBe("running");
    expect(info.attached).toBe(true);
    expect(info.baseUrl).toBe(loopbackBase(9999));
    expect(deps.spawn).not.toHaveBeenCalled();
    expect(m.getToken()).toBe("t");
    expect(bootstrapMemory).toHaveBeenCalledWith(loopbackBase(9999), "t");
  });

  it("keeps an attached engine available while surfacing a memory startup request failure", async () => {
    const deps = makeDeps({
      readProfileLock: () => ({ port: 9999, token: "private-token", pid: 111 }),
      probe: vi.fn(async () => true),
      bootstrapMemory: vi.fn(async () => { throw new Error("unavailable private-token"); }),
    });
    const info = await new EngineManager(deps).start();
    expect(info.state).toBe("running");
    expect(info.detail).toContain("Settings → Memory");
    expect(info.detail).not.toContain("private-token");
    expect(deps.spawn).not.toHaveBeenCalled();
  });

  it("respects an explicit automatic memory opt-out while attaching", async () => {
    const bootstrapMemory = vi.fn(async () => {});
    const deps = makeDeps({
      readProfileLock: () => ({ port: 9999, token: "t", pid: 111 }),
      probe: vi.fn(async () => true),
      bootstrapMemory,
      env: { RJ_MEMORY_AUTO_START: "0" },
    });
    expect((await new EngineManager(deps).start()).state).toBe("running");
    expect(bootstrapMemory).not.toHaveBeenCalled();
  });

  it("preserves an engine exit while waiting for its memory bootstrap request", async () => {
    const child = fakeChild();
    const deps = makeDeps({
      spawn: () => child,
      readProfileLock: vi.fn().mockReturnValueOnce(null).mockReturnValue({ port: 18720, token: "t" }),
      probe: vi.fn(async () => true),
      bootstrapMemory: vi.fn(async () => { child.exit(1); }),
    });
    const manager = new EngineManager(deps);
    expect((await manager.start()).state).toBe("failed");
    expect(manager.getToken()).toBeNull();
  });

  it("removes a stale lock and spawns with loopback args", async () => {
    const child = fakeChild();
    const spawn = vi.fn((_argv: string[], _opts: { env: Record<string, string> }) => child);
    const deps = makeDeps({
      spawn,
      readProfileLock: vi
        .fn()
        .mockReturnValueOnce({ port: 1, token: "stale" }) // stale lock
        .mockReturnValueOnce(null) // probe-fail cleanup read? not used
        .mockReturnValue({ port: 18720, token: "fresh", pid: 4321 }),
      probe: vi.fn(async (url: string) => url.includes("18720")),
    });
    const m = new EngineManager(deps);
    const info = await m.start();
    expect(deps.isProcessAlive).not.toHaveBeenCalled();
    expect(spawn).toHaveBeenCalledOnce();
    const argv = spawn.mock.calls[0]![0];
    expect(argv.slice(0, 3)).toEqual(DEFAULT_DEV_ENGINE_CMD);
    expect(argv).toContain("--host");
    expect(argv).toContain("127.0.0.1");
    expect(JSON.stringify(argv)).not.toContain("fresh");
    expect(info.state).toBe("running");
    expect(info.attached).toBe(false);
  });

  it("ignores a stale profile.lock until the newly spawned child writes its own lock", async () => {
    const child = fakeChild();
    const spawn = vi.fn((_argv: string[], _opts: { env: Record<string, string> }) => child);
    const probe = vi.fn(async (url: string) => url.includes("18720"));
    const deps = makeDeps({
      spawn,
      readProfileLock: vi
        .fn()
        .mockReturnValueOnce({ port: 1, token: "stale", pid: 999 }) // step 1: stale lock
        .mockReturnValueOnce({ port: 1, token: "stale", pid: 999 }) // step 3 first poll: still stale lock on disk!
        .mockReturnValue({ port: 18720, token: "fresh", pid: 4321 }),
      probe,
      sleep: async () => {},
    });
    const m = new EngineManager(deps);
    const info = await m.start();
    expect(deps.isProcessAlive).toHaveBeenCalledWith(999);
    expect(spawn).toHaveBeenCalledOnce();
    expect(probe.mock.calls.filter(([u]) => u.includes(":1/"))).toHaveLength(1);
    expect(info.state).toBe("running");
    expect(info.attached).toBe(false);
    expect(m.getToken()).toBe("fresh");
  });

  it("awaits an in-progress stop() before starting a new child and ignores late exit from old child", async () => {
    const child1 = fakeChild();
    child1.pid = 1001;
    const child2 = fakeChild();
    child2.pid = 1002;
    let spawnCount = 0;
    let child1Alive = true;
    let releaseStopSleep: () => void = () => {};
    const deps = makeDeps({
      spawn: vi.fn(() => (++spawnCount === 1 ? child1 : child2)),
      readProfileLock: vi.fn(() =>
        spawnCount === 0
          ? null
          : spawnCount === 1
            ? { port: 18720, token: "tok1", pid: 1001 }
            : { port: 18721, token: "tok2", pid: 1002 },
      ),
      freePort: vi.fn(async () => (spawnCount === 0 ? 18720 : 18721)),
      probe: vi.fn(async (url: string) => (url.includes("18720") ? child1Alive : url.includes("18721"))),
      sleep: vi.fn(
        () =>
          new Promise<void>((resolve) => {
            releaseStopSleep = resolve;
          }),
      ),
    });
    const m = new EngineManager(deps);
    await m.start();
    expect(m.getInfo().pid).toBe(1001);

    // Begin stop() — child1 does not exit immediately so stop() awaits sleep(100).
    const stopP = m.stop();
    const startP = m.start();
    // Simulate child1 exiting while stop() is waiting.
    child1Alive = false;
    child1.exit(0);
    releaseStopSleep();
    await stopP;
    const info2 = await startP;
    expect(info2.state).toBe("running");
    expect(info2.pid).toBe(1002);
    expect(m.getToken()).toBe("tok2");

    // A late exit callback from child1 must not clobber child2's running state.
    child1.exit(1);
    expect(m.getInfo().state).toBe("running");
    expect(m.getInfo().pid).toBe(1002);
    expect(m.getToken()).toBe("tok2");
  });

  it("fails cleanly when the engine never becomes ready", async () => {
    const deps = makeDeps({
      probe: vi.fn(async () => false),
      sleep: async () => {},
      now: (() => {
        let t = 0;
        return () => (t += 5000);
      })(),
    });
    const m = new EngineManager(deps);
    const info = await m.start();
    expect(info.state).toBe("failed");
    expect(info.detail).toMatch(/ready/i);
  });

  it("marks failed when the child exits unexpectedly", async () => {
    const child = fakeChild();
    const deps = makeDeps({
      spawn: () => child,
      readProfileLock: vi.fn()
        .mockReturnValueOnce(null) // no pre-existing lock
        .mockReturnValue({ port: 18720, token: "t" }),
      probe: vi.fn(async () => true),
      sleep: async () => {},
    });
    const m = new EngineManager(deps);
    await m.start();
    expect(m.getInfo().state).toBe("running");
    child.exit(1);
    expect(m.getInfo().state).toBe("failed");
  });

  it("stop() sends SIGTERM then SIGKILL on timeout; no orphans", async () => {
    const child = fakeChild();
    const kill = vi.fn(() => true);
    child.kill = kill;
    const deps = makeDeps({
      spawn: () => child,
      readProfileLock: vi.fn()
        .mockReturnValueOnce(null)
        .mockReturnValue({ port: 18720, token: "t" }),
      probe: vi.fn(async () => true),
      sleep: async () => {},
      now: (() => {
        let t = 0;
        return () => (t += 5000); // jump past STOP_TIMEOUT immediately
      })(),
    });
    const m = new EngineManager(deps);
    await m.start();
    await m.stop();
    expect(kill).toHaveBeenCalledWith("SIGTERM");
    expect(kill).toHaveBeenCalledWith("SIGKILL");
    expect(m.getInfo().state).toBe("stopped");
    expect(m.getToken()).toBeNull();
  });

  it("never replaces the lock of a live but unavailable engine", async () => {
    const deps = makeDeps({
      readProfileLock: () => ({ port: 9999, token: "t", pid: 111 }),
      isProcessAlive: () => true,
      sleep: async () => {},
      now: (() => { let time = 0; return () => (time += 10_000); })(),
    });
    const manager = new EngineManager(deps);
    expect((await manager.start()).state).toBe("failed");
    expect(deps.spawn).not.toHaveBeenCalled();
  });

  it("does not kill an attached engine on stop()", async () => {
    const deps = makeDeps({
      readProfileLock: () => ({ port: 9999, token: "t" }),
      probe: vi.fn(async () => true),
    });
    const m = new EngineManager(deps);
    await m.start();
    await m.stop();
    expect(m.getInfo().state).toBe("stopped");
  });
});
