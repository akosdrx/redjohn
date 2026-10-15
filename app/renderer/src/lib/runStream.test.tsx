// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { PropsWithChildren } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { ApiClient, RunEvent, RunSnapshot } from "./api";
import { ApiError } from "./api";
import { qk, recentTerminalHistory, TERMINAL_HISTORY_EVENT_WINDOW, useRunStream } from "./runStream";

vi.mock("@xterm/xterm", () => ({ Terminal: class {} }));

class SocketFixture {
  static instances: SocketFixture[] = [];
  readyState = 1;
  onopen: (() => void) | null = null;
  onmessage: ((event: { data: unknown }) => void) | null = null;
  onclose: ((event: { code: number; reason: string }) => void) | null = null;
  onerror: (() => void) | null = null;

  constructor(readonly url: string, readonly protocols: string[]) {
    SocketFixture.instances.push(this);
  }
  send() {}
  close() {
    this.readyState = 3;
    this.onclose?.({ code: 1000, reason: "fixture close" });
  }
  push(event: RunEvent) {
    this.onmessage?.({ data: JSON.stringify(event) });
  }
}

function event(runId: string, seq: number, type = "terminal.output", data: object = { chunk: `${runId}-${seq}\n` }): RunEvent {
  return { schema_version: 1, event_id: `${runId}-${seq}`, run_id: runId, seq,
    occurred_at: "2026-10-13T12:00:00Z", type, data, agent_id: "agent" } as RunEvent;
}

function snapshot(runId: string, cursor: number): RunSnapshot {
  return { run: { run_id: runId, workspace_id: "workspace", project_id: "project",
    status: "completed", name: "Completed session", session_project: true,
    scope: { scope_id: "scope", project_id: "project", version: 1,
      max_agents: 24, max_concurrent_agents: 6, max_depth: 3 } }, agents: [], cursor };
}

function apiWith(replay: ApiClient["getRunEvents"]): ApiClient {
  return { baseUrl: "http://127.0.0.1:8720/api/v1", getRunEvents: replay } as ApiClient;
}

function provider() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity } } });
  const Wrapper = ({ children }: PropsWithChildren) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  return { client, Wrapper };
}

beforeEach(() => {
  SocketFixture.instances = [];
  vi.stubGlobal("WebSocket", SocketFixture);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe("session terminal history", () => {
  it("restores completed output before live frames and keeps the stream through snapshot refetch", async () => {
    let resolveHistory!: (page: { items: RunEvent[]; cursor: number }) => void;
    const replay = vi.fn(() => new Promise<{ items: RunEvent[]; cursor: number }>((resolve) => { resolveHistory = resolve; }));
    const api = apiWith(replay);
    const { client, Wrapper } = provider();
    client.setQueryData(qk.run("a"), snapshot("a", 3).run);
    const writes: string[] = [];
    const write = (chunk: string) => writes.push(chunk);
    const { rerender } = renderHook(({ snap }: { snap: RunSnapshot }) => useRunStream({
      api, runId: "a", snapshot: snap, token: "private-token", agents: [], onTerminalWrite: write,
    }), { wrapper: Wrapper, initialProps: { snap: snapshot("a", 3) } });
    const socket = SocketFixture.instances[0]!;
    expect(socket.url).toMatch(/\?after_seq=3$/);
    act(() => socket.push(event("a", 4)));
    await act(async () => { await Promise.resolve(); });
    expect(writes).toEqual([]);
    await act(async () => resolveHistory({ items: [
      event("a", 1), event("a", 2, "run.status", { status: "running" }),
      event("a", 3, "tool.invocation.output", { chunk: "saved-tool-output\n" }), event("a", 4),
    ], cursor: 4 }));
    await waitFor(() => expect(writes).toEqual(["a-1\n", "saved-tool-output\n", "a-4\n"]));
    expect(client.getQueryData<{ status: string }>(qk.run("a"))?.status).toBe("completed");
    rerender({ snap: snapshot("a", 4) });
    expect(SocketFixture.instances).toHaveLength(1);
    expect(replay).toHaveBeenCalledTimes(1);
    act(() => { socket.push(event("a", 4)); socket.push(event("a", 5)); });
    await waitFor(() => expect(writes.at(-1)).toBe("a-5\n"));
    expect(writes.filter((chunk) => chunk === "a-4\n")).toHaveLength(1);
    client.clear();
  });

  it("loads saved output again when reselecting a session and never writes its cancelled history into another", async () => {
    let resolveOld!: (page: { items: RunEvent[]; cursor: number }) => void;
    const replay = vi.fn(async (id: string) => ({ items: [event(id, 1), event(id, 2)], cursor: 2 }));
    replay.mockImplementationOnce(() => new Promise((resolve) => { resolveOld = resolve; }));
    const api = apiWith(replay);
    const { client, Wrapper } = provider();
    const first: string[] = [], second: string[] = [], reselected: string[] = [];
    const { rerender } = renderHook(({ id, write }: { id: string; write: (chunk: string) => void }) => useRunStream({
      api, runId: id, snapshot: snapshot(id, 2), token: "fixture", agents: [], onTerminalWrite: write,
    }), { wrapper: Wrapper, initialProps: { id: "a", write: (chunk) => first.push(chunk) } });
    rerender({ id: "b", write: (chunk) => second.push(chunk) });
    await waitFor(() => expect(second).toEqual(["b-1\n", "b-2\n"]));
    expect(SocketFixture.instances[0]!.readyState).toBe(3);
    await act(async () => resolveOld({ items: [event("a", 1), event("a", 2)], cursor: 2 }));
    expect(first).toEqual([]);
    expect(second).toEqual(["b-1\n", "b-2\n"]);
    rerender({ id: "a", write: (chunk) => reselected.push(chunk) });
    await waitFor(() => expect(reselected).toEqual(["a-1\n", "a-2\n"]));
    expect(replay.mock.calls.map(([id]) => id)).toEqual(["a", "b", "a"]);
    client.clear();
  });

  it("continues live delivery and shows a safe message if historical output cannot be loaded", async () => {
    const api = apiWith(vi.fn().mockRejectedValue(new Error("network failure private-token")));
    const { client, Wrapper } = provider();
    const writes: string[] = [];
    renderHook(() => useRunStream({ api, runId: "a", snapshot: snapshot("a", 2), token: "fixture",
      agents: [], onTerminalWrite: (chunk) => writes.push(chunk) }), { wrapper: Wrapper });
    await waitFor(() => expect(writes.join("")).toContain("Saved terminal output could not be loaded"));
    act(() => SocketFixture.instances[0]!.push(event("a", 3)));
    await waitFor(() => expect(writes.at(-1)).toBe("a-3\n"));
    expect(writes.join("")).not.toContain("private-token");
    client.clear();
  });

  it("fetches only the recent window, follows actual page events and bounds retained output", async () => {
    const through = 100_000;
    const replay = vi.fn(async (id: string, after = 0, limit = 200) => ({
      items: Array.from({ length: Math.min(limit, through - after) }, (_, i) =>
        event(id, after + i + 1, "terminal.output", { chunk: `${after + i + 1}-${"x".repeat(2000)}\n` })),
      cursor: 200_000, // Advancing to this would skip all remaining history.
    }));
    const result = await recentTerminalHistory(apiWith(replay), "a", through, () => [], () => false);
    expect(replay).toHaveBeenCalledTimes(10);
    expect(replay.mock.calls[0]).toEqual(["a", through - TERMINAL_HISTORY_EVENT_WINDOW, 200]);
    expect(result.items.map((item) => item.chunk).join("").length).toBeLessThanOrEqual(2 * 1024 * 1024);
    expect(result.items.at(-1)!.chunk).toMatch(/^100000-/);
    expect(result.truncated).toBe(true);
  });

  it("replays retained output after an expired cursor without walking old history", async () => {
    const replay = vi.fn(async () => ({ items: [event("a", 9), event("a", 10)], cursor: 10 }));
    replay.mockRejectedValueOnce(new ApiError(410, "gone", "expired", { min_available_seq: 9 }));
    const result = await recentTerminalHistory(apiWith(replay), "a", 10, () => [], () => false);
    expect(replay.mock.calls).toEqual([["a", 0, 200], ["a", 8, 200]]);
    expect(result.items.map((item) => item.chunk)).toEqual(["a-9\n", "a-10\n"]);
    expect(result.truncated).toBe(true);
  });

  it("clears agent current_activity when an empty string is sent and preserves findings total on hydrateCaches", async () => {
    const { applyEventToCaches, hydrateCaches } = await import("./runStream");
    const { client } = provider();
    client.setQueryData(qk.agents("a"), {
      items: [{ agent_id: "agent", run_id: "a", name: "recon", role: "recon", status: "running", current_activity: "scanning" }],
    });
    applyEventToCaches(client, "a", event("a", 11, "agent.activity", { current_activity: "" }));
    expect(client.getQueryData<{ items: Array<{ current_activity?: string }> }>(qk.agents("a"))?.items[0]?.current_activity).toBe("");

    client.setQueryData(qk.findings("a"), { items: [], next_cursor: "c1", total: 120 });
    hydrateCaches(client, "a", {
      ...snapshot("a", 12),
      findings: [{ finding_id: "f1", run_id: "a", code: "C1", title: "T1", severity: "high", status: "verified" }],
    });
    expect(client.getQueryData<{ total?: number | null }>(qk.findings("a"))?.total).toBe(120);
    client.clear();
  });
});
