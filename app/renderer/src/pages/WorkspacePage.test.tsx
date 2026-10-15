// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WorkspacePage } from "./WorkspacePage";
import { useUiStore } from "../store/ui";
import { applyEventToCaches, qk } from "../lib/runStream";
import type { RunEvent } from "../lib/api";

const mock = vi.hoisted(() => ({ api: {} as Record<string, ReturnType<typeof vi.fn>> }));
vi.mock("@xterm/xterm", () => ({ Terminal: vi.fn() }));
vi.mock("../lib/engine", () => ({ useEngine: () => ({ api: mock.api, token: null }) }));
vi.mock("@redjohn/ui", async (importOriginal) => {
  const original = await importOriginal<typeof import("@redjohn/ui")>();
  return { ...original, LiveTerminal: ({ composer }: { composer: React.ReactNode }) => <div>{composer}</div> };
});
const agent = { agent_id: "a1", run_id: "r1", name: "Coordinator", role: "coordinator", status: "running", depth: 0, task: "review" };
const run = { run_id: "r1", project_id: "p1", name: "Audit", status: "running" };
afterEach(cleanup);
function event(type: string, data: object, agentId: string | null = null): RunEvent {
  return { schema_version: 1, event_id: crypto.randomUUID(), run_id: "r1", seq: 2, occurred_at: new Date().toISOString(), type, data, agent_id: agentId } as RunEvent;
}
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, staleTime: Infinity }, mutations: { retry: false } } });
  render(<QueryClientProvider client={client}><WorkspacePage /></QueryClientProvider>);
  return client;
}
beforeEach(() => {
  useUiStore.setState({ selectedRunId: "r1", selectedAgentByRun: { r1: "a1" } });
  mock.api = {
    listRuns: vi.fn().mockResolvedValue({ items: [run] }),
    getRun: vi.fn().mockResolvedValue(run),
    getRunSnapshot: vi.fn().mockResolvedValue({ run, agents: [agent], cursor: 1, services: [{ service: "openviking", state: "live" }] }),
    listAgents: vi.fn().mockResolvedValue({ items: [agent] }),
    listRunFindings: vi.fn().mockResolvedValue({ items: [] }),
    listRunTargets: vi.fn().mockResolvedValue({ items: [] }),
    listMcps: vi.fn().mockResolvedValue({ items: [] }),
    listSkills: vi.fn().mockResolvedValue({ items: [] }),
    getStatus: vi.fn().mockResolvedValue({ services: [{ service: "api", state: "live" }, { service: "openviking", state: "down" }] }),
    startRun: vi.fn().mockResolvedValue(run),
    stopRun: vi.fn().mockResolvedValue({ ...run, status: "stopped" }),
  };
});
describe("workspace engine integration", () => {
  it("opens Tools and Skills settings from the workspace header", async () => {
    const navigate = vi.fn();
    window.addEventListener("redjohn:navigate", navigate);
    const client = mount();
    fireEvent.click(await screen.findByRole("button", { name: "Tools →" }));
    expect(navigate).toHaveBeenCalled();
    fireEvent.click(await screen.findByRole("button", { name: "Skills →" }));
    expect(navigate).toHaveBeenCalledTimes(2);
    window.removeEventListener("redjohn:navigate", navigate);
    client.clear();
  });
  it("reflects live status in the badge and disables messaging after completion", async () => {
    const client = mount();
    const input = await screen.findByRole("textbox", { name: "Message this agent…" });
    expect(input).not.toBeDisabled();
    act(() => applyEventToCaches(client, "r1", event("run.status", { status: "completed" })));
    expect(await screen.findByText("Completed")).toBeInTheDocument();
    expect(input).toBeDisabled();
    client.clear();
  });
  it("uses current service health instead of the original snapshot", async () => {
    const client = mount();
    expect(await screen.findByText("OpenViking Down")).toBeInTheDocument();
    client.clear();
  });
  it("discovers a child announced after the initial agent response", async () => {
    const client = mount();
    fireEvent.click(await screen.findByRole("combobox", { name: "Recipient agent" }));
    await screen.findByRole("option", { name: "Coordinator" });
    mock.api.listAgents!.mockResolvedValue({ items: [agent, { ...agent, agent_id: "child", name: "Web child", role: "specialist", depth: 1 }] });
    act(() => applyEventToCaches(client, "r1", event("agent.status", { status: "running", name: "Web child" }, "child")));
    expect(await screen.findByRole("option", { name: "Web child" })).toBeInTheDocument();
    client.clear();
  });
  it("starts a created run and stops it through the real page controls", async () => {
    mock.api.getRun!.mockResolvedValue({ ...run, status: "created" });
    mock.api.getRunSnapshot!.mockResolvedValue({ run: { ...run, status: "created" }, agents: [agent], cursor: 1 });
    const client = mount();
    fireEvent.click(await screen.findByRole("button", { name: "Start run" }));
    await waitFor(() => expect(mock.api.startRun).toHaveBeenCalledWith("r1"));
    fireEvent.click(await screen.findByRole("button", { name: "Stop run" }));
    await waitFor(() => expect(mock.api.stopRun).toHaveBeenCalledWith("r1"));
    expect(await screen.findByText("Stopped")).toBeInTheDocument();
    client.clear();
  });
});
