// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { MemoryReadyGate } from "./MemoryReadyGate";
const mock = vi.hoisted(() => ({ api: { getMemoryConfig: vi.fn(), getStatus: vi.fn(), autoStartMemory: vi.fn() } }));
vi.mock("../lib/engine", () => ({ useEngine: () => ({ api: mock.api }) }));
const clients: QueryClient[] = [];
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } }); clients.push(client);
  render(<QueryClientProvider client={client}><MemoryReadyGate><p>Pentest workspace</p></MemoryReadyGate></QueryClientProvider>);
}
afterEach(() => { cleanup(); clients.splice(0).forEach((client) => client.clear()); });
beforeEach(() => vi.resetAllMocks());
it("opens an unconfigured harness without starting or installing memory", async () => {
  mock.api.getMemoryConfig.mockResolvedValue({ configured: false }); mount();
  await screen.findByText("Pentest workspace");
  expect(mock.api.getStatus).not.toHaveBeenCalled(); expect(mock.api.autoStartMemory).not.toHaveBeenCalled();
});
it("waits for saved memory to become live before showing pentests", async () => {
  mock.api.getMemoryConfig.mockResolvedValue({ configured: true });
  mock.api.getStatus.mockResolvedValueOnce({ services: [{ service: "openviking", state: "starting", detail: "Loading saved memory" }] }).mockResolvedValue({ services: [{ service: "openviking", state: "live" }] });
  mount(); await screen.findByText("Loading saved memory");
  expect(screen.queryByText("Pentest workspace")).not.toBeInTheDocument();
  await screen.findByText("Pentest workspace");
});
it("lets a failed connection be repaired in Memory settings", async () => {
  mock.api.getMemoryConfig.mockResolvedValue({ configured: true });
  mock.api.getStatus.mockResolvedValue({ services: [{ service: "openviking", state: "down", detail: "Connection refused" }] });
  const navigate = vi.fn(); window.addEventListener("redjohn:navigate", navigate);
  mount(); fireEvent.click(await screen.findByRole("button", { name: "Open memory settings" }));
  await screen.findByText("Pentest workspace"); expect(navigate).toHaveBeenCalled();
  window.removeEventListener("redjohn:navigate", navigate);
});
