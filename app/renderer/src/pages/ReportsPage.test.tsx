// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ReportsPage } from "./ReportsPage";
import { useUiStore } from "../store/ui";

const mock = vi.hoisted(() => ({ api: {} as Record<string, ReturnType<typeof vi.fn>> }));
vi.mock("../lib/engine", () => ({ useEngine: () => ({ api: mock.api }) }));
const report = { report_id: "report-existing", run_id: "r1", format: "html", created_at: "2026-10-13T12:00:00Z" };
afterEach(cleanup);
function mount() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const view = render(<QueryClientProvider client={client}><ReportsPage /></QueryClientProvider>);
  return { ...view, client };
}
beforeEach(() => {
  useUiStore.setState({ selectedRunId: "r1" });
  mock.api = { listReports: vi.fn().mockResolvedValue({ items: [] }), getCapabilities: vi.fn().mockResolvedValue({ reports: ["html", "json"] }) };
});
describe("report loading and persistence", () => {
  it("shows an actionable empty state when no reports exist", async () => {
    const view = mount();
    expect(await screen.findByText("No reports yet. Generate a report from a finished pentest.")).toBeInTheDocument();
    view.unmount(); view.client.clear();
  });
  it("loads reports created before opening this page", async () => {
    mock.api.listReports!.mockResolvedValue({ items: [report] });
    const view = mount();
    expect(await screen.findByText(report.report_id)).toBeInTheDocument();
    view.unmount(); view.client.clear();
  });
  it("shows the actual list failure instead of silently hiding it", async () => {
    mock.api.listReports!.mockRejectedValue(new Error("Report service unavailable"));
    const view = mount();
    expect(await screen.findByText(/Report service unavailable/)).toBeInTheDocument();
    view.unmount(); view.client.clear();
  });
});
