// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, expect, it, vi } from "vitest";
import { SettingsPage } from "./SettingsPage";
const mock = vi.hoisted(() => ({ listSkills: vi.fn(), getSettings: vi.fn().mockResolvedValue({}) }));
vi.mock("../lib/engine", () => ({ useEngine: () => ({ api: mock, info: { state: "running" } }) }));
afterEach(cleanup);
it("searches and pages skills from the actual settings page", async () => {
  mock.listSkills.mockImplementation(async ({ query, cursor }) => ({ items: [{ skill_id: "s", name: query ? "Needle skill" : cursor ? "Second page" : "First page" }], next_cursor: cursor ? null : "cursor-2", total: 10000 }));
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><SettingsPage initialSection="skills" /></QueryClientProvider>);
  const input = await screen.findByRole("searchbox", { name: "Search skills" });
  await screen.findByText("First page");
  fireEvent.click(screen.getByRole("button", { name: "Next skills page" }));
  await screen.findByText("Second page");
  fireEvent.change(input, { target: { value: "Needle" } });
  fireEvent.submit(input.closest("form")!);
  await screen.findByText("Needle skill");
  await waitFor(() => expect(mock.listSkills).toHaveBeenLastCalledWith({ limit: 50, query: "Needle" }));
  expect(screen.getByRole("button", { name: "Previous skills page" }).hasAttribute("disabled")).toBe(true);
  client.clear();
});
