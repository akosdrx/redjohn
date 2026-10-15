// @vitest-environment jsdom
import { createRef } from "react";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, expect, it, vi } from "vitest";
import { LiveTerminal, type LiveTerminalHandle } from "./LiveTerminal";

const terminal = vi.hoisted(() => ({ write: vi.fn(), reset: vi.fn(), scrollToBottom: vi.fn() }));
vi.mock("@xterm/xterm", () => ({ Terminal: class {
  write = terminal.write;
  reset = terminal.reset;
  scrollToBottom = terminal.scrollToBottom;
  loadAddon() {}
  open() {}
  dispose() {}
} }));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit() {} } }));
vi.mock("@xterm/addon-search", () => ({ SearchAddon: class { findNext() { return true; } } }));

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} });
});

it("resumes the bounded chronological buffer after a long paused mixed-agent stream", () => {
  const ref = createRef<LiveTerminalHandle>();
  render(<LiveTerminal ref={ref} agents={[]} selectedAgentId={null} onSelectAgent={() => {}} follow={false} onFollowChange={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: "Pause" }));
  act(() => {
    for (let i = 0; i < 10_000; i++) ref.current!.write(`line-${String(i).padStart(5, "0")}\n`, i % 2 ? "odd" : "even");
  });
  expect(terminal.write).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Resume" }));
  const resumed = terminal.write.mock.calls.map(([text]) => text as string).join("");
  const rows = resumed.split(/\r?\n/).filter(Boolean);
  expect(rows.length).toBeLessThanOrEqual(5000);
  expect(rows.at(-1)).toBe("line-09999");
  expect(rows.every((line, i) => i === 0 || line > rows[i - 1]!)).toBe(true);
});

it("preserves SGR colors and does not append a spurious newline to a partial line on repaint", () => {
  const ref = createRef<LiveTerminalHandle>();
  render(<LiveTerminal ref={ref} agents={[]} selectedAgentId={null} onSelectAgent={() => {}} follow={false} onFollowChange={() => {}} />);
  fireEvent.click(screen.getByRole("button", { name: "Pause" }));
  act(() => {
    ref.current!.write("\x1b[31mcolored\x1b[0m\nprompt> ", "a1");
  });
  fireEvent.click(screen.getByRole("button", { name: "Resume" }));
  const resumed = terminal.write.mock.calls.map(([text]) => text as string).join("");
  expect(resumed).toBe("\x1b[31mcolored\x1b[0m\r\nprompt> ");
});
