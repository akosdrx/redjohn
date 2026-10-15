// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { FindingsTable } from "./FindingsTable";
import { MessageComposer } from "./MessageComposer";
import type { AgentRow, FindingRow } from "../types";

const findings: FindingRow[] = [
  {
    findingId: "f1",
    severity: "high",
    status: "verified",
    title: "Outdated component",
    description: "Potentially vulnerable version",
    target: "app.acme.test",
    agentName: "Web",
  },
  {
    findingId: "f2",
    severity: "low",
    status: "observation",
    title: "Verbose error response",
    target: "staging.acme.test",
  },
];

describe("FindingsTable", () => {
  it("renders severity, title, target and agent", () => {
    render(<FindingsTable findings={findings} />);
    expect(screen.getByText("Outdated component")).toBeInTheDocument();
    expect(screen.getByLabelText("severity: High")).toBeInTheDocument();
    expect(screen.getByText("app.acme.test")).toBeInTheDocument();
    expect(screen.getByText("Web")).toBeInTheDocument();
  });

  it("shows the lifecycle status label when enabled", () => {
    render(<FindingsTable findings={findings} showStatus />);
    expect(screen.getByText("Verified")).toBeInTheDocument();
    expect(screen.getByText("Observation")).toBeInTheDocument();
  });

  it("renders an empty state without findings", () => {
    render(<FindingsTable findings={[]} />);
    expect(screen.getByText(/no findings/i)).toBeInTheDocument();
  });
});

const agents: AgentRow[] = [
  { agentId: "a1", name: "Web", activity: "Analyzing", status: "running" },
  { agentId: "a2", name: "API", activity: "Testing", status: "running" },
];

describe("MessageComposer", () => {
  it("sends to the selected recipient", async () => {
    const onSend = vi.fn().mockResolvedValue(undefined);
    render(
      <MessageComposer agents={agents} recipientId="a1" onRecipientChange={() => {}} onSend={onSend} />,
    );
    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/message this agent/i), "check /login");
    await user.click(screen.getByRole("button", { name: /send/i }));
    expect(onSend).toHaveBeenCalledWith("a1", "check /login");
  });

  it("does not send empty messages", async () => {
    const onSend = vi.fn().mockResolvedValue(undefined);
    render(
      <MessageComposer agents={agents} recipientId="a1" onRecipientChange={() => {}} onSend={onSend} />,
    );
    const user = userEvent.setup();
    await user.click(screen.getByRole("button", { name: /send/i }));
    expect(onSend).not.toHaveBeenCalled();
  });

  it("surfaces send failures", async () => {
    const onSend = vi.fn().mockRejectedValue(new Error("boom"));
    render(
      <MessageComposer agents={agents} recipientId="a1" onRecipientChange={() => {}} onSend={onSend} />,
    );
    const user = userEvent.setup();
    await user.type(screen.getByPlaceholderText(/message this agent/i), "hi");
    await user.click(screen.getByRole("button", { name: /send/i }));
    expect(await screen.findByRole("alert")).toHaveTextContent(/failed to send/i);
  });
});
