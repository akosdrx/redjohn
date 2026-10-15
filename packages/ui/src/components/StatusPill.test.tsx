// @vitest-environment jsdom
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityPill, StatusPill } from "./StatusPill";

describe("StatusPill", () => {
  it("renders a text label, not color alone", () => {
    render(<StatusPill kind="service" state="live" />);
    expect(screen.getByRole("status")).toHaveTextContent("Live");
  });

  it("maps agent statuses to labels", () => {
    render(<StatusPill kind="agent" state="queued" />);
    expect(screen.getByRole("status")).toHaveTextContent("Queued");
  });

  it("exposes an accessible name including the state", () => {
    render(<StatusPill kind="run" state="failed" />);
    expect(screen.getByRole("status")).toHaveAccessibleName(/run status: Failed/i);
  });

  it("supports a custom label", () => {
    render(<StatusPill kind="service" state="live" label="Streaming" />);
    expect(screen.getByRole("status")).toHaveTextContent("Streaming");
  });

  it("renders an unknown/forward state as a neutral pill instead of throwing", () => {
    // The engine is separately versioned; a new enum value must not crash the
    // renderer (there is no error boundary around every pill).
    expect(() =>
      render(<StatusPill kind="agent" state={"paused" as never} />),
    ).not.toThrow();
    expect(screen.getByRole("status")).toHaveTextContent("paused");
  });
});

describe("SeverityPill", () => {
  it("renders the severity as text", () => {
    render(<SeverityPill severity="high" />);
    expect(screen.getByLabelText("severity: High")).toHaveTextContent("High");
  });
});
