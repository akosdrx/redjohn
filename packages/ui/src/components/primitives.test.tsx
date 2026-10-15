// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest";
import { useState } from "react";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it } from "vitest";
import { Dialog, Select } from "./primitives";

afterEach(cleanup);
function Form() {
  const [value, setValue] = useState("standard");
  return <Dialog open onClose={() => {}} title="Assessment"><Select aria-label="Mode" value={value} onChange={(event) => setValue(event.target.value)}>
    <option value="low">Low</option><option value="standard">Standard</option><option value="disabled" disabled>Disabled</option><option value="deep">Deep</option>
  </Select><output>{value}</output></Dialog>;
}
it("uses an app popup inside a dialog and commits a keyboard choice", async () => {
  const user = userEvent.setup();
  render(<Form />);
  const field = screen.getByRole("combobox", { name: "Mode" });
  await user.click(field);
  expect(field).toHaveAttribute("aria-expanded", "true");
  expect(screen.getByRole("listbox")).toBeInTheDocument();
  await user.keyboard("{ArrowDown}{Enter}");
  expect(screen.getByText("deep")).toBeInTheDocument();
  expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
  expect(field).toHaveFocus();
});
it("dismisses the app popup without changing its selection", async () => {
  const user = userEvent.setup();
  render(<Form />);
  const field = screen.getByRole("combobox", { name: "Mode" });
  await user.click(field); await user.keyboard("{ArrowDown}{Escape}");
  expect(screen.getByText("standard")).toBeInTheDocument();
  expect(field).toHaveAttribute("aria-expanded", "false");
  fireEvent.click(field);
  fireEvent.pointerDown(document.body);
  expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
});

it("restores dialog focus to its launcher and closes a popup on outer scroll", async () => {
  const user = userEvent.setup();
  function Harness() {
    const [open, setOpen] = useState(false);
    return <><button onClick={() => setOpen(true)}>Open assessment</button><Dialog open={open} onClose={() => setOpen(false)} title="Assessment"><Select aria-label="Mode" value="low"><option value="low">Low</option></Select></Dialog></>;
  }
  render(<Harness />);
  const launcher = screen.getByRole("button", { name: "Open assessment" });
  await user.click(launcher);
  await user.click(screen.getByRole("combobox", { name: "Mode" }));
  fireEvent.scroll(document.body);
  expect(screen.queryByRole("listbox")).not.toBeInTheDocument();
  await user.click(screen.getByRole("button", { name: "Close dialog" }));
  expect(launcher).toHaveFocus();
});
