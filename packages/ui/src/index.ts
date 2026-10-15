"use client";

/* @redjohn/ui — shared RedJohn UI. No Electron/Node imports allowed here. */

export { tokens, colors, spacing, typography, radius } from "./tokens.js";
export type { Tokens } from "./tokens.js";
export { strings } from "./strings.js";
export type { Strings } from "./strings.js";
export * from "./types.js";
export { cn } from "./utils.js";
export {
  sanitizeTerminalChunk,
  stripAnsi,
  splitTrailingEscape,
  TerminalLineBuffer,
  formatLogLine,
  DEFAULT_MAX_LINES,
} from "./terminal-core.js";

export { Panel, Button, Input, Textarea, Select, Field, Chip, Dialog, Spinner } from "./components/primitives.js";
export type { PanelProps, ButtonProps, DialogProps } from "./components/primitives.js";
export { StatusPill, SeverityPill } from "./components/StatusPill.js";
export type { StatusPillProps } from "./components/StatusPill.js";
export { AgentActivityTable } from "./components/AgentActivityTable.js";
export type { AgentActivityTableProps } from "./components/AgentActivityTable.js";
export { FindingsTable, FindingStatusLabel } from "./components/FindingsTable.js";
export type { FindingsTableProps } from "./components/FindingsTable.js";
export { LiveTerminal } from "./components/LiveTerminal.js";
export type { LiveTerminalHandle, LiveTerminalProps } from "./components/LiveTerminal.js";
export { MessageComposer } from "./components/MessageComposer.js";
export type { MessageComposerProps } from "./components/MessageComposer.js";
export { NewPentestDialog, TARGET_KINDS } from "./components/NewPentestDialog.js";
export type { NewPentestDialogProps, NewPentestValues, PentestTargetKind, ScanMode } from "./components/NewPentestDialog.js";
export { EmptyState, LoadingState, ErrorState } from "./components/States.js";
export { Logo, LOGO_ASSET } from "./components/Logo.js";
