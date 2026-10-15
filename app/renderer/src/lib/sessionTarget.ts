import { TARGET_KINDS } from "@redjohn/ui";
import type { Run } from "./api";

/** Older runs retain the pinned scope even before target snapshots were introduced. */
export function sessionTarget(run: Run): { label: string; value: string } {
  const value = run.authorized_target || run.scope?.allowed_targets?.[0] || "No target recorded";
  // An unknown/forward target_kind from a newer engine must not crash the row
  // via a missing TARGET_KINDS entry; fall through to the heuristic instead.
  const known = run.target_kind ? TARGET_KINDS[run.target_kind] : undefined;
  if (known) return { label: known.short, value };
  let label = "Target";
  if (value.startsWith("/")) label = "Local";
  else if (/^https:\/\/github\.com\/[^/]+\/[^/]+/.test(value)) label = "Repo";
  else if (/^https?:\/\//.test(value) || /^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/i.test(value)) label = "Web";
  return { label, value };
}
