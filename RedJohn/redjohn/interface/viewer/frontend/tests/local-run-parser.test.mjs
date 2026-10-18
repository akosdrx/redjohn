import assert from "node:assert/strict";
import test from "node:test";
import { parseAgentsJson, parseRunJson, parseVulnerabilitiesJson, RunParseError, severityCounts } from "../src/lib/local-run-parser.ts";
import { parseTarget } from "../src/lib/target-utils.ts";

test("run import preserves RedJohn targets, report and duration", () => {
  const summary = parseRunJson(JSON.stringify({
    run_id: "owned-run", run_name: "RedJohn local lab", targets_info: [{ original: "https://owned.test" }],
    start_time: "2026-01-01T00:00:00Z", end_time: "2026-01-01T00:01:03Z", status: "completed",
    scan_results: { executive_summary: "Validated on the owned fixture", recommendations: "Retest after repair" },
  }));
  assert.deepEqual(summary.targets, ["https://owned.test"]);
  assert.equal(summary.durationSeconds, 63);
  assert.equal(summary.executiveSummary, "Validated on the owned fixture");
  assert.equal(summary.recommendations, "Retest after repair");
});

test("invalid imported records produce actionable parse errors", () => {
  for (const input of ["{", "null", "[]", "42"]) assert.throws(() => parseRunJson(input), RunParseError);
  for (const input of ["{}", "[null]", "[42]", "[[]]"]) assert.throws(() => parseVulnerabilitiesJson(input), RunParseError);
});

test("finding import normalizes severities and preserves evidence", () => {
  const findings = parseVulnerabilitiesJson(JSON.stringify([
    { id: "v1", title: "Owned evidence", severity: " HIGH ", timestamp: "2026-01-01 00:00:00 UTC", evidence: "fixture response", cwe: "CWE-79", cvss: 7.2 },
    { severity: "info", cwe: ["CWE-89", null, 12], timestamp: "2026-01-01T00:00:01Z" },
  ]), "owned-run");
  assert.equal(findings[0].created_at, "2026-01-01T00:00:00.000Z");
  assert.equal(findings[0].scan_id, "owned-run");
  assert.equal(findings[0].evidence, "fixture response");
  assert.deepEqual(findings[0].cwe, ["CWE-79"]);
  assert.deepEqual(findings[1].cwe, ["CWE-89"]);
  assert.deepEqual(severityCounts(findings), { critical: 0, high: 1, medium: 0, low: 1 });
});

test("agent tree import terminates on cycles and retains orphaned workers", () => {
  const agents = parseAgentsJson(JSON.stringify({
    statuses: { parent: "completed", child: "running", orphan: "failed", a: "waiting", b: "waiting" },
    parent_of: { child: "parent", orphan: "missing", a: "b", b: "a" },
    names: { child: "Replay worker" }, metadata: { child: { skills: ["http", 12], task: "Retest" } },
  }));
  assert.equal(agents.length, 5);
  assert.equal(new Set(agents.map((agent) => agent.id)).size, 5);
  const child = agents.find((agent) => agent.id === "child");
  assert.equal(child.depth, 1);
  assert.deepEqual(child.skills, ["http"]);
  assert.equal(agents.find((agent) => agent.id === "orphan").depth, 0);
});

test("target links never interpret an embedded provider URL as the real host", () => {
  assert.equal(parseTarget("https://evil.test/github.com/akosdrx/redjohn").href, "https://evil.test/github.com/akosdrx/redjohn");
  assert.equal(parseTarget("https://github.com.evil.test/akosdrx/redjohn").provider, null);
  assert.equal(parseTarget("https://github.com/akosdrx/redjohn.git").href, "https://github.com/akosdrx/redjohn");
  assert.equal(parseTarget("javascript:alert(1)").href, null);
});
