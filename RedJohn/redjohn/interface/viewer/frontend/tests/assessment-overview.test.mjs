import assert from "node:assert/strict";
import test from "node:test";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AssessmentOverview } from "../src/components/AssessmentOverview.tsx";

test("assessment UI keeps capability gaps distinct from negative findings", () => {
  const html = renderToStaticMarkup(React.createElement(AssessmentOverview, { assessment: {
    read_only: true, engagement_id: "owned_fixture", candidate_count: 0,
    coverage: [{ family: "nuclei", execution_status: "blocked", coverage_status: "blocked", count: 1 }],
    capability_gaps: [{ id: "missing_scanner", status: "unavailable" }],
    rce_regression: "not_reproduced_missing_fixture",
  } }));
  assert.match(html, /Coverage: .*blocked/);
  assert.match(html, /Unavailable capabilities are coverage gaps, never negative vulnerability results/);
  assert.match(html, /Original RCE: not reproduced; fixture missing/);
  assert.match(html, /Read-only report snapshot/);
});

test("assessment UI bounds rows, escapes evidence, and omits unapproved snapshots", () => {
  assert.equal(renderToStaticMarkup(React.createElement(AssessmentOverview, { assessment: {} })), "");
  const html = renderToStaticMarkup(React.createElement(AssessmentOverview, { assessment: {
    read_only: true, engagement_id: "<script>owned</script>", coverage: Array.from({ length: 150 }, () => ({ family: "http", count: 1 })),
  } }));
  assert.equal((html.match(/role="listitem"/g) || []).length, 100);
  assert.doesNotMatch(html, /<script>/);
  assert.match(html, /&lt;script&gt;/);
});
