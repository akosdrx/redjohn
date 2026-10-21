// HTTP response doubles exercise the frontend contract; not a real backend E2E.
import assert from "node:assert/strict";
import test from "node:test";
import { fetchAll, fetchCapabilities, otpVerify, parseMcpConnectionStatus, sendReport, steerAgent } from "../src/data/serverSource.ts";

test("read-only capability defaults closed on absent or malformed permissions", async (t) => {
  for (const value of [{}, { can_steer: "true" }, { can_steer: false }]) {
    t.mock.method(globalThis, "fetch", async () => Response.json(value));
    assert.deepEqual(await fetchCapabilities(), { can_steer: false });
    t.mock.restoreAll();
  }
});

test("steering preserves agent and message, HTTP rejection stays failure", async (t) => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (url, options) => {
    calls.push({ url, options });
    return Response.json({ error: "read_only_run" }, { status: 409 });
  });
  assert.deepEqual(await steerAgent("owned-worker", "Retest the fixed fixture"), { ok: false, error: "read_only_run" });
  assert.equal(calls[0].url, "/api/agents/steer");
  assert.equal(calls[0].options.method, "POST");
  assert.equal(calls[0].options.cache, "no-store");
  assert.deepEqual(JSON.parse(calls[0].options.body), { agent_id: "owned-worker", message: "Retest the fixed fixture" });
});

test("successful HTTP status cannot turn rejected OTP into verified auth", async (t) => {
  t.mock.method(globalThis, "fetch", async () => Response.json({ verified: false, error: "invalid_code" }));
  assert.deepEqual(await otpVerify("owner@example.test", "000000"), { verified: false, error: "invalid_code" });
});

test("dropped POST transport is an explicit failure and the next action can retry", async (t) => {
  let attempts = 0;
  t.mock.method(globalThis, "fetch", async () => {
    if (attempts++ === 0) throw new TypeError("owned connection reset");
    return Response.json({ ok: true });
  });
  assert.deepEqual(await steerAgent("owned-worker", "Retest"), { ok: false, error: "unavailable" });
  assert.deepEqual(await steerAgent("owned-worker", "Retest"), { ok: true });
  assert.equal(attempts, 2);
});

test("report sending encodes requested run and surfaces non-JSON failures", async (t) => {
  let request;
  t.mock.method(globalThis, "fetch", async (_url, options) => {
    request = JSON.parse(options.body);
    return new Response("upstream unavailable", { status: 503 });
  });
  assert.deepEqual(await sendReport("owned/run & retest"), { ok: false, error: "unavailable" });
  assert.deepEqual(request, { run: "owned/run & retest" });
});

test("run loading encodes scope and does not hide a failed primary run fetch", async (t) => {
  const urls = [];
  t.mock.method(globalThis, "fetch", async (url) => {
    urls.push(url);
    if (url.startsWith("/api/run?")) return Response.json({ run_id: "r", finished: true, targets_info: [] });
    return new Response("not available", { status: 503 });
  });
  const result = await fetchAll("owned/run & retest");
  assert.equal(result.finished, true);
  assert.deepEqual(result.vulnerabilities, []);
  assert.equal(result.reportMarkdown, null);
  assert.deepEqual(result.transcript, { agents: [], events: [] });
  assert.ok(urls.every((url) => url.endsWith("?run=owned%2Frun%20%26%20retest")));
  t.mock.restoreAll();
  t.mock.method(globalThis, "fetch", async () => new Response("forbidden", { status: 403 }));
  await assert.rejects(fetchAll(), /\/api\/run responded 403/);
});

test("MCP roster exposes validated non-secret fields only", () => {
  assert.deepEqual(parseMcpConnectionStatus({ mcp_connection_status: [
    null, [], { name: " " }, { name: "owned-tools", provider: "stdio", tool_count: 2, dead: false, token: "private", url: "secret" },
    { name: "invalid", tool_count: -2 }, { name: "notfinite", tool_count: NaN },
  ] }), [
    { name: "owned-tools", provider: "stdio", toolCount: 2, dead: false },
    { name: "invalid", provider: null, toolCount: 0, dead: false },
    { name: "notfinite", provider: null, toolCount: 0, dead: false },
  ]);
});
