/** Native acceptance: hidden Electron window, real IPC/core, real renderer.
 * Usage: node scripts/verify-desktop.mjs /path/to/RedJohn [dev-app-directory]
 * No screenshots, existing user profiles, external targets, or paid APIs.
 */
import { spawn, execFileSync } from "node:child_process";
import { mkdtemp, writeFile, rm, access, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createServer } from "node:net";
import { createServer as createHttpServer } from "node:http";

const executable = process.argv[2];
if (!executable) throw new Error("Pass the Electron or packaged RedJohn executable");
const root = await mkdtemp(join(tmpdir(), "redjohn-native-smoke-"));
await mkdir(join(root, "core", "smoke"), { recursive: true });
await writeFile(join(root, "core", "smoke", "settings.json"), JSON.stringify({ model_provider: "fixture" }), { mode: 0o600 });
const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const port = await new Promise((resolve, reject) => {
  const server = createServer();
  server.on("error", reject);
  server.listen(0, "127.0.0.1", () => {
    const port = server.address().port;
    server.close(() => resolve(port));
  });
});
const fixtureServer = createHttpServer((_req, res) => {
  if (_req.url === "/v1/models") { res.writeHead(200, { "Content-Type": "application/json" }); res.end(JSON.stringify({ data: [{ id: "native-fixture", name: "Fixture model" }] })); return; }
  if (_req.url === "/v1/chat/completions") {
    if (_req.headers.authorization !== "Bearer native-fixture-key") { res.writeHead(401); res.end("fixture auth rejected"); return; }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ id: "native-model", object: "chat.completion", created: 1, model: "native-fixture", choices: [{ index: 0, message: { role: "assistant", content: "OK" }, finish_reason: "stop" }], usage: { prompt_tokens: 8, completion_tokens: 2, total_tokens: 10 } }));
    return;
  }
  // Deterministic local work keeps a child alive long enough for messaging.
  setTimeout(() => { res.writeHead(200, { "Content-Type": "text/plain" }); res.end("Local authorized fixture"); }, 1000);
});
await new Promise((resolve) => fixtureServer.listen(0, "127.0.0.1", resolve));
const fixtureTarget = `http://127.0.0.1:${fixtureServer.address().port}`;
const fixture = join(root, "fixture.json");
await writeFile(fixture, JSON.stringify({
  Coordinator: [
    { tool_calls: [{ name: "builtin:delegate", args: { name: "Fixture child", task: "Local echo only", allowed_tools: ["builtin:http_get", "builtin:complete_task"], allowed_targets: [fixtureTarget] } }] },
    { tool_calls: [{ name: "builtin:wait_children", args: {} }] },
    { tool_calls: [{ name: "builtin:complete_task", args: { summary: "Fixture coordinator completed" } }] },
  ],
  "Fixture child": [
    { tool_calls: [{ name: "builtin:http_get", args: { url: fixtureTarget } }] },
    { tool_calls: [{ name: "builtin:complete_task", args: { summary: "Fixture child completed" } }] },
  ],
}));
const env = {
  HOME: root,
  PATH: process.env.PATH ?? "",
  ...Object.fromEntries(["DISPLAY", "XAUTHORITY", "XDG_RUNTIME_DIR", "CHROME_DEVEL_SANDBOX"].filter(key => process.env[key]).map(key => [key, process.env[key]])),
  REDJOHN_HOME: join(root, "core"),
  REDJOHN_PROFILE: "smoke",
  RJ_FIXTURE_SCRIPT: fixture,
  RJ_MAX_AGENT_STEPS: "1000",
  // Runtime lifecycle is covered separately; this UI fixture must not pull models.
  RJ_MEMORY_AUTO_START: "0",
  // Optional source-engine override is for development smoke only.
  ...(process.argv[3] && process.env.REDJOHN_ENGINE_CMD ? { REDJOHN_ENGINE_CMD: process.env.REDJOHN_ENGINE_CMD } : {}),
};
let logs = "";
const launchServices = process.platform === "darwin" && process.env.RJ_UI_USE_LAUNCH_SERVICES === "1";
const appArgs = [
  ...(process.argv[3] ? [resolve(process.argv[3])] : []),
  "--redjohn-smoke-test",
  `--user-data-dir=${join(root, "ui")}`,
  `--remote-debugging-port=${port}`,
];
const child = spawn(launchServices ? "/usr/bin/open" : resolve(executable), launchServices ? [
  "-n", "-g", "-j", "-W", "-a", resolve(executable, "../../.."),
  ...Object.entries(env).flatMap(([key, value]) => ["--env", `${key}=${value}`]),
  "--args", ...appArgs,
] : appArgs, { env, cwd: root, stdio: ["ignore", "pipe", "pipe"] });
child.stdout.on("data", (data) => { logs = (logs + data).slice(-8000); });
child.stderr.on("data", (data) => { logs = (logs + data).slice(-8000); });
let ws;
const pending = new Map();
let nextId = 0;
const stages = [];
const streamDiagnostics = [];
async function cdp(method, params = {}) {
  const id = ++nextId;
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)); }, 20_000);
    pending.set(id, { resolve: (v) => { clearTimeout(timeout); resolve(v); }, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}
async function evaluate(expression) {
  const response = await cdp("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true });
  if (response.exceptionDetails) throw new Error(response.exceptionDetails.exception?.description ?? response.exceptionDetails.text);
  return response.result?.value;
}
async function until(expression, description, timeout = 30_000) {
  const deadline = Date.now() + timeout;
  while (Date.now() < deadline) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`App exited while waiting for ${description}: ${logs}`);
    if (await evaluate(expression)) return;
    await delay(75);
  }
  throw new Error(`Timed out waiting for ${description}. DOM: ${await evaluate("document.body.innerText")}\n${logs}`);
}
const button = (name) => `Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === ${JSON.stringify(name)})`;
async function click(name) {
  await until(`${button(name)} && !${button(name)}.disabled`, name);
  await evaluate(`${button(name)}.click()`);
}
async function createRun(name) {
  await evaluate("Array.from(document.querySelectorAll('button')).find(b => b.textContent.includes('New pentest')).click()");
  await until("!!document.querySelector('[role=dialog]') && !!document.querySelector('input[aria-label=Name]')", "new pentest dialog");
  await evaluate(`(() => {
    const fill = (el, value) => {
      const proto = el.tagName === 'TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, value);
      el.dispatchEvent(new Event('input', { bubbles: true }));
    };
    fill(document.querySelector('input[aria-label="Name"]'), ${JSON.stringify(name)});
    fill(document.querySelector('input[aria-label="Authorized target"]'), ${JSON.stringify(fixtureTarget)});
    fill(document.querySelector('textarea'), 'Run deterministic local fixture only');
  })()`);

  await click("Create pentest");
  await until(`document.querySelector('h1')?.textContent === ${JSON.stringify(name)}`, "created run");
  await click("Start run");
}
try {
  let target;
  let debugState = "listener not reached";
  for (let i = 0; i < Number(process.env.RJ_UI_LAUNCH_ATTEMPTS ?? 300); i++) {
    if (child.exitCode !== null || child.signalCode !== null) throw new Error(`App exited: ${logs}`);
    try {
      const list = await globalThis.fetch(`http://127.0.0.1:${port}/json/list`).then((r) => r.json());
      debugState = JSON.stringify(list.map(({ type, url }) => ({ type, url })));
      target = list.find((item) => item.type === "page" && item.url.startsWith("file:"));
      if (target) break;
    } catch (error) { debugState = String(error); }
    await delay(100);
  }
  if (!target) throw new Error(`No renderer target (${debugState}; pid=${child.pid}): ${logs}`);
  ws = new globalThis.WebSocket(target.webSocketDebuggerUrl);
  await new Promise((resolve, reject) => { ws.onopen = resolve; ws.onerror = reject; });
  ws.onmessage = ({ data }) => {
    const message = JSON.parse(data);
    if (message.method === 'Network.webSocketWillSendHandshakeRequest') streamDiagnostics.push({ origin: message.params.request.headers.Origin });
    if (message.method === 'Network.webSocketHandshakeResponseReceived') streamDiagnostics.push({ handshake: message.params.response.status });
    if (message.method === 'Network.webSocketFrameError') streamDiagnostics.push({ error: message.params.errorMessage });
    if (message.method === 'Runtime.exceptionThrown') streamDiagnostics.push({ exception: message.params.exceptionDetails.text });
    const waiting = pending.get(message.id);
    if (waiting) {
      pending.delete(message.id);
      if (message.error) waiting.reject(new Error(message.error.message));
      else waiting.resolve(message.result);
    }
  };
  await cdp('Network.enable');
  await cdp('Runtime.enable');
  await until("window.redjohn && window.redjohn.getEngineInfo().then(i => { if (i.state === 'failed') throw new Error(i.detail); return i.state === 'running'; })", "engine readiness", 60_000);
  // Calls originate in the sandboxed file:// renderer, exercising real CORS,
  // preload token transport and canonical API responses.
  await evaluate(`(async () => {
    const info = await window.redjohn.getEngineInfo();
    const token = await window.redjohn.getToken();
    const call = async (path, method, body) => {
      const res = await fetch(info.baseUrl + path, { method, headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, ...(body ? { body: JSON.stringify(body) } : {}) });
      if (!res.ok) throw new Error('Renderer API ' + path + ': ' + res.status + ' ' + await res.text());
      return res.json();
    };
    const status = await call('/status', 'GET');
    if (!status.services) throw new Error('Missing engine service status');
  })()`);
  stages.push("renderer_authenticated_api");
  await evaluate(`(async () => {
    const assertChrome = () => {
      const logo = document.querySelector('aside img')?.getBoundingClientRect();
      const bar = document.querySelector('.rj-titlebar')?.getBoundingClientRect();
      if (window.redjohn.platform === 'darwin' && (!logo || !bar || logo.top < bar.bottom || bar.height < 36)) throw new Error('Logo overlaps native window controls');
    };
    assertChrome(); await window.redjohn.toggleMaximize();
    await new Promise(resolve => setTimeout(resolve, 250)); assertChrome();
    await window.redjohn.toggleMaximize();
  })()`);
  stages.push("native_titlebar_clearance");
  await cdp("Page.reload");
  await until("!!document.querySelector('h1') || document.body?.innerText.includes('Select a pentest')", "workspace after reload");
  await createRun("Native fixture completion");
  await until("!!Array.from(document.querySelectorAll('option')).find(o => o.textContent === 'Fixture child')", "live child recipient");
  stages.push("create_start_child_stream");
  await until("document.body.innerText.includes('Streaming') && !document.body.innerText.includes('No output yet.')", "live terminal output");
  stages.push("live_terminal_output");
  await evaluate(`document.querySelector('[role=combobox][aria-label="Recipient agent"]').click()`);
  await until("!!Array.from(document.querySelectorAll('[role=option]')).find(o => o.textContent === 'Fixture child')", "custom agent popup");
  await evaluate("Array.from(document.querySelectorAll('[role=option]')).find(o => o.textContent === 'Fixture child').click()");
  await until("!document.querySelector('input[aria-label=" + JSON.stringify("Message this agent…") + "]')?.disabled", "message composer");
  await evaluate(`(() => {
    const input = document.querySelector('input[aria-label="Message this agent…"]');
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(input, 'Local smoke message');
    input.dispatchEvent(new Event('input', { bubbles: true }));
  })()`);
  await until("!document.querySelector('button[aria-label=" + JSON.stringify("Send") + "]')?.disabled", "send button");
  await evaluate("document.querySelector('button[aria-label=Send]').click()");
  await until("document.querySelector('input[aria-label=" + JSON.stringify("Message this agent…") + "]')?.value === ''", "message accepted");
  stages.push("message_accepted");
  await until("!!document.querySelector('[aria-label=" + JSON.stringify("run status: Completed") + "]')", "completed live state", 60_000);
  stages.push("completion_live_state");
  await createRun("Native fixture stop");
  await click("Stop run");
  await until("!!document.querySelector('[aria-label=" + JSON.stringify("run status: Stopped") + "]')", "stopped state");
  stages.push("stop_run");
  await click("Reports");
  await until("document.body.innerText.includes('No reports yet.')", "report empty state");
  await click("Generate report");
  await until("!!document.querySelector('[data-testid=reports-page] tbody tr')", "persisted report row");
  const reportId = await evaluate("document.querySelector('[data-testid=reports-page] tbody tr td').textContent");
  await click("Workspace");
  await click("Reports");
  await until(`document.body.innerText.includes(${JSON.stringify(reportId)})`, "report remount persistence");
  await evaluate(`(async () => {
    const info = await window.redjohn.getEngineInfo(); const token = await window.redjohn.getToken();
    const response = await fetch(info.baseUrl + '/reports/' + ${JSON.stringify(reportId)} + '/download', { headers: { Authorization: 'Bearer ' + token } });
    if (!response.ok || !(response.headers.get('content-disposition') || '').includes('attachment')) throw new Error('Report download failed');
    if (!(await response.text()).includes('Native fixture stop')) throw new Error('Report contains wrong run');
  })()`);
  stages.push("reports_empty_create_remount_download");
  // Archive/restore retain the report, and deleting this session leaves the other intact.
  await click("Archive");
  await until("document.body.innerText.includes('Archived')", "archived session");
  await click("Restore");
  await until("!!Array.from(document.querySelectorAll('button')).find(b => b.textContent.trim() === 'Archive')", "restored session");
  await click("Delete");
  await until("!!document.querySelector('[role=dialog][aria-label=\"Delete pentest\"]')", "delete review");
  await click("Delete pentest");
  await until("document.querySelector('h1')?.textContent === 'Native fixture completion'", "remaining session selected");
  await click("Workspace");
  await until("document.querySelector('[data-testid=terminal-viewport]')?.innerText.includes('builtin:complete_task')", "saved session terminal history");
  stages.push("saved_session_terminal_replay");
  await click("Reports");
  await until("document.querySelector('[data-testid=reports-page]')?.innerText.includes('No reports yet.')", "reports isolated after session delete");
  await evaluate(`(async () => {
    const info = await window.redjohn.getEngineInfo(); const token = await window.redjohn.getToken();
    const runs = await fetch(info.baseUrl + '/pentests', { headers: { Authorization: 'Bearer ' + token } }).then(r => r.json());
    if (runs.items.length !== 1 || runs.items[0].name !== 'Native fixture completion') throw new Error('Session deletion affected another run');
  })()`);
  stages.push("archive_restore_delete_session_isolation");
  await click("Workspace");
  await click("Tools →");
  await until("document.body.innerText.includes('Metasploit') && document.body.innerText.includes('OWASP ZAP')", "Tools navigation");
  await click("Memory");
  await until("!!document.querySelector('input[aria-label=\"Embeddings base URL\"]') && !!document.querySelector('input[aria-label=\"Embeddings model\"]')", "memory embedding fields");
  await until("!!Array.from(document.querySelectorAll('button')).find(b => b.textContent === 'Check OpenViking connection')", "memory connection check");
  if (await evaluate("!!document.querySelector('[role=combobox][aria-label=\"Memory mode\"]') || !!document.querySelector('input[aria-label=\"OpenViking service key\"]')")) throw new Error("Obsolete memory form remains");
  stages.push("compact_memory_and_tools_navigation");
  await click("Tools");
  await until("document.body.innerText.includes('Metasploit') && document.body.innerText.includes('OWASP ZAP') && !!Array.from(document.querySelectorAll('button')).find(b => b.textContent.includes('Download') || b.textContent === 'Scanners installed')", "assessment tools and on-demand scanner provisioning");
  stages.push("native_tools_settings");
  await click("NIST NVD");
  await until("document.body.innerText.includes('Without a key 5 req/30sec') && document.body.innerText.includes('With free key 50 req/30sec')", "NVD quota settings");
  await click("Providers");
  await click("Add provider connection");
  await until("!!document.querySelector('button[data-provider=custom]')", "provider list");
  await evaluate("document.querySelector('button[data-provider=custom]').click()");
  await evaluate(`(() => {
    const set = (label, value) => { const el = document.querySelector('input[aria-label="' + label + '"]'); Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set.call(el, value); el.dispatchEvent(new Event('input', { bubbles: true })); };
    set('Connection name', 'Fixture connection'); set('API base URL', ${JSON.stringify(fixtureTarget + '/v1')}); set('Provider API key', 'native-fixture-key');
  })()`);
  await click("Continue");
  await until("!!document.querySelector('[role=combobox][aria-label=\"Provider model\"]')", "readable model selection");
  await until("document.body.innerText.includes('Fixture model')", "model display name");
  await click("Save connection");
  await until("document.body.innerText.includes('Provider connection saved.')", "provider saved");
  await click("Check connection");
  await until("document.body.innerText.includes('Authenticated model request succeeded.')", "frozen SDK and credential access");
  await click("Use");
  await until("document.body.innerText.includes('In use')", "provider activated");
  await evaluate("window.redjohn.restartEngine()");
  await until("window.redjohn.getEngineInfo().then(i => i.state === 'running')", "engine restart after configuration", 60_000);
  await click("Providers");
  await until("document.body.innerText.includes('Fixture connection') && document.body.innerText.includes('In use')", "restored provider");
  await click("Check connection");
  await until("document.body.innerText.includes('Authenticated model request succeeded.')", "credential survives engine restart");
  stages.push("provider_sdk_activation_and_restart_persistence");

  // Quit through the same IPC used by the close dialog. No forced kill in a pass.
  let quitError;
  void evaluate("window.redjohn.quitAndStopEngine()").catch((error) => { quitError = String(error); });
  for (let i = 0; i < 150 && child.exitCode === null && child.signalCode === null; i++) await delay(100);
  if (child.exitCode !== 0) throw new Error(`App did not quit cleanly: ${child.exitCode}, ${child.signalCode}; quit IPC: ${quitError}; logs: ${logs}`);
  const lockExists = await access(join(root, "core", "smoke", "profile.lock")).then(() => true, () => false);
  if (lockExists) throw new Error("Engine profile lock survived app quit");
  stages.push("clean_engine_quit");
  console.log(JSON.stringify({ executable: resolve(executable), hidden_window: true, stages, passed: true }));
} catch (error) {
  const backend = ws ? await evaluate(`(async () => {
    const info = await window.redjohn.getEngineInfo();
    const token = await window.redjohn.getToken();
    const get = path => fetch(info.baseUrl + path, { headers: { Authorization: 'Bearer ' + token } }).then(r => r.json());
    const runs = await get('/pentests');
    return await Promise.all(runs.items.map(async run => ({ run, snapshot: await get('/pentests/' + run.run_id + '/snapshot') })));
  })()`).catch(() => null) : null;
  console.error(JSON.stringify({ stages, passed: false, error: String(error), streamDiagnostics, backend }));
  process.exitCode = 1;
} finally {
  for (const request of pending.values()) request.resolve({});
  ws?.close();
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
  await delay(250);
  // A failed UI smoke may never reach the quit IPC; terminate only its own
  // isolated profile engine, never a process from the user's normal profile.
  try {
    const { readFile } = await import("node:fs/promises");
    const lock = JSON.parse(await readFile(join(root, "core", "smoke", "profile.lock"), "utf8"));
    // Guard against PID reuse: a stale lock may name a recycled pid now owned
    // by an unrelated process. Only signal it if `ps` confirms it is still a
    // RedJohn engine (dev `redjohn_core.serve` or packaged `redjohn-engine`).
    let ownsPid = false;
    try {
      const cmd = execFileSync("/bin/ps", ["-p", String(lock.pid), "-o", "command="], { encoding: "utf8" }).trim();
      ownsPid = /redjohn-engine|redjohn_core/i.test(cmd);
    } catch { /* pid not alive */ }
    if (ownsPid) {
      process.kill(lock.pid, "SIGTERM");
      await delay(500);
    }
  } catch { /* Engine already stopped or never created its lock. */ }
  if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
  if (launchServices) {
    // `open -W` is only the launch controller. Reap a failed test's main app
    // by its unique private user-data argument, never the normal application.
    const table = execFileSync("/bin/ps", ["-axo", "pid=,command="], { encoding: "utf8" });
    for (const line of table.split("\n")) {
      const match = line.trim().match(/^(\d+)\s+(.+)$/);
      if (match && match[2].startsWith(resolve(executable) + " ") && match[2].includes(`--user-data-dir=${join(root, "ui")}`)) {
        try { process.kill(Number(match[1]), "SIGTERM"); } catch { /* already exited */ }
      }
    }
  }
  fixtureServer.closeAllConnections();
  await new Promise((resolve) => fixtureServer.close(resolve));
  await rm(root, { recursive: true, force: true });
}
