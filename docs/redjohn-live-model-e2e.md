# Opt-in real model CLI and Go TUI verification

The manual `redjohn-live-model.yml` workflow prepares native Ubuntu 24.04 x64
and ARM64 jobs, sequentially. It calls the actual Python CLI entrypoint and
the actual Go TUI source. It does not replace the existing model-free terminal,
root-runner contracts, or scanner integration tests.

## Access and current verification boundary

Provide an explicit **bare OpenAI model identifier** as the `model` dispatch
input and configure the dedicated repository secret
`REDJOHN_LIVE_MODEL_API_KEY` using GitHub's secret settings. Never put a key in
a dispatch input, source file, CLI argument or chat. Existing local/provider
credentials are not read or uploaded. This opt-in harness currently supports
the OpenAI HTTPS Responses API only; RedJohn's other product providers stay
available and unchanged. No model is selected automatically.

Without either prerequisite, the job exits nonzero **before dependency/scanner
installation** and uploads `preflight.json` and `result.json` with
`status: blocked` and `live_model_verified: false`. A green contract test or
an older model-free terminal test cannot substitute for a real model result.

The new real path has not been exercised with a provider credential. Until a
completed commit-bound run contains both interface proofs, its model, scanner,
display, stop/resume and cleanup assertions remain **unverified**. Missing
credentials do not prove that those assertions work or fail.

## What a successful run must prove

* A private loopback HTTPS fixture and approved metadata-only seed surfaces;
  the model must submit the jobs through the real `assessment_control` tool.
* Actual Chromium discovery and pinned Nuclei execution in the existing
  persistent SQLite scheduler, completed coverage and the positive fixture
  finding. No supplied external assessment target is accepted.
* SDK session `assessment_control` and `finish_scan` calls, nonzero recorded
  model usage, and a saved assessment report. The CLI's positive finding exit
  code 2 is accepted only with the complete evidence, never on its own.
* The native terminal's waiting state, explicit Stop, observed stopped state,
  resume instruction through IPC, resumed model/scanner work, displayed
  completion and explicit Quit. This is an in-process stop/resume test; it
  does not claim to prove a complete restart of the terminal application.
* A real pre-exec 2 GiB owner cgroup within the shared 4 GiB aggregate, verified
  owner namespace, zero OOM kills, released runtime reservations and removed
  owner cgroup. Missing kernel/namespace support fails closed. Existing job
  AppArmor hardening and cleanup are reused unchanged.

The small fixture/gateway/evidence supervisor stays outside the owner limit;
it is not part of the mixed benchmark or an assertion about all host memory.

## Deterministic provider and execution budgets

The harness's loopback relay forwards accepted requests to the fixed
`https://api.openai.com` host using normal certificate and hostname validation.
Only Responses and chat-completions API paths are admitted. All CLI, resumed,
child and preflight requests share **24 calls**, **2048 output tokens per
call**, **512 KiB per request**, **8 MiB per response**, and a **1200-second
admission window**. Calls have finite transport/response timeouts. The overall
relay admits at most two active handlers, including incomplete HTTP headers;
extra connections are closed without contacting the provider. The overall
job has a 45-minute timeout; each owned interface process has a 900-second
supervisor deadline. Each agent has 12 turns and a secondary USD 2 application
cost stop. The gateway caps requests independently of cost-table coverage.

Only the three reviewed tools `assessment_control`, `finish_scan` and
`wait_for_user` are exposed by the relay. It buffers the bounded real response
and checks structured calls before returning it to the unchanged SDK, rejecting
shell, custom and built-in tool calls. This changes test transport latency;
it is not a streaming-performance benchmark or a synthetic model response.

The actual provider output cap is also available to ordinary RedJohn agent
runs as optional `LLM_MAX_OUTPUT_TOKENS` (`1..65536`). Its default is unset,
preserving existing behavior. The installed Agents SDK maps
`ModelSettings.max_tokens` to Responses `max_output_tokens`; see the official
[token limits documentation](https://developers.openai.com/api/docs/guides/token-counting).

## Evidence and invocation

After this workflow is registered in GitHub:

```sh
gh workflow run redjohn-live-model.yml --repo akosdrx/redjohn \
  --ref codex/redjohn-ubuntu-actions -f model=YOUR_EXPLICIT_OPENAI_MODEL
```

The workflow must exist on GitHub's default branch for normal standalone manual
discovery/dispatch. Before that registration, use the existing Ubuntu workflow's
manual bridge (`live_model_only=true`, `model=YOUR_EXPLICIT_OPENAI_MODEL`); it
calls this local reusable workflow at the same selected commit. Missing secrets
are still a failed blocked run on both architectures, never a successful skip.

```sh
gh workflow run redjohn-ubuntu.yml --repo akosdrx/redjohn \
  --ref codex/redjohn-ubuntu-actions \
  -f live_model_only=true -f model=YOUR_EXPLICIT_OPENAI_MODEL
```

Both the blocked preflight and real harness outcomes have JUnit artifacts.
Blocked capability cases use explicit JUnit errors with zero skipped tests;
only complete interface and real-provider proof gets the
`real_model_interface_e2e` classification. JSON retains the authoritative
blocked/failed/passed state and distinguishes absence from a negative finding.

Artifacts are bound to commit SHA, run ID, attempt and architecture. They retain
source hashes, preflight/real provider counters, redacted terminal transcripts,
owner receipts and profile/cgroup cleanup. Raw SDK session databases, approval
keys, fixture TLS files and local relay credentials remain in `RUNNER_TEMP` and
are deliberately excluded from artifacts. The provider key stays in the relay
process; CLI/TUI children receive a fresh local relay token only.

`test_model_output_budget.py` and `.github/tests/test_live_model_harness.py`
are explicitly **synthetic settings/security contracts**. They do not contact
a provider and cannot establish real model/CLI/TUI/scanner success.
