# RedJohn user-interface regression and real integration coverage

The active Go TUI now has meaningful executable regression coverage. Viewer
tests use Node's built-in runner with the already pinned TypeScript compiler;
no new npm dependency or production test loader is introduced. The real browser,
native terminal and scanner integrations remain distinct from response doubles.

## Coverage added

| Suite | Actual boundary exercised | Evidence classification |
| --- | --- | --- |
| Go `internal/app` | Version/capability negotiation; frame budgets; concurrent duplicate stop suppression; exact request correlation; revision gaps/resync; atomic collection rollback; terminal failure; explicit stop confirmation; stable selection; report fences | 15 Go contract test functions, 21 cases including subtests; controlled protocol peers |
| Viewer Node tests | Run/finding import, cyclic agent trees, target URL host classification, capability denial, auth/report/steering errors and retry, bounded/escaped assessment rendering | 14 unit/contract tests, including 6 with HTTP-response/transport doubles; 2 render actual React components to static markup |
| `test_nuclei_cli_live.py` | Public `redjohn` CLI dispatch → persistent scheduler → pinned real Nuclei → owned CA-verified TLS target; new process resumes without traffic duplication; explicit repaired-target retest; persisted JSON/HTML reports | Real CLI/scanner/TLS integration; no LLM/provider used |
| `test_tui_terminal_live.py` | Freshly built native Go executable in an actual pseudo-terminal → real private IPC backend → actual agent coordinator and SQLite session; message, default Cancel, confirmed Stop, resumable message, Quit and reopened persisted history | Real terminal/IPC/coordinator/storage integration; owned agent has no LLM runner |
| `test_viewer_steering_live.py` | Sandboxed headless Chromium → actual authenticated local Viewer HTTP server → real coordinator/SQLite; missing capability denied; live delivery; unreachable stopped agent denied with draft retained; resumable retry | Real browser/HTTP/coordinator/storage integration; owned agent has no LLM runner |

The new tests exposed and fixed four concrete Viewer defects: arrays accepted as
finding objects, provider-looking URL substrings mislabeled as trusted repository
hosts, invalid MCP tool counts displayed, and rejected POST transports escaping
the structured failure contract and stranding pending controls.

## Commands

From the repository root, using its installed development environment:

```sh
cd redjohn/interface/tui
go vet ./...
go test -race -count=1 -json ./...
go build -trimpath -o /tmp/redjohn-user-flow/redjohn-tui ./cmd/redjohn-tui
```

From `redjohn/interface/viewer/frontend`:

```sh
npm ci
npx --no-install tsc --noEmit
npm test
npm test -- --test-reporter=junit --test-reporter-destination=/tmp/frontend.junit.xml
npm run build
```

The Node JUnit reporter writes `<testcase>` elements directly below
`<testsuites>`; evidence readers must count those actual cases too.

From the repository root, after the native binary and Viewer bundle are built:

```sh
REDJOHN_TUI_BINARY=/tmp/redjohn-user-flow/redjohn-tui PYTHONPATH=. \
  .venv/bin/python -m pytest -q \
  tests/test_nuclei_cli_live.py \
  tests/test_tui_terminal_live.py \
  tests/test_viewer_steering_live.py \
  --junitxml=/tmp/user-interface.junit.xml
```

The scanner test uses the reviewed `REDJOHN_NUCLEI_LOCK` when configured, otherwise
the existing local fixture lock. Missing binaries/bundles are explicit dependency
skips; these must fail a full-integration CI gate. Tests never download tools or
disable Chromium sandboxing, TLS verification or network isolation to pass.

## Verification limits

Initial focused checks ran on macOS ARM64 (Python 3.13.16, Node 24.21.0,
Go 1.27.1): all 14 frontend cases passed; all 21 Go cases (15 top-level test
functions) passed with the race detector; all three new real interface/CLI
integrations passed with no skips in 12.81 seconds; the existing real stdio MCP
case also passed. Ruff, TypeScript checking and the actual Vite build passed.
These are working-tree checks, not an Ubuntu x64/ARM64 CI claim. The
GitHub matrix must build the same sources with its pinned toolchains, set
`REDJOHN_TUI_BINARY` to the freshly built native executable and preserve its
commit-bound JUnit/log artifacts before claiming both platforms verified.

Existing real local stdio MCP round-trip/shutdown coverage remains active and is
independently executable as
`tests/test_mcp_configuration.py::test_operator_stdio_server_round_trip_and_shutdown`.
It does not require a provider or external MCP endpoint.

No live LLM/OAuth subscription, external relay/email delivery or remote provider
response is established by these tests. A configured model name, local response
double, delivered mailbox instruction, CLI exit or passed UI contract does not
prove a live model/agent scan. Those capabilities require their own authorized
credentials/service endpoint and final real E2E evidence.
The initial local configuration probe resolved no model, API key or API base;
it performed no external request and printed no secret values.
