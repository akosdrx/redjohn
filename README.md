# RedJohn (`rjkali`) — Native Kali Linux Edition

Autonomous security assessment, vulnerability verification, and penetration
testing platform built for **Kali Linux**: a durable Python assessment core,
Go Bubble Tea TUI, and local Web Viewer. The CLI, TUI, and viewer share the same
`AssessmentStore`, `Scheduler`, and `Control API`.

## Repository layout

Everything lives in this repository root:

```text
redjohn/                 Python package, adapters, scheduler, TUI, viewer
tests/                   unit, contract, and real-integration tests
scripts/                 installers, pinned-tool installers, maintenance
docs/                    current runbooks, contracts, and archived evidence
.github/                 CI workflows, scripts, policies, and fixtures
benchmarks/              soak and allocator diagnostics
examples/                reviewed assessment configurations
pyproject.toml           package, tool, and test configuration
```

## Install on Kali Linux

```bash
git clone https://github.com/akosdrx/redjohn.git rjkali
cd rjkali
./scripts/install-kali.sh
```

The installer creates the repository-root `.venv`, installs the governed
`[browser]` extra, and downloads Playwright Chromium. System Chromium remains
available only for the separate legacy `agent-browser` path.

## Bounded assessment

`rj assess` provides real Playwright/Chromium discovery, persistent SQLite
inventory, fair job scheduling, bounded evidence/cache/resources, and the
existing Nuclei integration with explicit engine/template locks. Optional tools
are selected individually; missing tools remain coverage gaps.

Independent controllers share host admission. An approved Linux run can request
a real cgroup-v2 memory/PID backstop. Pre-send contention waits durably and
resumes in the same controller. See the [resource runbook](docs/shared-resources-and-os-memory.md)
and the [completion ledger](docs/redjohn-completion-status.md).

The governed path supports owned HTTP(S) loopback labs and a Linux remote-HTTPS
path with kernel-attested worker namespaces, exact origin/IP allowlists, and a
controller-owned inspection proxy. Upstream CA/hostname validation and request
admission remain strict. Authenticated POST replay preserves approved JSON,
form, and multipart bytes up to 64 KiB. Private vault v2 approval and durable
sent-request evidence are required. Capture and session-refresh jobs use fenced
SQLite state; lost responses are never automatically resent.

With an explicit [`continuous_replay` mapping](docs/continuous-refresh-replay.md),
the durable scheduler continues session refresh → fresh Chromium capture →
selected Nuclei replay without restarting the coordinator. Optional
[bounded session recovery](docs/automatic-session-recovery.md) detects verified
401/private expiry and admits refresh under persistent limits.

See [POST/session workflow](docs/post-refresh-replay.md),
[browser capture and body-token refresh](docs/browser-post-body-tokens.md),
[remote egress/authenticated replay](docs/remote-egress-auth.md), and
[browser verification](docs/archive/redjohn-browser-verification.md).

## MCP

MCP connections are operator-managed. RedJohn reads `~/.redjohn/mcp-servers.json`
(or `REDJOHN_MCP_CONFIG`) without creating or rewriting it. No CVE or OSINT MCP
server is installed by default; native `lookup_cve` and `hunt` tools remain
available. See [custom MCP configuration](docs/mcp-configuration.md).

## Optional assessment adapters

- httpx, Katana, and VulnX: [configuration and limits](docs/projectdiscovery-adapters.md)
- ffuf and Web View: [runbook](docs/ffuf-discovery.md)
- Arjun, sqlmap, Dalfox: [query specialists](docs/query-specialists.md)
- TInjA, Schemathesis, Interactsh: [schema/OAST adapters](docs/schema-oast-adapters.md)
- source and artifact scanners: [source scanners](docs/redjohn-source-scanners.md)

Missing optional binaries are explicit blocked capabilities, not negative
vulnerability results.

## Usage

```bash
# Interactive TUI
rj

# Web Viewer
redjohn view

# Direct target
rj -t https://target.example.com

# Headless mode
redjohn -n -t https://target.example.com --scan-mode deep
```

For local/non-web targets without an approved assessment binding, the legacy SDK
path requires the explicit `--unconfined-legacy` flag. Web/API targets continue
under the host-bound policy.

## Optional Nuclei fixture engine

From the repository root:

```bash
.venv/bin/python scripts/install-nuclei-pinned.py
.venv/bin/python scripts/create-nuclei-fixture-lock.py
.venv/bin/python -m redjohn.assessment https-demo --output redjohn_runs/https-e2e
```

The installer verifies the pinned Nuclei v3.11.1 release without replacing an
existing installation or downloading a template collection. The demo uses real
Chromium and Nuclei with strict TLS validation, persists the queue across CLI
processes, and verifies a fixed control. Its marker is integration evidence,
not a CVE/RCE reproduction.

## Tests and CI

```bash
PYTHONPATH=. .venv/bin/python -m pytest tests -q
(cd redjohn/interface/viewer/frontend && npm test && npm run build)
(cd redjohn/interface/tui && go vet ./... && go test -race -count=1 ./...)
```

CI runs the Ubuntu x64/ARM64 matrix, native component smoke, artifact E2E, and
controller-memory attribution. See [the remediation status](docs/redjohn-remediation-status.md)
for commit-bound results and open items.

## Documentation

- [Architecture](docs/redjohn-architecture.md)
- [Runbook](docs/redjohn-runbook.md)
- [Requirements](docs/redjohn-requirements.md)
- [Completion status](docs/redjohn-completion-status.md)
- [Remediation and verification](docs/redjohn-remediation-status.md)
- [Capability catalogue](docs/redjohn-capabilities.md)
- [Implementation audit](docs/redjohn-implementation-audit.md)
- [Skill coverage](docs/redjohn-skill-coverage.md)
