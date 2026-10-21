# RedJohn (`rjkali`) — Native Kali Linux Edition

Real ffuf discovery in the durable scheduler and assessment Web View: [runbook](RedJohn/docs/ffuf-discovery.md), [E2E evidence and images](docs/redjohn-ffuf-verification.md).

Autonomous security assessment, vulnerability verification, and penetration testing platform built natively for **Kali Linux** (Docker-free local runtime + Go Bubble Tea TUI + Web Viewer).

Source lives in `RedJohn/` — CLI, Go TUI, and web viewer.

## Persistent bounded assessment core

The new `rj assess` path adds actual Playwright/Chromium discovery, persistent
SQLite inventory and fair job scheduling, bounded evidence/cache/resource
control, and the existing Nuclei integration with explicit engine/template locks.
Optional tools are selected individually. Missing tools are coverage gaps.

Independent assessment controllers now share host admission; an approved Linux
run can request a real cgroup memory/pids backstop. Safe pre-send contention can
wait durably and resume in the same controller. See the [resource runbook](RedJohn/docs/shared-resources-and-os-memory.md)
and the [complete remaining-work ledger](docs/redjohn-completion-status.md).

MCP connections are operator-managed: startup and the Kali installer never add
CVE/OSINT servers or rewrite the MCP configuration. The native RedJohn tools and
[custom MCP support](RedJohn/docs/mcp-configuration.md) remain available.

With an explicit [`continuous_replay` mapping](RedJohn/docs/continuous-refresh-replay.md),
the running durable scheduler continues session refresh → fresh Chromium capture →
selected Nuclei replay without restarting the coordinator.
Its optional [bounded session recovery](RedJohn/docs/automatic-session-recovery.md)
detects verified 401/private expiry and admits refresh under persistent limits.

The explicit `browser_post_capture` capability captures real application-generated
Chromium JSON/form/multipart POSTs under private automatic-approval rules. Startup
reconciles each current actor/revision into the durable queue. Reviewed body-token
bindings update only selected fields after refresh; actual fresh browser capture
is required before replay. See [browser capture and body-token refresh](RedJohn/docs/browser-post-body-tokens.md).

The governed path supports owned HTTP(S) loopback labs and a Linux remote-HTTPS
path with kernel-attested worker namespaces, exact origin/IP allowlists and a
controller-owned inspection proxy. Upstream CA/hostname validation and request
admission remain strict. The existing Nuclei adapter uses explicit engine/template
locks and host-only credentials bound to an observed request, actor and session.
Authenticated POST replay preserves approved JSON, form and multipart bytes up to
64 KiB. Exact policy allowlists, private vault v2 approval and durable sent-request
evidence are required. Capture and explicit session-refresh jobs use fenced SQLite
state; lost responses never trigger automatic resends. See [POST/session workflow](RedJohn/docs/post-refresh-replay.md).

From the repository root, prepare the optional engine once, then run the real
Chromium → observed inventory → Nuclei → fixed-control/restart demonstration:

```bash
.venv/bin/python RedJohn/scripts/install-nuclei-pinned.py
.venv/bin/python RedJohn/scripts/create-nuclei-fixture-lock.py
cd RedJohn
../.venv/bin/python -m redjohn.assessment https-demo --output ../redjohn_runs/https-e2e
cd ..
```

The installer verifies the pinned official Nuclei v3.11.1 release, preserves
existing installations, and downloads no upstream template collection. Tests and
scheduled jobs never install it automatically. The demo contacts only its own
HTTPS fixture; its harmless marker demonstrates integration, not a real CVE/RCE.
It persists pending work, resumes in separate CLI processes, and checks an
explicit fixed-control retest. Reports distinguish missing/blocked capabilities
from completed negative checks. Remote browser/scanner jobs remain blocked on
hosts without working Linux namespace enforcement. The owned non-loopback Linux
fixture passed the previous GET/HEAD browser/inventory/authenticated Nuclei/restart
E2E; [measurements and limits](docs/redjohn-remote-auth-verification.md) retain the
browser's partial coverage and candidate-only finding status. The legacy
interactive agent remains a separate workflow. A local/non-web target that has
no approved assessment binding is refused unless the operator explicitly passes
`--unconfined-legacy`; web/API targets continue under the host-bound policy.
Current remediation evidence: [remediation status](docs/redjohn-remediation-status.md).
See [audit](docs/redjohn-implementation-audit.md),
[runbook](docs/redjohn-runbook.md), [POST replay/session refresh](RedJohn/docs/post-refresh-replay.md),
[remote egress/authenticated replay](RedJohn/docs/remote-egress-auth.md),
and [requirements](docs/redjohn-requirements.md).

## Key Features on Kali Linux

- **Docker-Free Native Kali Runtime (`local` backend):** Runs directly on Kali Linux (`UnixLocalSandboxSession`) with zero Docker dependency.
- **Native Kali Tool & Wordlist Integration:**
  - Automatically resolves Kali tools (`nmap`, `nuclei`, `ffuf`, `httpx-toolkit`, `sqlmap`, `wpscan`, `subfinder`, `gobuster`, `nikto`, `zaproxy`, `msfconsole`, `caido-cli`, `playwright`).
  - Automatic `httpx` -> `httpx-toolkit` and `zap.sh` -> `zaproxy` shims in `~/.redjohn/kali-shims` so Python `httpx` never collides with ProjectDiscovery `httpx-toolkit`.
  - Pre-configured environment variables and read-only sandbox grants for `/usr/share/seclists`, `/usr/share/wordlists` (`rockyou.txt`), `/usr/share/nmap/scripts`, and `/usr/share/exploitdb`.
- **Skills:** twelve existing English contracts are preserved, plus 47 English lazy
  assessment contracts with explicit implemented/unsupported capability mapping.
  Original-source and translated-content hashes are separate. Skill presence does
  not imply that a scanner adapter is available.
- **Native CVE & Exploit Intelligence (`lookup_cve`):**
  - Parallel correlation of NIST NVD CVSS v3.1/v4.0, FIRST EPSS (30-day exploit probability), CISA KEV, and GitHub PoC repositories with Composite Risk Score (`0–100`) and SSVC v2 decision tree (`Act` / `Attend` / `Track*` / `Track`).
- **Pre-Compiled Linux Go TUI Binaries:**
  - Includes statically linked Bubble Tea TUI binaries for both `linux/amd64` (`redjohn/bin/redjohn-tui-linux-amd64`) and `linux/arm64` (`redjohn/bin/redjohn-tui-linux-arm64`).

---

## Quick Install on Kali Linux

```bash
git clone https://github.com/akosdrx/redjohn.git rjkali
cd rjkali
./RedJohn/scripts/install-kali.sh
```

The installer uses the repository-root `.venv`, installs the governed
`[browser]` extra, and downloads Playwright Chromium. The system Chromium is
kept for the separate legacy `agent-browser` path.

---

## Usage

```bash
# Launch interactive Bubble Tea TUI:
rj
# (or: redjohn)

# Launch real-time Web Viewer in browser:
redjohn view

# Run against a target directly:
rj -t https://target.example.com

# Headless / CI mode:
redjohn -n -t https://target.example.com --scan-mode deep
```

### Arjun, sqlmap és Dalfox — kijelölt tartós feladatok

A RedJohn opcionális GET/query specialistákat és külön, újraindítás után is
folytatható Chromium XSS-megerősítést tartalmaz. A motorok csak kijelölt jobnál
indulnak, közös scope/egress/kérés/erőforrás-korláttal. Telepítés, inputhatárok,
licencfeltételek és indítás: [használati leírás](RedJohn/docs/query-specialists.md).
A valódi binárisos és a kontraktusteszteket a [mérési jegyzőkönyv](docs/redjohn-specialists-verification.md) különíti el.

TInjA / Schemathesis / Interactsh selected profiles and durable late polling:
[verification](docs/redjohn-schema-oast-verification.md),
[adapter contract](RedJohn/docs/schema-oast-adapters.md).

Authenticated TInjA/Schemathesis/OAST selected POST fields and bounded session recovery: [RedJohn/docs/authenticated-schema-oast.md](RedJohn/docs/authenticated-schema-oast.md).

Byte-preserving MIME/charset variants and persistent CLI deadline diagnostics:
[RedJohn/docs/mime-replay-and-restart.md](RedJohn/docs/mime-replay-and-restart.md).
