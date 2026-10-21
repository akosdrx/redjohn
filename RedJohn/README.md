# RedJohn

Shared host admission, durable capacity waiting and opt-in Linux memory containment:
[configuration and boundaries](docs/shared-resources-and-os-memory.md).
The full master-prompt task remains tracked in the [completion ledger](../docs/redjohn-completion-status.md).

Optional httpx, standard Katana and VulnX intelligence: [configuration, pins and limits](docs/projectdiscovery-adapters.md), [verification](../docs/redjohn-projectdiscovery-verification.md).

Optional ffuf discovery and assessment Web View: [configuration and limits](docs/ffuf-discovery.md), [real E2E evidence and images](../docs/redjohn-ffuf-verification.md).

The [continuous refresh/replay workflow](docs/continuous-refresh-replay.md) connects
successful session refresh to fresh Chromium POST capture and selected Nuclei
replay inside the same persistent scheduler batch.

Open-source AI hackers for your apps. CLI, Go TUI, and web viewer.

```bash
pip install -e .
redjohn --help
```

MCP connections are optional and operator-managed. RedJohn reads
`~/.redjohn/mcp-servers.json` (or `REDJOHN_MCP_CONFIG`) without creating or
rewriting it. No CVE or OSINT MCP server is installed or configured by default;
the native `lookup_cve` and `hunt` tools remain available. See
[custom MCP configuration](docs/mcp-configuration.md).

Persistent assessment (actual local headless Chromium, no LLM needed):

```bash
pip install -e '.[browser]'
python -m playwright install chromium
redjohn assess demo --cycles 5 --output ../redjohn_runs/local-assessment
redjohn assess health
```

For the actual HTTPS Chromium → inventory → Nuclei scheduler demonstration,
prepare the optional pinned engine from the repository root:

```bash
.venv/bin/python RedJohn/scripts/install-nuclei-pinned.py
.venv/bin/python RedJohn/scripts/create-nuclei-fixture-lock.py
cd RedJohn
../.venv/bin/python -m redjohn.assessment https-demo --output ../redjohn_runs/https-e2e
cd ..
```

The explicit installer checks official Nuclei v3.11.1 archive/checksum/license
pins without overwriting an existing installation or downloading a template
collection. The project's reviewed fixture template is locked separately. No test or
scheduler run installs optional tools automatically. The HTTPS demo uses real
Chromium and Nuclei with strict upstream TLS validation, persists the queue across
CLI processes, verifies a fixed control, and retains the historical candidate.
Its own marker is integration evidence, not a CVE or RCE proof.

Read [the runbook](../docs/redjohn-runbook.md),
[implementation audit](../docs/redjohn-implementation-audit.md),
[Nuclei integration](docs/nuclei-integration.md),
[skill mapping](docs/redjohn-skill-coverage.md), and
[actual browser verification](docs/redjohn-browser-verification.md).
The governed browser supports explicit HTTP(S) literal-loopback lab fixtures;
HTTPS inspection checks every request and validates the upstream CA/hostname.
The Linux remote path requires exact HTTPS origins/IP allowlists, actual kernel
namespace attestation and the inspected proxy. Authenticated Nuclei replay uses
host-only credentials bound to an observed GET/HEAD or explicitly approved POST
request and its actor, tenant, session revision and body SHA-256. JSON, URL-encoded
form and multipart POST bodies retain exact bytes within a 64 KiB ceiling; policy
allowlists, a private version-2 vault and real sent-request evidence are required.
Explicit non-idempotent session-refresh jobs rotate headers/cookies and advance
numeric revisions without rewriting old jobs or captures.
The configured `browser_post_capture` path now captures real Chromium-generated
POSTs and automatically approves only exact private rules after complete 2xx
transport proof. Explicit body-token bindings rotate selected JSON/form/multipart
fields without changing other bytes or uploads; a fresh browser capture replaces
pending approval. Startup resolves `current` revision rules into durable capture
jobs. See [browser capture/body-token setup](docs/browser-post-body-tokens.md). Read
[POST capture, replay and refresh](docs/post-refresh-replay.md) for the durable
reservation, private-file and fresh-capture contracts. Unsupported hosts and missing prerequisites fail
closed. See [remote enforcement and replay](docs/remote-egress-auth.md) for the
supported subset and actual E2E commands. Missing specialist adapters remain
explicitly unsupported; this is not full master-prompt acceptance.
The [remote/auth verification record](../docs/redjohn-remote-auth-verification.md)
reports the previous GET/HEAD owned non-loopback Linux chain and its explicit
coverage limits. The current POST/refresh implementation and test commands are
tracked separately in [the new workflow](docs/post-refresh-replay.md).
All 47 assessment contracts are English, with original and translated hashes
kept separately; the existing twelve English core skills remain available.
Actual engine/Chromium tests and mocked scanner/installer tests are reported
separately in [verification](../docs/redjohn-verification.md).

### Arjun, sqlmap és Dalfox — kijelölt tartós feladatok

A RedJohn opcionális GET/query specialistákat és külön, újraindítás után is
folytatható Chromium XSS-megerősítést tartalmaz. A motorok csak kijelölt jobnál
indulnak, közös scope/egress/kérés/erőforrás-korláttal. Telepítés, inputhatárok,
licencfeltételek és indítás: [használati leírás](docs/query-specialists.md).
A valódi binárisos és a kontraktusteszteket a [mérési jegyzőkönyv](../docs/redjohn-specialists-verification.md) különíti el.

TInjA / Schemathesis / Interactsh selected profiles and durable late polling:
[verification](../docs/redjohn-schema-oast-verification.md),
[adapter contract](docs/schema-oast-adapters.md).

Authenticated TInjA/Schemathesis/OAST selected POST fields and bounded session recovery: [docs/authenticated-schema-oast.md](docs/authenticated-schema-oast.md).

Byte-preserving MIME/charset variants and persistent CLI deadline diagnostics:
[docs/mime-replay-and-restart.md](docs/mime-replay-and-restart.md).
