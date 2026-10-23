# RedJohn (`rjkali`) — Native Kali Linux & macOS Edition

Autonomous security assessment, vulnerability verification, and P2P Swarm penetration testing platform built for **Kali Linux** and **macOS**: a durable Python assessment core, native **Rust Ratatui TUI** (`redjohn-tui`), 60 domain & specialized skill contracts, persistent agent memory, and a local Web Viewer.

## Repository layout

```text
redjohn/                 Python package, P2P Swarm, assessment adapters, scheduler, Rust TUI, Web Viewer
redjohn/skills/          60 built-in core, domain, assessment, and memory skill contracts
scripts/                 Kali Linux & general installation scripts + Hatchling TUI build hook
pyproject.toml           Package and build configuration
```

## Install on Kali Linux

```bash
git clone https://github.com/akosdrx/redjohn.git rjkali
cd rjkali
./scripts/install-kali.sh
```

The installer sets up `.venv`, installs the `[browser]` extra with Playwright + Chromium, compiles the native Rust TUI binary (`redjohn-tui`), and configures `agent-browser`. A Rust toolchain (cargo) is required — wheel builds compile the TUI sidecar too.

## Key Features

- **Native Rust TUI (`redjohn-tui`)**: Interactive Setup Desk and Live Dashboard with keyboard modals (F3 MCP, F4 Skills, F5 Findings) and slash commands (`/models`, `/swarm`, `/openviking`).
- **60 Skill Contracts**: 3 core contracts (`root`, `safety`, `sandbox`), 9 offensive domain contracts (`recon`, `auth`, `rce`, `injection`, `api`, `client`, `logic`, `supply`, `whitebox`), 47 specialized assessment contracts (`redjohn/skills/assessment/*`), and the OpenViking memory contract — inferred at agent creation and continuously loaded across turns.
- **Persistent Agent Memory (OpenViking)**: prior findings and target intelligence are recalled at scan start (fenced and labeled as untrusted data in the scope prompt) and verified findings are archived automatically under `viking://resources/pentests/`.
- **Keyless Web Search & Content Extraction**: works out of the box without external search API keys via DuckDuckGo HTML search, direct HTTP extraction, and headless Chromium/Playwright rendering fallback (optional `PERPLEXITY_API_KEY` or `EXA_API_KEY` support).
- **Governed Assessment Core**: persistent SQLite inventory (`AssessmentStore`), fair job scheduler (`Scheduler`), host resource governor with host-derived limits, and native CVE intelligence (`lookup_cve`).

## Usage

```bash
# Interactive Rust TUI (Setup Desk -> Live Session)
rj

# Direct target in TUI
rj -t https://target.example.com

# Headless CLI mode
redjohn -n -t https://target.example.com --scan-mode deep

# Local Web Viewer
redjohn view
```

## Development

```bash
pip install -e . --group dev
ruff check redjohn                                        # lint
mypy redjohn                                              # strict type check
pytest tests -q                                           # test suite
cargo test --manifest-path redjohn/interface/tui/Cargo.toml   # Rust TUI tests
```
