# RedJohn (`rjkali`) — Native Kali Linux & macOS Edition

Autonomous security assessment, vulnerability verification, and P2P Swarm penetration testing platform built for **Kali Linux** and **macOS**: a durable Python assessment core, native **Rust Ratatui TUI** (`redjohn-tui`), 59 domain & specialized assessment skill contracts, and local Web Viewer.

## Repository layout

```text
redjohn/                 Python package, P2P Swarm, assessment adapters, scheduler, Rust TUI, Web Viewer
redjohn/skills/          59 built-in core, domain, and assessment skill contracts
scripts/                 Kali Linux & general installation scripts + Hatchling TUI build hook
pyproject.toml           Package and build configuration
```

## Install on Kali Linux

```bash
git clone https://github.com/akosdrx/redjohn.git rjkali
cd rjkali
./scripts/install-kali.sh
```

The installer sets up `.venv`, installs the `[browser]` extra with Playwright + Chromium, compiles the native Rust TUI binary (`redjohn-tui`), and configures `agent-browser`.

## Key Features

- **Native Rust TUI (`redjohn-tui`)**: Interactive Setup Desk, Live Dashboard, Swarm Graph (`Ctrl+G`), 59-Skill Browser & Selector (`Ctrl+K`), Model & Reasoning Effort Picker (`Ctrl+M`), and Findings Explorer (`Ctrl+F`).
- **59 Auto-Loaded Skill Contracts**: 3 core contracts (`root`, `safety`, `sandbox`), 9 offensive domain contracts (`recon`, `auth`, `rce`, `injection`, `api`, `client`, `logic`, `supply`, `whitebox`), and 47 specialized assessment contracts (`redjohn/skills/assessment/*`), automatically inferred at agent creation and continuously loaded across turns.
- **Keyless Web Search & Content Extraction**: Works out of the box without external search API keys via DuckDuckGo HTML search, direct HTTP extraction, and headless Chromium/Playwright rendering fallback (supports optional `PERPLEXITY_API_KEY` or `EXA_API_KEY` when configured).
- **Governed Assessment Core**: Persistent SQLite inventory (`AssessmentStore`), fair job scheduler (`Scheduler`), Host Resource Governor, and native CVE intelligence (`lookup_cve`).

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
