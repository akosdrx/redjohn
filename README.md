# RedJohn (`rjkali`) — Native Kali Linux Edition

Autonomous security assessment, vulnerability verification, and penetration testing platform built natively for **Kali Linux** (Docker-free local runtime + 170 specialized offensive/defensive skills + Go Bubble Tea TUI + Web Viewer + optional Kali `.deb` Desktop client).

## Key Features on Kali Linux

- **Docker-Free Native Kali Runtime (`local` backend):** Runs directly on Kali Linux (`UnixLocalSandboxSession`) with zero Docker dependency.
- **Native Kali Tool & Wordlist Integration:**
  - Automatically resolves Kali tools (`nmap`, `nuclei`, `ffuf`, `httpx-toolkit`, `sqlmap`, `wpscan`, `subfinder`, `gobuster`, `nikto`, `zaproxy`, `msfconsole`, `caido-cli`, `playwright`).
  - Automatic `httpx` -> `httpx-toolkit` and `zap.sh` -> `zaproxy` shims in `~/.strix/kali-shims` so Python `httpx` never collides with ProjectDiscovery `httpx-toolkit`.
  - Pre-configured environment variables and read-only sandbox grants for `/usr/share/seclists`, `/usr/share/wordlists` (`rockyou.txt`), `/usr/share/nmap/scripts`, and `/usr/share/exploitdb`.
- **170 Integrated Skills:**
  - 24 RedJohn Master Skill Packs (`01-attack-planner` through `24-zero-day-hunting`)
  - 77 Deep-Dive Reference Skills (`25-active-directory-attacks` through `101-xss-dom-advanced`, including `45-rce-exploitation`)
  - Dedicated CMS Framework Skills (`wordpress`, `joomla`, `drupal`, `prestashop`) + Strix native vulnerability & coordination skills
- **Native CVE & Exploit Intelligence (`lookup_cve`):**
  - Parallel correlation of NIST NVD CVSS v3.1/v4.0, FIRST EPSS (30-day exploit probability), CISA KEV, and GitHub PoC repositories with Composite Risk Score (`0–100`) and SSVC v2 decision tree (`Act` / `Attend` / `Track*` / `Track`).
- **Pre-Compiled Linux Go TUI Binaries:**
  - Includes statically linked Bubble Tea TUI binaries for both `linux/amd64` (`strix/bin/strix-tui-linux-amd64`) and `linux/arm64` (`strix/bin/strix-tui-linux-arm64`).

---

## Quick Install on Kali Linux

```bash
git clone https://github.com/itsolutionshu/rjkali.git
cd rjkali
./scripts/install-kali.sh
```

To also build and install the native Kali Linux `.deb` Electron Desktop application:

```bash
./scripts/install-kali.sh --desktop
```

---

## Usage

```bash
# Launch interactive Bubble Tea TUI:
rj
# (or: redjohn / strix)

# Launch real-time Web Viewer in browser:
strix view

# Run against a target directly:
rj -t https://target.example.com

# Headless / CI mode:
strix -n -t https://target.example.com --scan-mode deep
```
