# RedJohn Linux desktop

Native Debian/Ubuntu/Kali entry point, sharing the parent desktop UI and core.
There is no separate frontend fork and no Docker runtime.

The verified release is Linux ARM64. Build scripts and pinned tool assets also
support native x64 builders; this checkout does not claim an executed x64 release.
The current binary baseline is glibc 2.38: Ubuntu 24.04+, Debian 13+, and current
Kali rolling. Build older baselines separately; do not repackage a macOS engine.

## Install

```sh
sudo apt install --reinstall ./rj-linux-desktop/release/RedJohn-0.1.0-arm64.deb
redjohn
```

The deb installs native services and tools under `/opt/RedJohn`, the desktop
launcher, Chromium's sandbox fallback and an Ubuntu AppArmor user-namespace
profile. It retains assessments, credentials and memory in the user's local
profile across ordinary upgrades and removal/reinstallation.

An AppImage is also produced. On machines restricting unprivileged user
namespaces, prefer the deb, which provisions the sandbox helpers and policy.
The application and Playwright do not use `--no-sandbox`.

## Build on Linux

From the parent `rj-desktop` directory:

```sh
bash rj-linux-desktop/scripts/install-build-dependencies.sh
bash rj-linux-desktop/scripts/build.sh
```

Bootstrap provides pinned standalone Python, Node and the build environment.
The native engine, memory runtime, tool binaries, templates and MCP dependencies
are verified and bundled before packaging. Downloads happen during this explicit
build/provisioning step, not when a fresh harness starts. Qwen remains a separate,
explicit Memory installation. Native architecture is selected by bootstrap;
`RJ_LINUX_ARCH` must match the engine and tools, and packaging checks reject a
mismatch. Local package homepage/maintainer values are placeholders; override
`extraMetadata.homepage` and `linux.maintainer` for a public distribution.

## Kali tools

The engine first uses an installed system tool. It does not install a second
system binary or overwrite Kali's packages. The universal release includes
managed fallback binaries for missing tools. The MCP server chooses the proper
CLI flags for packaged versus Kali Arjun/Dalfox versions. ProjectDiscovery
`httpx-toolkit`/`pd-httpx` is distinguished from the Python HTTPX command.

Native scans, job status, stop and artifacts belong to one assessment. Playwright
uses isolated bundled Chromium. NIST NVD has its own optional encrypted API key
setting; its readonly MCP connection is shared inside the profile.

## Acceptance boundaries

Ubuntu 24.04.4 ARM64: real native tool executions, bundled Chromium, NVD handshake,
14 hidden GUI/IPC/provider/session stages, and real Qwen/Nomic memory extraction,
restart and crash recovery. Both saved-provider and Local extraction paths passed.
The readonly AppImage also passed those 14 GUI stages, with a temporary scoped
AppArmor namespace permission in the verification VM. Upgrade and removal/reinstall
retained the isolated archived assessment and encrypted provider connection.
Kali 2026.3: signed root filesystem on the verification VM's Ubuntu kernel;
14 hidden GUI stages, stock httpx/ffuf/Arjun/SQLMap executions and bundled Nuclei
fallback. This is native execution in a Kali userland, not a separately booted
Kali kernel or an x64 desktop acceptance claim.

Evidence is in the parent `docs/evidence/` folder, including
`linux-installed-native-tools.json`, `linux-installed-ui.json`,
`linux-provider-memory.json`, `linux-local-memory.json`, `kali-native-tools.json`
and `kali-ui.json`.

Kali provisioning follows its [official archive-key guidance](https://www.kali.org/blog/new-kali-archive-signing-key/)
and [Debian-based build instructions](https://www.kali.org/docs/development/live-build-a-custom-kali-iso/).
