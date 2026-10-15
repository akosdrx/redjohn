# pentestskills

Operator-authored skill library for RedJohn web/API penetration-test runs, plus the
sanctioned infrastructure stacks (Oracle, Proxmox VE). Opened by `00-master`, the
main methodology prompt; the 17 numbered folders are loaded on demand per phase.

## Layout

| Folder | Function | OWASP Top 10:2021 |
|---|---|---|
| `00-master-pentest-methodology/` | Main methodology prompt: phase machine, dispatch map, evidence gates, stop conditions | all |
| `10-recon-endpoint-mapping/` | Crawl/DOM mapping, directory fuzzing, parameter mining, technology fingerprinting, API schema discovery | — |
| `20-traffic-manipulation/` | Raw request replay, dynamic response diffing, OOB callback listener discipline | — |
| `30-auth-access-control/` | IDOR/BOLA token-swap matrix, JWT audit, session management, OAuth/OIDC, rate limiting & brute force | A01, A07 |
| `35-cryptographic-failures/` | TLS/cipher audit, weak hashing, padding oracles, secrets in transit/at rest | A02 |
| `40-injection-engine/` | SQL/NoSQL/LDAP/OS command injection, context-aware XSS, SSTI, XXE, SSRF | A03, A10 |
| `45-rce-exploitation/` | RCE chains: deserialization gadgets, file upload to RCE, LFI to RCE, safe impact proof | A08 (exec) |
| `50-config-baseline/` | Security headers/CSP, CORS, sensitive file exposure, verbose errors, subdomain takeover | A05 |
| `55-client-side-attacks/` | CSRF, clickjacking, open redirects, postMessage/origin abuse, XSS chaining | — |
| `58-logic-concurrency/` | Business logic abuse, race conditions, mass assignment | A04 |
| `60-api-graphql-websockets/` | GraphQL introspection/field authz/batching, REST gaps, WebSocket testing | API Top 10 |
| `65-supply-chain-integrity/` | CI/CD pipeline abuse, unsigned updates, dependency integrity | A08 (integrity) |
| `70-exploit-intel/` | Version pinning, CVE to exploit correlation (searchsploit/nuclei) and their gaps, CWE mapping, CVSS 4.0 | A06 |
| `75-zeroday-research/` | Novel-vuln path: patch diffing, targeted fuzzing/replay, novelty assessment, undisclosed-vuln handling | A06 gap |
| `80-oracle-stack/` | Oracle DB listener/SID/default accounts, WebLogic console+T3, EBS surface, CPU advisory cadence | stack-specific |
| `82-proxmox-ve/` | pveproxy :8006, PVE API/tokens/realms, cluster surface, escape impact verification | stack-specific |
| `85-logging-monitoring/` | Detection-coverage testing, log injection, sensitive data in logs, missing audit events | A09 |
| `90-evidence-reporting/` | Reproducible PoCs, remediation library, CWE+CVSS classification, dedupe, report assembly | — |

Out of scope by design: Active Directory/Kerberos attack paths, general cloud
(AWS/Azure/GCP) misconfiguration, mobile, binary exploitation. Oracle and Proxmox
are the sanctioned infrastructure exceptions.

## Loading into RedJohn Desktop

The engine discovers this catalog locally on startup, registers it in the Skills
browser, and bundles it into the installed engine wheel. No import or OpenViking
connection is needed to read these skills. `REDJOHN_SKILLS_ROOT` optionally selects
an operator-maintained catalog for development.

Every agent receives the master methodology and the selected `scan-low`,
`scan-standard`, `scan-high` or `scan-deep` profile in its system context on every
model turn. Child agents inherit the same profile and session target. Surface
skills are loaded on demand through `builtin:search_skills`, `builtin:load_skill`
and `builtin:read_skill_file`; numeric prefixes such as `10` resolve uniquely.

The desktop runtime provides scoped read-only local-project and GitHub source
inspection, scoped HTTP, and per-session official MCP integrations. The CLIs named
by the surface skills are optional, and request-sending helper scripts cannot run
through the offline command executor. A skill never grants execution permission
or expands the session's target scope.

## Verification

Offline, no credentials, no network:

```
python3 tools/verify_catalog.py
```

Checks: 22 folders discovered (18 methodology/surface skills and 4 scan profiles), `name` matches folder stem, descriptions present
and unique, every script compiles and passes `--self-test` (scope-guard blocks
out-of-scope hosts, allows explicitly scoped loopback).

## Status

Complete and verified against the approved architecture plan (rev 2),
then slimmed per the "show the way" authoring standard: every SKILL.md is
a 25-45 line orientation (mission, heuristics, handoffs, tool pointers)
with frontmatter untouched; checklists and lookup tables live in
`references/`, executable helpers in `scripts/`. 22 folders, 32
stdlib-only scripts. `tools/verify_catalog.py` passes: folder set,
name==stem frontmatter, unique dispatch descriptions, line caps (60
numbered / 140 master), compile and in-process `--self-test` for every
script. Offline engine tests verify automatic loading, inherited profiles,
per-turn instructions and scoped source reads. Authenticated model-driven
engagement dispatch and full live scan coverage remain unverified; no external
target assessment is part of catalog verification. Authoring rules live in `CONVENTIONS.md`;
`00-master-pentest-methodology/references/` holds the coverage matrix
proving OWASP Top 10:2021 coverage cell-by-cell.
