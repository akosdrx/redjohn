---
name: supply_chain_integrity
description: Use when integrity of build and update paths is in question - CI/CD workflow
  injection via pull_request_target with PR-controlled scripts, unsigned update channels,
  squattable or unverified dependency names, and lockfile drift between environments.
---

# Supply chain integrity (P7)

How code, builds and updates arrive — and whether integrity holds. Mostly
offline analysis of operator-provided source, CI config and lockfiles;
anything live goes through `20`/`50` under the guard.

## The way

- The classic injection triad — `pull_request_target` + PR-head checkout
  + PR-controlled execution — runs fork code with base-repo secrets.
  Regex triage finds candidates; the job context confirms (`if:` guards
  and reusable-workflow indirection need eyes).
- `${{ github.event.* }}` interpolated into `run:` is script injection
  with a branch-name payload; the remediation marker is env-indirection
  plus quoting.
- Secret *names* in findings, never values.
- A checksum fetched from the same channel is not integrity; a
  signed-but-older artifact the client accepts is a rollback channel.
- Drift is comparative: the same dependency resolving differently across
  environments (prod vs CI vs image) — compare lockfiles pairwise.
- Confusion and typosquat rows are heuristic leads until a registry or
  config proof attaches.

## Handoffs

Pinned versions -> `70` for CVE correlation; secret exposure ->
`30`/`90` (names only); live update-endpoint probing -> `50`/`20`.

## Tools

`workflow_scan.py`, `lockfile_drift.py` (both offline by design — that
boundary is part of the verification story). Pattern catalog and
checklists in `references/`.

---

## Reference Module: `cicd-injection-patterns`

# CI/CD injection patterns: catalog, detection, severity

Doc-example workflows only (`example-org/example-repo`); adapt to the
engagement's real workflows. Detection regexes mirror
`scripts/workflow_scan.py` — the script triages, the operator confirms
(regexes cannot see `if:` guards, reusable-workflow indirection, or
composite actions in other repos).

## Pattern 1: pull_request_target + PR-head checkout + PR-controlled
execution (the classic triad)

Severity: CRITICAL when the triad is in one job; the trigger alone is
MEDIUM context. CWE-78 class (script injection) executed in CI context.

Doc-example vulnerable workflow (`.github/workflows/ci.yml`):

```yaml
name: CI
on:
  pull_request_target:
    branches: [main]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: example-org/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Build and test the PR
        run: make test
      - name: Report
        run: echo "Testing ${{ github.event.pull_request.title }}"
        env:
          REPORT_TOKEN: ${{ secrets.REPORT_TOKEN }}
```

Why it is vulnerable:

1. `pull_request_target` runs the workflow definition from the BASE branch
   with base-repo secrets and write access.
2. `ref: ${{ github.event.pull_request.head.sha }}` checks out the FORK's
   commit — from here, the workspace content is attacker-controlled.
3. `make test` executes the PR's own Makefile (same for `npm test` /
   `npm ci && npm run build` / `go test ./...` — any tool that reads
   workspace files), so the attacker's build file runs with
   `secrets.REPORT_TOKEN` in the environment.

Detection regexes (what workflow_scan.py looks for):

| Signal | Regex |
|---|---|
| Fork-context trigger | `\bpull_request_target\b` |
| PR-head checkout | `github\.event\.pull_request\.head\.(sha\|ref)` or `ref:\s*refs/pull/` |
| PR-controlled execution | `run:` block invoking `make`, `npm ci`, `npm (run\|test)`, `go (test\|build)`, `pytest`, `bash scripts/`, `./gradlew` in the same job as the PR-head checkout |

Secure doc-example shape (what good looks like):

```yaml
name: CI (labels only for forks)
on:
  pull_request_target:
    branches: [main]
permissions:
  contents: read
jobs:
  label:
    if: github.repository == 'example-org/example-repo'
    runs-on: ubuntu-latest
    steps:
      - uses: example-org/labeler@<full-commit-sha>
        with:
          repo-token: ${{ secrets.GITHUB_TOKEN }}
```

`pull_request` (without `_target`) checks out the PR merge ref WITHOUT
secrets — running PR code belongs there, never under `_target`.

## Pattern 2: script injection via `run:` interpolation

Severity: HIGH when a user-controlled `github.event.*` field (or
`github.head_ref`) is interpolated directly into a `run:` block; MEDIUM for
non-user-controlled context fields (still a hygiene issue).

Vulnerable doc examples:

```yaml
      - run: echo "PR title: ${{ github.event.pull_request.title }}"
      - run: echo "branch: ${{ github.head_ref }}"
      - run: ./ci/comment.sh "${{ github.event.issue.title }}"
      - run: echo "commit: ${{ github.event.head_commit.message }}"
```

Payloads (string reaches the shell verbatim): `` `id` ``, `$(id)`,
`$(curl ...)` inside the PR title, branch name, issue title or commit
message.

User-controlled field prefixes (the script's list):

- `github.event.pull_request.title` / `.body` / `.head.ref` / `.head.label`
  / `.head.repo.*` (attacker's fork metadata)
- `github.event.issue.title` / `.body` (`issues.*` variants)
- `github.event.comment.body`, `github.event.review.body`,
  `github.event.review_comment.body`
- `github.event.discussion.title` / `.body`
- `github.event.commits[*].message`, `github.event.head_commit.message`
- `github.head_ref` (context-level branch name — separate regex)

Remediation marker (env indirection + quoting):

```yaml
      - env:
          PR_TITLE: ${{ github.event.pull_request.title }}
        run: echo "PR title: $PR_TITLE"
```

Env indirection passes the value as an environment variable instead of
template-substituting into the shell text — its presence next to the
`secrets`/event reference is what downgrades the finding.

Detection regex: `\$\{\{\s*github\.(event\.[A-Za-z0-9_.\[\]"]*|head_ref)\s*\}\}`
found inside a `run:` block (the script tracks block-scalar continuation
lines by indentation).

## Pattern 3: secrets in fork-reachable jobs

Severity: HIGH. Any `secrets.<NAME>` referenced in a job whose workflow
triggers include `pull_request_target` (or that runs on
`github.event.pull_request` payloads of a `_target` workflow via
`workflow_run` chains — check those too) is exposed to fork authors once
patterns 1/2 land.

Detection regex: `secrets\.[A-Za-z_][A-Za-z0-9_]*` in a job block of a
workflow whose `on:` contains `pull_request_target`.

Evidence rule: record the secret NAME and the job context only. Never
attempt to exfiltrate the value; impact is argued from the code path
(D1/D2), and any value handling needs explicit written authorization.

## Pattern 4: artifact poisoning (concept check)

Severity: observation -> finding depending on the consumption chain. Jobs
that BUILD from PR code under `pull_request_target` (or `pull_request` with
write permissions) and `upload-artifact`; a later trusted job
(`needs:`-chained or scheduled deploy) downloads that artifact and
publishes/executes it. The regex scan flags `upload-artifact` /
`download-artifact` adjacency across trust boundaries; confirm by reading
the `needs:` graph manually.

## Pattern 5: floating action references

Severity: LOW observation. `uses: example-org/action@v4` or `@main` —
mutable tags; a tag can be repointed. Full 40-char SHA pins
(`uses: example-org/action@<full-sha>`) are the control. Record per-action
rows; mass-unpinned actions raise the supply-chain posture note in the
report.

Detection regex: `uses:\s*[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@(?![0-9a-f]{40})(\S+)`

## Other CI families (generic job-template review)

The same three questions, family-agnostic:

1. Does an untrusted string (MR title/branch, issue text, fork env var)
   reach a shell script block by template interpolation?
2. Which secrets are scoped to which job, and are any reachable from
   untrusted-trigger jobs? (GitLab: protected refs; Jenkins: credentials
   binding + branch restrictions; Azure Pipelines: `resources.repositories`
   trust + `variables` mapping.)
3. Does a job execute files fetched from the untrusted ref?

## Severity reasoning summary

| Combination | Severity |
|---|---|
| Triad complete (target trigger + head checkout + PR-run) | CRITICAL |
| User-controlled interpolation into `run:` | HIGH |
| Secrets referenced in fork-reachable job | HIGH (with 1/2) / MEDIUM (alone, context) |
| `pull_request_target` present (no triad) | MEDIUM (review trigger) |
| Artifact crossing trust boundary | MEDIUM (chain-dependent) |
| Floating action tag | LOW observation |


---

## Reference Module: `dependency-integrity`

# Dependency integrity: lockfile fields, confusion, typosquats, drift

Offline reference for `scripts/lockfile_drift.py` output and the manual
follow-ups. Documentation package names only; substitute engagement data.

## 1. Lockfile field reference

### requirements.txt (pip)

```
requests==2.31.0              # pinned (==) - good
urllib3>=1.26,<3              # floating (>=,< only) - drift risk
flask                         # unpinned - resolves to latest at install
django==4.2.7                 # pinned
django==4.1                   # duplicate of the above after normalization
-r base.txt                   # include - scan the included file too
-e git+https://example.com/example-org/lib#egg=lib   # URL dep - pin by commit
requests==2.31.0 --hash=sha256:abc...   # hash-pinned - best
```

Classification: `==`/`===` present = pinned; any of `>=` `<=` `>` `<` `~=`
without `==` = floating; empty specifier = unpinned; URL/git specifiers =
observation (pin by commit hash for reproducibility). Name normalization
for duplicate detection: lowercase, `-` and `_` and `.` equivalent (PEP 503).

### package-lock.json (npm)

| Field | Meaning | Integrity relevance |
|---|---|---|
| `lockfileVersion` | 1 (legacy deps-only), 2 (packages+deps), 3 (packages) | v1 = legacy observation |
| `packages[""]` | root manifest snapshot | `dependencies`/`devDependencies` here = manifest-vs-lock cross-check |
| `packages[path].version` | exact resolved version | the pin itself |
| `packages[path].resolved` | registry URL | which registry served it (confusion check) |
| `packages[path].integrity` | `sha512-...` subresource hash | MISSING = URL-trust only -> flag |
| `packages[path].link` | symlink entry | link entries legitimately lack integrity |
| `dependencies` (v1/v2) | legacy tree | same version/integrity checks per node |

Duplicate = same package name resolving to more than one version across the
tree (common after imperfect dedupe); record each path.

### pyproject.toml (simple parse)

- `[project] dependencies = ["name specifier", ...]` — PEP 508 entries,
  classified like requirements.txt (`==` pinned; `>=`/`~=` floating; bare
  name unpinned).
- `[tool.poetry.dependencies]` — caret `^1.2` and tilde `~1.2` are floating
  by design; exact `1.2.3` pins; table values `{ version = "^1.2" }` read
  the inner version. The `python` key is the runtime constraint, not a
  dependency — skip it.
- `[project.optional-dependencies]` extras — same rules; also the duplicate
  source: a name in both `dependencies` and an extra (or two extras) with
  different specifiers is drift.

## 2. Lockfile drift procedure (across environments)

1. Collect the same-format lockfile from EACH environment: prod
   (`requirements.txt`), CI (`.github/workflows` install step's file or
   `ci-requirements.txt`), container image (`container/requirements.txt`),
   dev (`requirements-dev.txt`).
2. Run `python3 scripts/lockfile_drift.py --lock <file>` per file; save
   each output.
3. Diff the pinned version SETS per normalized name across files:
   `requests==2.31.0` (prod) vs `requests==2.32.3` (CI) = drift row.
4. Classify each drift row: intended (backport branch) vs unnoticed
   (no changelog/PR reference) — unnoticed drift between the environment
   that TESTS and the environment that RUNS is the finding.
5. Manifest-vs-lock (package-lock v2/v3): root `packages[""].dependencies`
  specifiers vs the resolved `version` pins — a manifest saying `^1.0.0`
  with lock at `1.0.1` is normal; a lock MISSING a manifest entry is a
  broken lock (reinstall would float).

## 3. Dependency confusion checklist

Preconditions to check in the repo config (offline):

- pip: is there an internal index (`index-url` in `pip.conf`/
  `requirements.txt` header/`PIP_INDEX_URL` in CI env)? Does
  `extra-index-url` ALSO list a public index (the classic confusion
  setup — public can shadow internal names)?
- npm: internal `@scope` registry mapping in `.npmrc`; is the scope
  published publicly? Does `publishConfig` point at the internal registry?
- Are internal package names guessable (`example-core`,
  `example-org-utils`) and NOT registered/reservable on the public
  registry?

Finding shape (offline claim): "internal name `example-core` resolves from
the public index because `extra-index-url` includes it and the internal
index is not authoritative for that name" — cite the config file:line. The
runtime proof (registering a canary name) needs written authorization and
never happens by default.

## 4. Typosquat heuristics (leads, not findings)

- Edit-distance-1 against the popular package in the SAME ecosystem:
  `request`/`requests`, `python-dateutil`/`python_dateutil`,
  `colorama`/`coloroma`.
- Suffix/prefix swaps: `-js`, `-cli`, `-utils`, `2`/`4` appended to popular
  names.
- `-`/`_` variants of popular names (both resolve identically in some
  registries — normalization matters).
- Recently-registered maintainers of a long-lived dependency name
  (needs registry data — hand to `70` with the package+version).

Every heuristic row is recorded as: name, the popular name it shadows, the
distance basis, the environment(s) that install it. Claim "malicious"
never; claim "unverified name, review" at most.

## 5. Integrity hashes and provenance

- package-lock: every non-link entry needs `integrity` (sha512). Entries
  resolved from git URLs have `resolved` git refs instead — check they pin
  a commit, not a branch.
- pip: hash-pinning (`--hash` on every line, `require-hashes = true` in
  pip.conf) is the equivalent control; its absence is an observation.
- Provenance / sigstore-style attestation: presence per package source is
  an observation row (present/absent/unknown-registry); absence is posture
  information for the report, not a vulnerability.

## 6. Registration and handoffs

```text
dependency | name=example-core | env=prod,ci | pin=2.31.0 vs 2.32.3
  | class=drift | source=lockfile_drift.py | evidence=<engagement>/p7-deps-001.txt
```

- Version->CVE correlation -> `70-exploit-intel` (with version proof and
  advisory note).
- Confusion/typosquat leads needing registry lookups -> `70`; runtime
  proofs (if authorized) -> `20` under scope guard.


---

## Reference Module: `update-channel-checklist`

# Update channel integrity: signature, pinning, downgrade checklist

For applications that ship updates (desktop apps, agents, plugins, CLI
self-update). Everything below is answered from PROVIDED artifacts (update
URLs in source/config, captured manifests, binaries, public keys); live
probing goes to `20`/`50` under the scope guard.

## 1. Transport checklist

| Check | Question | Evidence from |
|---|---|---|
| T1 | All update/version-check URLs https-only? | source/config grep: `http://` near `update`, `feed`, `download`, `version` |
| T2 | Certificate validation ON (no `--insecure`, `verify=False`, `NODE_TLS_REJECT_UNAUTHORIZED=0`) in the updater path? | updater source/config |
| T3 | Redirects followed to arbitrary hosts? (signed-http -> unsigned-CDN style chains) | updater logic / captured redirect chain |
| T4 | Update metadata and the artifacts themselves on the same trust level? | manifest + artifact URLs |

TLS-version/cipher depth belongs to `35-cryptographic-failures`.

## 2. Signature verification checklist

| Check | Question | Insecure signal |
|---|---|---|
| S1 | Does the updater verify ANY signature on the update? | "download -> checksum -> run" with no key check |
| S2 | Manifest AND binaries signed, or manifest only? | unsigned binary referenced by signed manifest (binary must carry its own signature) |
| S3 | Which scheme: detached GPG/minisign, OS code signing, sigstore? | scheme absent = S1 finding |
| S4 | Is the verification key pinned in the client (hardcoded/embedded public key)? | key fetched from the same channel = same-origin compromise passes |
| S5 | Is failure fatal (refuse to install) or log-only? | log-only downgrade of S1 |
| S6 | Checksums: fetched from where? | checksums from the same origin as the binary are NOT integrity |

Client-side grep leads: `minisign`, `gpg --verify`, `codesign --verify`,
`WinVerifyTrust`, `sigstore/cosign`, `checksum`, `sha256(`, `md5(`
(MD5 as update checksum = weak, `35`).

## 3. Downgrade protection checklist

| Check | Question | Insecure signal |
|---|---|---|
| D1 | Client rejects versions OLDER than installed? | any validly-signed older artifact installs |
| D2 | Version monotonicity enforced at signature layer (anti-rollback counters/VDF) or only client logic? | client-only check = bypassable logic |
| D3 | Can the version-check endpoint force "no update available" and freeze the client on a known-vulnerable version? | silent no-update response with no freshness proof |
| D4 | Rollback windows: is the previous-version binary still accepted side-by-side after update? | accepted old binary with old vulnerabilities = rollback path |

## 4. Pinning checklist (pinned vs floating)

| Check | Question |
|---|---|
| P1 | Update feed URL pinned (exact host) or wildcard/DNS-discoverable? |
| P2 | Channel/stable-vs-beta selection enforced by signature or by request parameter? |
| P3 | Plugin/extension IDs validated against a signed allowlist before load? |
| P4 | Docker/base images in the build pinned by digest, or by mutable tag? |

## 5. Findings mapping

| Failure class | CWE (canonical) | Severity reasoning |
|---|---|---|
| No signature verification on update (S1+S4) | CWE-494 (Download of Code Without Integrity Check) | HIGH; remote code delivery depends on network position |
| Same-origin checksum only (S6) | CWE-493 (Critical Private Resource Sourced from Untrusted Repository variant) / CWE-345 | MEDIUM-HIGH |
| Downgrade accepted (D1/D2) | CWE-862-class logic gap (missing anti-rollback) | MEDIUM |
| http:// update URL (T1) | CWE-319 (Cleartext Transmission of Sensitive Information) | HIGH for code channels |
| Log-only verification failure (S5) | CWE-755 | MEDIUM |

Claims stay at the observed layer: "the updater executes downloaded
binaries without signature verification" is the finding; "attacker can RCE
every client" is impact language that needs the D2/D3 evidence discipline
before it enters a report.

## 6. Evidence expectations

- The updater's verification code path quoted (file:line) OR the captured
  unsigned exchange (request+response pair via `20` when live probing is
  authorized and in scope).
- The pinned-key material location (not the key value if secret — public
  keys may be quoted).
- One clean diagram row per check (T1-T4, S1-S6, D1-D4, P1-P4) in the run
  notes even when passing — the coverage statement for `90` comes from it.

