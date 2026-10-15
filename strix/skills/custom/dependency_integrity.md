---
name: dependency_integrity
description: 'Dependency integrity: lockfile fields, confusion, typosquats, drift
  (from supply_chain_integrity specialist reference library)'
---

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

