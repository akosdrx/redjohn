---
name: patch_diffing
description: Patch diffing for n-day rediscovery (from zeroday_patch_research specialist
  reference library)
---

# Patch diffing for n-day rediscovery

Step-by-step procedure, hunk-triage heuristics, and the version-
discriminating PoC rules. Cheapest research path: most "suspected novel"
bugs in niche components are unreported-then-silent-fixed n-days.

## 1. Procedure

1. **Pin the target version** (tier <= 2 fingerprint from `10`). Tier 3/4:
   stop — diffing against a guessed version wastes the timebox.
2. **Locate the upstream repo** and its release tags (upstream first-party
   repo; note forks and distro-maintained trees separately — a distro patch
   set is its own diff stream). Fetch tags in the operator-approved network
   window: `git clone --branch <pinned-tag> --depth 50 <upstream-url>` or
   fetch just the two tags; save everything to evidence and go offline.
3. **Pick the comparison pair**: pinned version -> NEXT PATCH release
   (`v2.3.0` -> `v2.3.1`). Skip feature releases (`v2.4.0`) for the first
   pass — security fixes overwhelmingly ride patch bumps. If the patch
   release has no candidates, widen one step and re-triage.
4. **Produce the artifacts**:
   - `git diff v2.3.0 v2.3.1 > evidence/p8-diff-<component>-001.patch`
   - `git log v2.3.0..v2.3.1 --oneline > .../commits.txt`
   - changelog section for the release (many projects mark security fixes
     there before any advisory exists).
5. **Machine triage**: `python3 scripts/secdiff.py --diff fix.patch`
   (or `--dir evidence/patches/`). Ranked hunks + CWE hypotheses come out;
   candidates are leads, not findings.
6. **Commit-message correlation**: match candidate hunks to commits;
   "security", "CVE", "hardening", "validation", contributor = maintainer
   of the touched file all raise confidence.
7. **Map to a CWE hypothesis** (secdiff output + `70`'s cwe-mapping.md) and
   proceed to the discriminating PoC (section 3).

Illustration (real, well-known; verify against the upstream repo and NVD at
authoring time): Apache Log4j `rel/2.14.1` -> `rel/2.15.0` contains the
JNDI-lookup restriction fixing CVE-2021-44228 — a textbook
security-dense patch bump.

## 2. Hunk-triage heuristics (what secdiff implements)

| Signal | Weight | Notes / false positives |
|---|---|---|
| CVE id in hunks/test names (`CVE-YYYY-NNNNN`) | strongest | near-definitive when present |
| Strong keywords in added/removed lines: `inject`, `overflow`, `bypass`, `sanitiz*`, `escap*`, `auth` (NOT "author"), `permission` | high | `auth` must exclude `author*` — classic FP |
| Weak keywords: `valid*`, `fix*`, `patch*` | low | ubiquitous in changelogs; tie-breaker only |
| Sink-adjacent changes: touched or neighboring lines containing `eval(`, `exec(`, `system(`, `popen`, `subprocess`, `shell=True`, `innerHTML`, `document.write`, `deserialize`, `pickle.loads`, `yaml.load`, `memcpy`, `strcpy`, `sprintf`, `query` | high | the fix rewiring a sink's input path |
| Regression-test naming: test files whose name/content reference the CVE, a crash input, "regress", "security" | confirming | test-only churn WITHOUT those markers is usually cosmetic |
| Focused hunks (< ~40 lines, single concern) | raises rank | giant refactors hide fixes — deprioritize and re-diff per-commit |
| Huge refactor / docs / version-bump / CI-only | cosmetic | version bumps are how you FIND the pair, not candidates |

Triage output classes: `security-fix-candidate` -> `review` ->
`likely-cosmetic`; only the first two earn PoC effort, in rank order,
inside the timebox.

## 3. Version-discriminating PoC rules

The discriminator is what separates research from noise: a probe whose
output DIFFERS between the two versions of the component.

1. **Build both versions locally** in the disposable container lab
   (`v2.3.0` vulnerable-side, `v2.3.1` fixed-side).
2. **Write the probe against the hunk's changed path**, minimal input,
   benign observable (error text change, rejected/accepted field, reflected
   value, one canary callback). No destructive payloads even locally.
3. **Prove the pair**: probe on pre-patch -> signal; same probe on
   post-patch -> no signal (or the fixed response). Save both outputs —
   this pair is the finding's spine.
4. **Then, and only then, run the identical probe in-scope** — one
   request, RoE discipline, evidence pair captured. In-scope signal ==
   the target runs the vulnerable code path (D1).
5. A probe that fires on BOTH versions discriminates nothing — it proves
   the feature exists. Do not report it as the vulnerability.
6. **NEVER assume exploitability from the fix's existence.** Fixes land
   for crashes, defense-in-depth, theoretical issues, and dead code.
   Exploitability/impact is claimed only from in-scope verification within
   the engagement allowance (`45` doctrine).
7. Keep the probe in the run's evidence: `evidence/p8-poc-<component>-001/`
   with `pre-patch.txt`, `post-patch.txt`, and the in-scope pair.

## 4. Patch-Gap & N-Day Regression Analysis

Upstream security fixes frequently patch only the primary reported entry point
(e.g., filtering a single query parameter in a controller) while leaving the
underlying sink accessible via alternate routes, alternate HTTP verbs (`PUT`/`PATCH`),
alternate content types (`application/xml`, `multipart/form-data`), or legacy
API versions.

1. **Sink-Adjacent Diffing**: Use `secdiff.py` to inspect patch hunks and isolate
   the exact sanitization or sink change.
2. **Sibling Route Traversal**: Cross-reference whether sibling controllers or
   unlinked helper functions call the same unpatched sink logic.
3. **Verb & Serialization Polymorphism**: Test whether the patch checks only `POST`
   requests while the router dispatches `PUT` or deserialized JSON/XML to the
   same backend service.
4. **Regression Probing**: Re-run the discriminating probe against adjacent entry
   points to detect patch gaps without deploying weaponized payloads.
   Detailed analysis: `references/sast-dast-blindspots.md`.

