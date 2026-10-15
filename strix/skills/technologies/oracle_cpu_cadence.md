---
name: oracle_cpu_cadence
description: Oracle CPU cadence and correlation (from oracle_stack_security specialist
  reference library)
---

# Oracle CPU cadence and correlation

How Oracle Critical Patch Update (CPU) advisories are organized, and the exact
procedure for correlating a pinned Oracle version to advisory rows through
`70-exploit-intel`.

## 1. Cadence and structure

- Oracle CPUs publish quarterly: January, April, July, October (verify the
  current publication-day convention — historically the Tuesday closest to
  the 17th — against oracle.com/security at authoring time).
- Each CPU advisory ("Oracle Critical Patch Update Advisory <Month> <Year>")
  contains per-product risk matrices: Oracle Database, Fusion Middleware
  (WebLogic lives here), E-Business Suite, Java SE, etc.
- Each matrix row: affected product component, CVE id, CVSS base score,
  attack vector/complexity, affected versions and patch levels, and the
  package/patch that fixes it.
- Out-of-band urgent fixes arrive as "Oracle Security Alerts" instead of CPUs;
  check for both when correlating.
- Note: many fixes ship under the CPU umbrella without standalone technical
  writeups; the CPU document itself is the vendor advisory of record.

## 2. Version anchoring (what "version" means per product)

| Product | Version anchor to record | Patch-level caveat |
|---|---|---|
| Oracle Database | banner version like `19.0.0.0.0` + platform string | PSU/RU history is NOT visible remotely; a banner inside a range only proves the base release |
| WebLogic | console/error-page version like `12.2.1.4.0` + PSU/CPU patch level if disclosed | PSUs change applicability without changing the base banner; missing patch-level info caps the claim |
| E-Business Suite | `Release 12.x.y` markers, tech-stack component versions | EBS rows are per-component (Technology Components, Framework, etc.) — match the component, not the release |

Rule: an Oracle claim always cites release + (known|unknown) patch level.
Unknown patch level forces the `70` caveat rung; it never forces a "likely
vulnerable" rung on its own.

## 3. Correlation procedure with `70`

1. Take tier <= 2 fingerprints only (TNS banner, console version string, EBS
   release marker; tier table in `70`'s confidence rules).
2. Identify the product family and matrix section (DB / Fusion Middleware /
   EBS).
3. In an operator-approved network window, pull the relevant CPU advisories
   (or pre-fetched copies) covering the fingerprinted release's lifetime to
   the present; build the offline advisories file for
   `scripts/cve_correlate.py` (folder `70`) with rows keyed by product
   component + affected version range.
4. Correlate offline: version membership per row -> candidate CVE list.
5. Apply the claim ladder: correlation output is "likely vulnerable" at best
   (tier 1) or "version in range, impact unverified" (tier 2); "confirmed
   vulnerable" only via `45` in-scope reproduction.
6. Record sources + access dates; negative results are dated statements
   ("no CPU row matched as of <date>").

## 4. Affected-component reading rules

- Read the *component* column literally: "Oracle WebLogic Server" rows do not
  apply to other Fusion Middleware components on the same host, and a DB row
  naming "Core RDBMS" does not cover "Java VM" (JVM) rows — they are separate
  rows with separate scores.
- CVSS scores in the matrix are Oracle's base scores with Oracle's chosen
  metrics; the report vector is rebuilt under `70`'s CVSS 4.0 procedure from
  observed attack preconditions, not copied.
- "Attack vector: remote unauthenticated" rows on internet-facing consoles
  raise engagement priority; "requires authentication" rows chain with `30`
  findings (which account's creds exist?).
- Version ranges in the matrix are Oracle's own strings (often
  "12.2.1.4.0 and later" style); paste them verbatim into the advisories
  file — do not normalize them by hand.
- Localized advisories/translations are non-authoritative; correlate against
  the English CPU document.

