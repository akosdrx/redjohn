---
name: 50-config-baseline
description: Use for passive non-intrusive baseline checks of an in-scope web target - missing security headers and CSP weaknesses, permissive or origin-reflecting CORS policy, exposed sensitive files and directories (.git, .env, backups, dumps), verbose error pages, and dangling-DNS subdomain takeover checks.
---

# Config baseline (P2)

Passive posture audit — the cheap, read-only report items that land before
the harness is even needed.

## The way

- Read-only by definition; every finding is a verbatim pair, re-fetched
  once to confirm stability.
- Header judgment is depth, not presence: CSP `script-src` quality
  (unsafe-inline/eval, wildcards) over "has CSP"; thresholds live in the
  reference tables — the skill's job is the verdict plus the pair.
- CORS is about the *shape* of reflection: arbitrary origin + credentials
  is the critical finding; subdomain-suffix and `null` reflections are
  their own verdicts. Victim-side proof belongs to `55`.
- Exposure triage: 200 + marker = confirmed (full body as evidence);
  200 without marker = reviewed before claiming; 403 = registration for
  later, never a bypass attempt here.
- `.git` exposure means read-only reconstruction for review — never push,
  never commit.
- Takeover: dangling CNAME + fingerprint response = D1 "claimable".
  Claiming the resource is an operator-gated impact proof, not a default.
- Verbose errors are triple-duty: fingerprint (`70`), probe selection
  (`40`), path disclosure (inventory).

## Handoffs

Framing and credentialed-CORS exploitation -> `55`; fingerprints -> `70`;
exposed secrets -> operator notification (never reused).

## Tools

`header_audit.py`, `exposure_probe.py`, `origin_reflect.py` (all
guarded); httpx/nuclei tags for sweep triage. Decision tables in
`references/`.
