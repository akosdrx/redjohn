---
name: 25-waf-edge-posture
description: Use when assessing WAF, CDN and reverse proxy edge posture - discovering direct-to-origin exposure, testing edge-vs-origin path normalization discrepancies, auditing X-Forwarded-* header trust, or diffing pre/post-test response baselines to detect mid-engagement SOC virtual patching.
---

# WAF, CDN & edge posture auditing (P2/P3)

Non-destructive assessment of reverse proxy, CDN, and WAF edge layers.
Exposes direct origin exposure, normalization parsing gaps, header trust
flaws, and detects live SOC virtual patching.

## The way

- Audit configuration, never attack third-party anti-bot infrastructure:
  focus on server-side architecture, origin exposure, and proxy header trust.
- Direct-to-origin verification: confirm candidate origin IPs via TLS cert
  Subject Alternative Name (SAN) matching, body SHA256 match, and origin
  response headers before asserting an edge bypass.
- Benign path normalization matrices: probe harmless, read-only variant
  paths (semicolons, URL encoding, dot-segments: `/public;x=1`, `/%2e/public`)
  on existing public routes to find proxy vs backend parsing discrepancies.
- Header trust auditing: verify whether client-supplied `X-Forwarded-For`,
  `X-Real-IP`, or `X-Forwarded-Host` are stripped by the edge or blindly
  trusted upstream for IP allowlists and rate-limiting.
- Pre/post-test baseline delta discipline: capture pre-test fingerprint
  `(status, size, time, headers, waf_cookies)`. On lost reproduction of a
  finding, diff post-test fingerprint to distinguish SOC virtual patches
  from durable code fixes.
- Classify edge blocks as edge behavior: CDN 403/405/429 block pages with
  CDN branding indicate the request never reached origin; log as edge
  posture, not application findings.

## Handoffs

Recon inventory and origin leads from `10`/`05` -> `25`; direct origin and
normalization findings -> `20` (traffic manipulation), `30` (auth bypass),
`40` (injection), and `95` (finding verifier).

## Tools

`waf_edge_probe.py` (guarded prober, origin diff, normalization probe,
baseline diffing, and offline `--self-test`). Normalization matrices,
origin discovery vectors, and SOC IR posture in `references/`.
