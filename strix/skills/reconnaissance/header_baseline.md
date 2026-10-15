---
name: header_baseline
description: Header baseline decision table (from config_baseline_audit specialist
  reference library)
---

# Header baseline decision table

Per-header pass/fail thresholds used by `scripts/header_audit.py`. Verdicts:
PASS (meets threshold), WARN (weak but not broken), FAIL (missing or
misconfigured), INFO (not applicable or contextual).

## Content-Security-Policy (CWE-693)

| Check | Threshold | Verdict |
|---|---|---|
| Header absent on HTML surface | — | FAIL |
| `script-src`/`default-src` contains `unsafe-inline` | inline executes | FAIL |
| `script-src`/`default-src` contains `unsafe-eval` | eval survives | FAIL |
| `script-src`/`default-src` source `*` | any host is a script origin | FAIL |
| `script-src` source bare scheme `http:`/`https:` | attacker hosts allowed | WARN (FAIL if paired with data exfil surface) |
| `object-src` absent AND `default-src` absent | plugin content unconstrained | WARN |
| `object-src *` | — | FAIL |
| `base-uri` missing | `<base>` hijack rewrites relative URLs | WARN |
| `frame-ancestors` missing | falls back to XFO check | WARN |
| `style-src unsafe-inline` | CSS exfil/defacement | WARN |
| `report-uri`/`report-to` present | observability | INFO |

Notes: `default-src 'self'` does NOT cover `base-uri` and `frame-ancestors`
(they have no fallback) — those must be set explicitly. Nonce/hash-based
script-src without `unsafe-inline` is the PASS bar.

## Strict-Transport-Security (CWE-319)

| Condition | Verdict |
|---|---|
| `max-age >= 31536000` + `includeSubDomains` | PASS |
| `max-age >= 15552000` (180d), any flags | WARN (margin too short) |
| `max-age < 15552000` | FAIL |
| Present without `includeSubDomains` | WARN (subdomains unprotected) |
| Absent on HTTPS host | FAIL |
| Header on plain-HTTP response | INFO (browsers ignore it) |
| `preload` present | INFO (must also satisfy max-age + includeSubDomains + HSTS on all subdomains) |

## X-Frame-Options vs CSP frame-ancestors (CWE-1021)

| Condition | Verdict |
|---|---|
| `X-Frame-Options: DENY` or `SAMEORIGIN` | PASS |
| CSP `frame-ancestors 'none'`/`'self'` | PASS |
| `ALLOW-FROM <origin>` | WARN (deprecated, modern browsers ignore) |
| Any other XFO value | FAIL |
| Neither XFO nor `frame-ancestors` | FAIL (frameable -> 55 clickjacking) |

`frame-ancestors` wins over XFO where both exist; keep both in the report.

## Referrer-Policy (CWE-200)

| Value | Verdict |
|---|---|
| `no-referrer`, `same-origin`, `strict-origin` | PASS |
| `strict-origin-when-cross-origin` | PASS (browser default) |
| `origin`, `origin-when-cross-origin` | WARN |
| `unsafe-url` / no-referrer-when-downgrade | WARN/FAIL (leaks full URL cross-origin) |
| Absent | WARN (defaults to strict-origin-when-cross-origin in modern engines) |

## Permissions-Policy (CWE-693)

| Condition | Verdict |
|---|---|
| Powerful features (`camera`, `microphone`, `geolocation`, `payment`, `usb`) denied/empty | PASS |
| Any of them `*` or broad allowlist | FAIL |
| Header absent | INFO (per-feature browser defaults apply; note in report) |

## Cross-Origin-* isolation

| Header | PASS | Notes |
|---|---|---|
| `Cross-Origin-Opener-Policy` | `same-origin` | `same-origin-allow-popups` WARN; absent WARN on top-level docs |
| `Cross-Origin-Embedder-Policy` | `require-corp` or `credentialless` | absent INFO |
| `Cross-Origin-Resource-Policy` | `same-origin`/`same-site` on sensitive subresources | absent INFO |

## X-Content-Type-Options (CWE-430)

| Value | Verdict |
|---|---|
| `nosniff` | PASS |
| Anything else | FAIL |
| Absent | FAIL (MIME sniffing -> polyglot upload chains in 45) |

## Cache-Control on authenticated responses (CWE-525)

| Condition | Verdict |
|---|---|
| Response has `Set-Cookie`/`WWW-Authenticate` + `Cache-Control: no-store` | PASS |
| `private` without `no-store` | WARN (shared proxies excluded, local caches not) |
| Authenticated response with no Cache-Control | FAIL |
| Public unauthenticated response | INFO |

Also check `Expires`/`Pragma` legacy headers only when Cache-Control is absent.

## Scoring and reporting

- One line per check in the report table; FAIL items get an evidence pair.
- Aggregate: count FAIL/WARN per host for the posture summary.
- Re-fetch any FAIL item once before writing it down (transient proxies can
  strip headers); D2 = stable across two fetches.

