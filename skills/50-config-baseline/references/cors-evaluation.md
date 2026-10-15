# CORS evaluation matrix

Used with `scripts/origin_reflect.py`. Probes are plain GETs with a crafted
`Origin` header; the verdict comes from `Access-Control-Allow-Origin` (ACAO),
`Access-Control-Allow-Credentials` (ACAC) and `Vary`.

## Probe matrix

| # | Probe `Origin` | ACAO observed | ACAC | Verdict | Impact |
|---|---|---|---|---|---|
| 1 | `https://evil.example` | exact echo of probe | `true` | REFLECTED-CREDENTIALED (FAIL, CWE-942) | Any origin reads authenticated responses with the victim's cookies; CRITICAL on JSON/API surfaces |
| 2 | `https://evil.example` | exact echo | absent | REFLECTED (FAIL) | Unauthenticated cross-origin read of public-but-CORS-gated data |
| 3 | `https://evil.example` | `*` | `true` | WILDCARD+CREDS (FAIL as policy bug) | Browsers refuse credentialed wildcard; signals copy-paste misconfig, report LOW/MED |
| 4 | `https://evil.example` | `*` | absent | WILDCARD (INFO) | Public data readable cross-origin; only a finding with sensitive bodies |
| 5 | `https://<target-host>.attacker.example` | echo | any | SUFFIX/PREFIX-TRUST (FAIL) | Naive `startsWith`/`endsWith` origin check bypassed by attacker subdomains |
| 6 | `Origin: null` | `null` echoed | `true` | NULL-ALLOWED (FAIL) | Sandboxed iframes and `data:` pages send `Origin: null`; chain with any 55 iframe surface |
| 7 | self-origin control | echo | any | CONTROL (PASS expected) | Sanity check: the endpoint does CORS at all |

## Preflight handling (OPTIONS)

Send `OPTIONS` with `Access-Control-Request-Method: PUT` and
`Access-Control-Request-Headers: x-custom-probe`.

| Observation | Verdict |
|---|---|
| Any requested method echoed in `Access-Control-Allow-Methods` | methods allowlist missing |
| Any requested header echoed in `Access-Control-Allow-Headers` | custom-header gate bypassable |
| `Access-Control-Max-Age` very large | caches the permissive preflight |
| Preflight refused for exotic methods only | note which methods pass |

## Vary and caching

- ACAO reflects Origin but no `Vary: Origin`: shared caches/CDNs may serve
  one origin's ACAO to another — poisoning candidate; note the cache headers
  seen (Age, X-Cache) as evidence.
- `Vary: Origin` present with reflection: caching correct, finding is the
  reflection itself.

## Impact rules (binding)

1. Credentialed reflection (row 1): impact = read any authenticated endpoint
   the victim can read. Demonstrate only against your own engagement account
   acting as victim (your second browser context), never real users.
2. Unauthenticated reflection/wildcard (rows 2/4): impact only if the bodies
   are sensitive (PII, internal enums, tokens). Otherwise record as hardening
   item, not a finding.
3. Null-allowed (row 6): needs an exploit page that produces `Origin: null`
   (sandboxed iframe) plus credentialed fetch — chain belongs to
   `55-client-side-attacks`.
4. Never claim "account takeover" from CORS alone; claim exactly what the
   readable endpoints expose.

## Evidence

- One request/response pair per probe row executed, named
  `evidence/p2-cors-<host>-<origin-slug>.{req,resp}.txt`.
- D2: repeat the reflected probe after re-authenticating the victim context;
  both runs in the evidence set.
