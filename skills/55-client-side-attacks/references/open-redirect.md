# Open redirect ladder and chaining map

Companion to `scripts/redirect_probe.py` (which executes the ladder).
CWE-601.

## Bypass ladder

Ordered weakest-to-strongest validation defeat. `TARGET_HOST` is the real
target host; payloads use documentation domains.

| # | Payload (for the param) | Defeats validation that... |
|---|---|---|
| 1 | `https://evil.example/landed` | accepts any absolute URL |
| 2 | `//evil.example/landed` | checks `startsWith("/")` only |
| 3 | `https:evil.example/landed` | parses the value as relative (scheme-colon) |
| 4 | `\/evil.example/landed` | treats backslash as path char |
| 5 | `/\evil.example/landed` | single-backslash variant of 4 |
| 6 | `%2F%2Fevil.example%2Flanded` | URL-decodes once before routing |
| 7 | `%2F%5Cevil.example%2Flanded` | decodes + backslash handling |
| 8 | `%252F%252Fevil.example%252Flanded` | double-decodes |
| 9 | `https://TARGET_HOST@evil.example/landed` | reads host before `@` |
| 10 | `https://evil.example@TARGET_HOST/landed` | some parsers pick the wrong side of `@` |
| 11 | `https://TARGET_HOST.evil.example/landed` | "contains target host" substring check |
| 12 | `https://evil.example/#TARGET_HOST` | "contains target host" check on the full string |

Working payload classes recorded verbatim as part of the finding (payload,
Location observed, status).

## Detection rules

- Send GET with the payload substituted; do NOT auto-follow redirects.
- Normalize the `Location` header: replace `\` with `/` before parsing
  (browsers treat backslashes as slashes in special schemes), then resolve
  against the request URL.
- Verdict OPEN when the resolved Location host differs from the target host
  and the payload controlled it.
- Same-host Location with payload in the path only = internal redirect
  (not a finding by itself; may be a hop — see chaining).

## Chaining map

| Chain | Steps | Handoff |
|---|---|---|
| OAuth `redirect_uri` interception | target's OAuth flow accepts an open-redirect URL as `redirect_uri` (or its own redirect param is vulnerable); authorization `code`/token lands on attacker page | `30-auth-access-control` owns the OAuth chain; supply the redirect evidence |
| SSO/middleware allowlist bypass | middleware trusts "redirect only to *.target.example.com"; open redirect on a trusted host bounces to `evil.example`; chain the 302s exactly | report as auth-bypass step with the full hop chain; coordinate with 30 |
| Referer/CSRF validation abuse | redirect page carries the real Referer/Origin then lands on attacker page; used to launder headers | report with the CSRF finding it enables |
| Phishing/trust only | bare redirect, no chain | LOW severity; still report (hardening) |

## Param candidate list

`url next redirect redirect_uri redirectUrl return returnUrl returnTo
continue dest destination go target to out view from callback successUrl
cancel_url jump goto location r u`

Also mine the JS bundles for `location.href =` / `location.replace(` fed
by query params (DOM open redirect — same ladder, executed in the victim
browser via `agent_browser`).

## Evidence

- Request with payload + verbatim response (status + Location) per working
  payload; `evidence/p6-redirect-<host>-<n>.{req,resp}.txt`.
- Chain evidence: every hop's request/response pair in order.
- D2: replay once; both runs kept.
