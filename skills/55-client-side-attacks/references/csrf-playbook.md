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
