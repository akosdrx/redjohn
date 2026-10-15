---
name: config_baseline_audit
description: Use for passive non-intrusive baseline checks of an in-scope web target
  - missing security headers and CSP weaknesses, permissive or origin-reflecting CORS
  policy, exposed sensitive files and directories (.git, .env, backups, dumps), verbose
  error pages, and dangling-DNS subdomain takeover checks.
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

---

## Reference Module: `cors-evaluation`

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


---

## Reference Module: `header-baseline`

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


---

## Reference Module: `sensitive-files`

# Sensitive file path list and triage

Companion to `scripts/exposure_probe.py` (which carries the same list as its
built-in set). All paths are relative to the target base URL.

## Path families

### VCS metadata (source disclosure)

| Path | Marker | Severity when 200 |
|---|---|---|
| `.git/config` | `[core]`, `[remote ` | HIGH — repo layout, remote URLs (redact any embedded credentials before evidence storage; hand the secret to the operator, never reuse it) |
| `.git/HEAD` | `ref: refs/` | MED — confirms a live repo |
| `.git/index` | binary (sha1 index) | HIGH — with objects readable, full source reconstruction |
| `.git/logs/HEAD` | `reflog` | MED — commit/author metadata |
| `.git/packed-refs` | `refs/` | MED |
| `.git/refs/heads/master`, `.git/refs/heads/main` | sha1 hex | MED |
| `.svn/entries`, `.svn/wc.db` | `svn` | HIGH (same class as git) |
| `.hg/store/00changelog.i` | binary | MED |

Safe reconstruction limits (binding): fetch git objects read-only into the
engagement workspace (dumb-HTTP object walk), analyze there, never `push`,
never create refs upstream, never touch the production repo state. If the
engagement does not authorize source retrieval, stop at proof of `.git/config`
+ `.git/index` readability.

### Environment / config files

| Path | Markers |
|---|---|
| `.env`, `.env.local`, `.env.development`, `.env.production`, `.env.staging` | `DB_`, `APP_`, `SECRET`, `API_KEY`, `SMTP_` |
| `.env.backup`, `.env.bak`, `.env.old`, `.env.save`, `env.txt` | same |
| `.htaccess` | `RewriteRule`, `AuthType` |
| `.htpasswd` | username:hash lines |
| `web.config`, `web.config.bak` | `connectionString`, `password` |
| `WEB-INF/web.xml` | `<servlet`, `<param-value` |
| `META-INF/context.xml` | `username`, `password` |
| `crossdomain.xml`, `clientaccesspolicy.xml` | `allow-access-from domain="*"` — wildcard policy is itself a finding |
| `.ssh/id_rsa` | `PRIVATE KEY` |

### Editor droppings and backups

`index.php~`, `index.php.bak`, `index.php.old`, `index.php.orig`,
`index.php.save`, `index.html.bak`, `config.php.bak`, `.DS_Store` (directory
listing), `Thumbs.db`, `*.swp`/`*.swo` (Vim swap magic `b0VIM`).
Markers: `<?php` for PHP backups, `password`/`PRIVATE KEY` generically.

### Server information pages

| Path | Markers |
|---|---|
| `/server-status`, `/server-status/` | `Apache Server Status`, `requests currently being processed` |
| `/server-info` | `Apache Server Information` |
| `/phpinfo.php`, `/info.php`, `/test.php` | `PHP Version`, `phpinfo()` |
| `/debug` | framework debug toolbar |
| `/trace.axd` | ASP.NET request traces |
| `/elmah.axd` | ASP.NET error logs |
| `/actuator`, `/actuator/health`, `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings` | Spring `_links`, `propertySources`; `env`/`heapdump` are CRITICAL (secrets in memory dump) |
| `/console` (Spring Boot devtools) | websocket console |

### Dumps and archives

| Path | Markers |
|---|---|
| `backup.sql`, `dump.sql`, `db.sql`, `database.sql` | `INSERT INTO`, `CREATE TABLE`, `-- MySQL dump` |
| `database.sql.gz`, `backup.sql.gz`, `backup.tar.gz` | gzip magic `1f 8b` |
| `backup.zip`, `site.zip`, `www.zip`, `backup.rar` | zip magic `PK` |

Magic-byte sniff outranks extension: report any PK/gzip-magic hit whatever
the extension is.

## Triage rules

1. **200 + marker** = confirmed exposure. Capture the full response (or head +
   sha256 when huge). Report severity from the table.
2. **200 without known marker** = download to the engagement workspace and
   review manually before claiming anything.
3. **403** = exists but ACL-protected. Register the path as a candidate for
   verb override (P5), encoding-ladder (P5), or path-normalization bypass
   (`/.git//config`, `/%2e%67it/config`, `/.git/config/.`) — but those are
   active checks: run them only under the P5 probing discipline, not from
   this passive phase.
4. **404** = absent; keep the log line for the coverage statement.
5. **3xx** = follow once manually only if same-origin; login redirects on
   everything usually mean an edge rule, note it.
6. Size anomalies: 200 with byte-identical body to the homepage = soft-404;
   treat as 404.
7. Never POST/PUT to anything in this phase; GET only.

## Evidence

- Per confirmed exposure: `evidence/p2-exposure-<host>-<slug>.{req,resp}.txt`
  (full body when practical).
- D2: re-fetch once; confirm same status + marker.
- Secrets found in bodies: redact in stored evidence to
  `REDACTED-<first-4>...`, keep the unredacted version only in the
  engagement-namespace secret handoff to the operator.


---

## Reference Module: `subdomain-takeover`

# Subdomain takeover (dangling DNS)

Detect subdomains of the engagement domain whose DNS points at third-party
service resources that no longer exist (dangling), making the name
potentially claimable by an attacker. This reference deliberately describes
service families generically; map them to the concrete vendors present in
your engagement during the run.

## Detection workflow

1. Input: P1 asset list with CNAME records for every in-scope hostname.
2. Flag hostnames whose CNAME target is outside the engagement domain (third
   -party service edge).
3. For each, two dangling signals:
   - DNS: the CNAME target itself (or a label inside it) returns NXDOMAIN.
   - HTTP: the service answers with its canonical "resource not found / not
     claimed / no such site" page.
4. A takeover candidate requires BOTH: dangling target AND a fingerprint
   match from the family table below.

## Fingerprint table (generic service families)

| Family (generic) | Typical dangling signal | Claimable via | Takeover impact |
|---|---|---|---|
| Cloud static-site hosting | NXDOMAIN on the site hostname; service 404 page says the site does not exist | creating a site/bucket with that name on the service | full content control on the engagement subdomain |
| Source-control pages service | NXDOMAIN; "there isn't a GitHub Pages site here"-class page | publishing a repo's site under the dangling name | content control + cookie-bearing domain |
| Helpdesk/ticketing SaaS | CNAME to the vendor; vendor answers "no such helpdesk" | creating an account with that hostname | phishing portal on trusted domain |
| Marketing/email landing platforms | NXDOMAIN on campaign hostname | re-registering the subdomain inside the platform | brand-trusted phishing |
| Status-page SaaS | vendor "no such status page" | claiming the name in the service | false status broadcasts |
| Analytics/session-recording SaaS | CNAME to CDN edge; "host not found in tenant" | registering tenant | script injection into the parent site's telemetry |
| CDN/edge with per-customer hostnames | edge 404 "unknown customer hostname" | re-provisioning the hostname on the CDN | content interception on that hostname |
| CMS/blog SaaS | "domain not claimed by any site" page | claiming the domain in the SaaS | full site clone on the domain |
| Cloud object storage static hosting | "no such bucket" page (404 or 403 variant) | creating a bucket with that name | content control; 403 variant usually NOT claimable — record as dangling-only |

Notes:
- The 403 "bucket" variant is frequently a permissions artifact, not an
  unclaimed name: do not escalate it beyond "dangling, claimability unknown".
- Some families dangle at a label inside the CNAME (tenant name), not the
  left-most label; verify which label is NXDOMAIN.

## Safe verification (binding rules)

1. Allowed without extra authorization: DNS queries (`dig CNAME`, `dig A`,
   `dig NS` on the chain) and unauthenticated GETs to the subdomain to
   capture the fingerprint page.
2. NOT allowed by default: registering/claiming the dangling resource on the
   third-party service, creating accounts, or pointing your own content at
   the name. Claiming is an impact proof that requires explicit written
   operator authorization, an engagement-controlled account, and use of your
   own documentation-domain content (`example.com`-class placeholder).
3. Never exploit a claimed takeover to serve content to real users; a benign
   canary page (`rj-pt-<engagement>-<nonce>` marker) is the ceiling.
4. Third-party services themselves are out of scope: test only the
   engagement's DNS names, never the vendor's infrastructure.

## Evidence

- DNS: `dig` output (or equivalent) showing the full CNAME chain and the
  NXDOMAIN answer, timestamped.
- HTTP: the fingerprint response captured verbatim.
- Verdict ladder: "dangling (D1)" when signals 1-2 hold; "claimable (D2)"
  only when a controlled claim was authorized and performed; otherwise the
  report says dangling with claimability untested.

