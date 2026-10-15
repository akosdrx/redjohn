---
name: recon_endpoint_mapping
description: Use when mapping a target's attack surface before vulnerability testing
  - crawling pages and client-side JavaScript for endpoints, fuzzing directories and
  files for unlinked paths, mining hidden GET/POST parameters, fingerprinting web
  servers, frameworks and libraries for CVE correlation, or discovering exposed API
  schemas (OpenAPI/Swagger, GraphQL, WSDL).
---

# Recon and endpoint mapping (P1)

Everything later phases test against comes from here: the **surface
inventory** (method, path, params, auth context, source) and the
**fingerprint list** (component, version, tier, evidence).

## The way

- Calibrate soft-404s before fuzzing: request a few random paths first; a
  hit is only a hit if it differs from that cluster.
- Crawl anonymous and once per auth context, separately labeled — the
  auth-only endpoint delta seeds `30`'s matrix.
- Fingerprints carry confidence tiers (exact / banner / banner+behavior /
  source). Only tier <= 2 ever goes to `70` for CVE correlation; banners
  can lie (fronting, frozen `Server` strings), so the tier travels with
  the claim.
- A 200 on `/openapi.json` is not exposure — verify the content shape;
  HTML login pages returned with 200 are soft-404s.
- JS mining records secret-looking *names* as inventory rows; values are
  never extracted.
- A 403 is a registration for later (`30`/`50`), not a bypass attempt now.
- Out-of-scope assets found along the way are observations, nothing more.

## Handoffs

Inventory -> `30`/`40`/`58`/`60`; fingerprints (tier <= 2) -> `70` (and
`80`/`82` when the stack matches); exposed files/VCS -> `50`.

## Tools

katana, ffuf, httpx, gowitness, waybackurls (in-scope only). Scripts:
`param_miner.py` (guarded), `js_endpoint_extract.py` (offline). Lookup
tables — wordlist matrix, param candidates, fingerprint signals, schema
paths — in `references/`.

---

## Reference Module: `api-schema-discovery`

# API schema discovery: probe list and verification

Concrete probes for exposed API definitions. All requests are serial,
scope-guarded GETs/POSTs against the in-scope origin; substitute
`https://target.example.com` with the engagement target.

## OpenAPI / Swagger probe list

| Path | Method | Positive signal |
|---|---|---|
| `/openapi.json` | GET | 200 + JSON with `openapi` or `swagger` top-level key |
| `/openapi.yaml` | GET | 200 + YAML with `openapi:` key |
| `/swagger.json` | GET | 200 + JSON with `swagger: "2.0"` or `openapi` key |
| `/swagger/v1/swagger.json` | GET | ASP.NET Core default swagger location |
| `/api/swagger.json` | GET | Common when API is mounted under `/api` |
| `/api/docs/swagger.json` | GET | NestJS-style docs mount |
| `/v2/api-docs` | GET | Springfox (Swagger 2) default |
| `/v3/api-docs` | GET | Springdoc (OpenAPI 3) default |
| `/v3/api-docs/swagger-config` | GET | Springdoc UI config; lists doc URLs |
| `/api-docs` | GET | Generic mount |
| `/api-docs/swagger.json` | GET | Generic mount variant |
| `/swagger-ui.html` | GET | Swagger UI redirect (302 to `/swagger-ui/index.html`) |
| `/swagger-ui/index.html` | GET | Swagger UI page (fetch its `url:` config) |
| `/swagger-ui/` | GET | Directory UI without `.html` |
| `/doc` , `/docs` | GET | Many frameworks mount docs UI here |
| `/actuator/mappings` | GET | Spring Boot endpoint map (may need actuator exposure) |
| `/api.raml` | GET | RAML definition |
| `/apidoc` , `/api/apidoc` | GET | apiDoc-style generated docs |

## Verification rules (before calling it exposed)

1. 200 alone proves nothing: confirm `Content-Type` is `application/json`
   (or YAML/text for YAML) and the body parses with a top-level
   `openapi`/`swagger`/`paths`/`definitions` key.
2. HTML login pages returned with 200 on these paths = soft-404; discard.
3. `swagger-config` responses count only when they list a reachable doc URL.
4. Check whether the schema is intentionally public (linked from `/docs` or
   marketing site) before drafting a finding; intentional exposure is an
   information-disclosure observation at most.

## GraphQL probes

Endpoints to try, in order: `/graphql`, `/api/graphql`, `/v1/graphql`,
`/graphql/v1`, `/graphiql`, `/altair`, `/playground`.

Minimal introspection query (POST with
`Content-Type: application/json`):

```json
{"query":"query IntrospectionProbe { __schema { queryType { name } } }"}
```

- 200 + `data.__schema` -> introspection open; record evidence pair.
- Error mentioning "introspection" / "disabled" -> endpoint exists,
  introspection blocked; register surface for `60`.
- 404/HTML -> move to the next path.
- Full schema dump is `60-api-graphql-websockets` work (depth limits,
  field-level authorization); P1 only proves the endpoint and open/closed
  introspection state.

## WSDL / SOAP probes

| Probe | Notes |
|---|---|
| `GET /Service.asmx?WSDL` | ASP.NET SOAP |
| `GET <endpoint>?wsdl` on every `/services/*` path found in the crawl | Java/Axis/CXF style |
| `GET /wsdl` | Generic mount |
| `GET /api/soap?wsdl` | SOAP under an API mount |
| `GET /soap` and `/soap/` | Generic SOAP gateway |

Positive signal: 200 + `Content-Type: text/xml` + root element
`<wsdl:definitions` or `<definitions`. Register operations; WSDL testing
(XML payloads, XXE, SOAPAction abuse) belongs to `40`/`60`.

## Registration

For every confirmed schema:

```text
schema | type=openapi3 | url=https://target.example.com/v3/api-docs |
  operations=<count> | auth=none | evidence=evidence/p1-api-schema-001.{req,resp}.txt
```

Then register each operation as an inventory row (method, path, params,
declared auth). No testing beyond the discovery request(s) at P1; the
operation list is consumed by `30` (role matrix), `40` (input surfaces),
`58`/`60` (API-specific checks).


---

## Reference Module: `fingerprinting-cve-handoff`

# Fingerprinting, CPE mapping and the 70-exploit-intel handoff

How a raw observation becomes a version-pinned fingerprint that
`70-exploit-intel` is allowed to correlate against CVEs.

## Signal sources table

| Signal class | Concrete signals | What it proves |
|---|---|---|
| Response headers | `Server:`, `X-Powered-By:`, `X-AspNet-Version:`, `X-AspNetMvc-Version:`, `X-Runtime:` (Rails), `X-Generator:` | Component + sometimes exact version |
| Cookies | `JSESSIONID` (Java servlet), `PHPSESSID` (PHP), `ASP.NET_SessionId` (ASP.NET), `laravel_session` (Laravel), `ci_session` (CodeIgniter), `connect.sid` (Express), `csrftoken`/`django_language` (Django), `PVEAuthCookie` (Proxmox -> `82`), `weblogic` cookies (:7001 -> `80`) | Component family, rarely version |
| Body/meta | `<meta name="generator" content="WordPress x.y">`, Drupal/Drupallet markers, `Whitelabel Error Page` (Spring Boot), Tomcat/Jetty stack traces on forced errors (benign 404/400 only) | Component + version when the generator prints it |
| Error pages | 404/500 page shape: nginx default, IIS `X-Powered-By` pages, PHP `expose_php` signature in `X-Powered-By` | Family; version on verbose builds |
| Console paths (single unauthenticated GET) | `/manager/html` (Tomcat), `:7001/console` (WebLogic -> `80`), `/actuator/health`, `/actuator/info` (Spring Boot), `/wp-login.php` + `readme.html` (WordPress), `/api2/json/version` (Proxmox :8006 -> `82`), `/OA_HTML` (Oracle EBS -> `80`) | Family + often exact version |
| Manifests/source | `package.json`, `composer.json`, `/actuator/info` build section, `META-INF/*.properties` in listings, `CHANGELOG.*`, `swagger.json` `info.version` | Exact version (tier 1) |
| Favicon hash | mmh3 hash of `GET /favicon.ico` matched against known favicon databases | Family confirmation; use as tiebreaker only |

Never trigger a verbose error on purpose at P1 beyond a benign 404/400; no
malformed payloads here (that is `40` territory).

## Version-confidence tiers

| Tier | Name | Evidence required | Permits |
|---|---|---|---|
| 1 | exact | Version read from a manifest, changelog, actuator info block, or vendor version endpoint | CVE correlation; `70` handoff with CPE |
| 2 | banner | Explicit version string in `Server`/`X-Powered-By`/generator meta | CVE correlation with "banner-sourced" caveat; `70` handoff |
| 3 | banner+behavior | Family from banner/cookie + behavior probe narrowing a range (e.g. endpoint only exists >= some release) | Hint only; no CVE claim; drives further probing |
| 4 | source | Inferred from file layout, cookie names, console path existence only | Registration in inventory only |

Banner stripping (`Server:` removed) drops many hosts to tier 3/4 — record
that explicitly; do not guess versions to force a tier upgrade.

## CPE mapping

- Format: `cpe:2.3:a:<vendor>:<product>:<version>[:update:edition:language]`.
  Examples (documentation illustrations):
  - Apache Tomcat 9.0.50 -> `cpe:2.3:a:apache:tomcat:9.0.50`
  - Spring Boot 2.6.4 -> `cpe:2.3:a:vmware:spring_boot:2.6.4` (verify vendor
    string against the NVD CPE dictionary at correlation time, not from
    memory)
- Normalize the component name to the CPE dictionary spelling before
  handing off; `70` owns the lookup, P1 only proposes the candidate CPE.
- One fingerprint row per component, not per signal: merge `Server` + cookie
  + console signals into the row and cite each evidence file.

## Handoff format (fingerprint list rows)

```text
fingerprint | component=Apache Tomcat | version=9.0.50 | tier=2 |
  evidence=evidence/p1-fingerprint-001.resp.txt (Server header, GET /) |
  cpe_candidate=cpe:2.3:a:apache:tomcat:9.0.50 | handoff=70-exploit-intel
```

Rules carried from CONVENTIONS and the master skill:

1. Only tier <= 2 rows go to `70-exploit-intel`. Tier 3/4 stay as hints.
2. A CVE claim needs: version proof (tier <= 2), the advisory ID, and a
   "verified against NVD/vendor advisory at authoring time" note. Prefer
   stable, well-known CVEs; never invent or guess an ID.
3. Oracle/Proxmox signals route to `80-oracle-stack` / `82-proxmox-ve`
   before generic `70` correlation — those skills own stack-specific
   versioning and patch levels.
4. Version claims are loop-back points: any tier upgrade discovered later
   (P4-P6) re-registers here and re-hands-off to `70`.


---

## Reference Module: `parameter-mining`

# Parameter mining: candidates, JS patterns, confirmation

Hidden GET/POST parameter discovery for P1. All names below are candidate
*names* — values are always a benign canary (`rj-pt-<engagement>-<nonce>`),
never a payload at this phase (payloads belong to `40-injection-engine`).

## Candidate lists by framework/surface

### Generic web (the `param_miner.py` built-in set)

`debug, admin, test, preview, action, redirect, next, url, file, path,
template, lang, theme, access, role, internal, draft, backup, restore,
export, format, callback, return, continue, data, query, cmd, exec, run,
command, download, view, display, page, id, type, mode, version, env, config`

### Debug/trace toggles worth their own pass

`debug, debug=1, dev, devmode, trace, verbose, profiling, sql_debug, showsql,
show_sql, log, logging, benchmark, timer, profile, xdebug, toolbar, di,
phpinfo, aspxerrorpath, test, staging, draft, preview, internal, admin`

### PHP applications

`include, include_path, page, module, action, file, dir, path, template,
tpl, lang, load, view, screen, display, step, inc, require, doc, document`

### ASP.NET applications

`aspxerrorpath, page, path, file, virtualpath, theme, skin, control,
handler, asmx, callback, method, viewstate, returnurl, ReturnUrl, next`

### Java/JSP applications

`action, method, forward, include, path, page, jsp_precompile, debug,
screenName, cmd, process, beanName, refresh, layout, return-to`

### REST/API surfaces

`fields, sparse, include, embed, expand, filter, q, query, sort, order,
limit, offset, page, per_page, page_size, verbose, debug, dry_run, format,
envelope, meta, internal, admin, sudo, as_user, act_as, scope, grant_type`

### Access/role hints (classify hits for `30-auth-access-control`)

`admin, isadmin, is_admin, role, roles, access, level, permissions, group,
priv, privileged, internal, staff, su, sudo, act_as, impersonate, user_id,
account_id, owner, org_id, tenant`

## JS regex extraction patterns

The same patterns `scripts/js_endpoint_extract.py` applies (copyable for
one-off greps; always anchored to quotes to cut noise):

```text
API call sites:
  (fetch|axios(?:\.(?:get|post|put|patch|delete))|\$\.(?:get|post|put|delete))\s*\(\s*["'`]([^"'`\s]+)["'`]

Quoted absolute endpoints:
  https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s"'`<>{}]*)

Quoted site paths (>=1 segment, quoted):
  ["'`](/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%?]+/){1,6}[A-Za-z0-9\-._~!$&'()*+,;=:@%?]*)["'`]

Query parameter names:
  [?&]([A-Za-z_][A-Za-z0-9_]*)=

Secret-looking NAMES only (never capture the value; case-insensitive so
camelCase apiKey matches):
  \b[A-Za-z_]*?(?:api[-_]?key|api[-_]?secret|secret[-_]?key|access[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|password|passwd)[A-Za-z0-9_]*\b\s*[:=]
```

Asset extensions to filter from path results: `.css .png .jpg .jpeg .svg
.woff .woff2 .ttf .gif .ico .mp4 .webm .map` (keep `.map` only as a
sourcemap lead: `//# sourceMappingURL=`).

## Archive sources

1. `waybackurls <origin> | grep -E '\?.+=' | sort -u` — historical parameter
   names; restrict to in-scope hosts, strip values before registering names.
2. Common Crawl index lookups for the same origins (passive, no target
   traffic) — same treatment: names only.
3. Old parameter names on live endpoints are still worth probing: features
   get removed from the UI, not always from the handler.

## Confirmation workflow (delta -> D1 -> D2)

1. Baseline: GET the endpoint bare; record status/length/sha256
   (`param_miner.py` does this automatically).
2. Probe: GET with `?name=<canary>`; a delta is any of status, length, or
   body-hash change versus baseline.
3. Reproduce with a fresh cache-buster nonce (`&rjpt=<nonce2>`) — the delta
   must survive; caching deltas do not.
4. A/A calibration on the endpoint (`20` harness): identical request twice;
   dimensions that differ A/A are noise and are excluded from the claim.
5. Diff properly with `resp_diff.py` (`20-traffic-manipulation`), never by
   eyeball; attach both pairs as evidence.
6. POST/body params: edit form bodies or JSON keys in the replay harness
   instead of GET probing; keep `Content-Type` correct for the surface.
7. Classify the confirmed parameter and hand off:
   - reflected / executed / queried -> `40-injection-engine`
   - access or ownership change -> `30-auth-access-control`
   - debug output, stack traces -> `50-config-baseline`
   - business behavior change (price, state, limits) -> `58-logic-concurrency`
8. Register: `param <name> on <method> <path>, source <js|archive|candidate>,
   evidence <file>` in the surface inventory.

Dead-end rule (from master): three probe generations on one endpoint without
a surviving delta -> log the negative result and move on.


---

## Reference Module: `wordlists`

# Wordlist selection matrix (directory/file fuzzing)

Wordlists referenced by name as shipped in the assessment container
(SecLists-style layout, `/opt/wordlists/` inside the RedJohn assessment
container). All example targets use documentation domains only.

## Selection matrix by target type

| Target type (signals) | Primary list | Size class | Extensions (`-e`) | Notes |
|---|---|---|---|---|
| Unknown / generic web | `Discovery/Web-Content/common.txt` | ~4.6k | `html,txt` | Always run first; cheapest signal per request |
| Generic, second pass | `Discovery/Web-Content/raft-medium-directories.txt` | ~32k | none | Only if first pass found real directories (same structure exists) |
| REST API (`/api`, JSON 404s) | `Discovery/Web-Content/api/objects.txt` + `raft-medium-words` for object names | ~1k + ~64k | none | Also permute `/api/v1`..`/api/v3`, underscores vs hyphens |
| Java/Tomcat (`JSESSIONID`, `Server: Coyote`) | `Discovery/Web-Content/tomcat.txt` | ~80 | none | Add probes `/manager/html`, `/host-manager/html`, `/WEB-INF/web.xml` (single GETs) |
| Java/Spring Boot (`/actuator` hint) | `Discovery/Web-Content/spring-boot.txt` | ~60 | none | `/actuator/*` endpoints; `/actuator/env` handling belongs to `50` |
| PHP (`PHPSESSID`, `.php` 404s) | `Discovery/Web-Content/big.txt` filtered | ~20k | `php,html,bak,old` | `/phpmyadmin/`, `composer.json`, `vendor/` probes |
| ASP.NET (`X-AspNet-Version`, `.aspx` 404s) | `Discovery/Web-Content/APSX.txt` / IIS shortname first | ~1k | `aspx,asmx,asp` | `aspnet_client/`, `trace.axd`, `elmah.axd` |
| WordPress (`wp-content` seen) | `Discovery/Web-Content/CMS/wp-plugins.fuzz.txt` + `wp-themes` | ~30k | none | Plus single GETs: `xmlrpc.php`, `wp-login.php`, `readme.html`, `wp-cron.php` |
| nginx static hosting | `Discovery/Web-Content/common.txt` + config names | ~5k | `conf,bak,txt` | `nginx.conf`, `nginx.conf.bak`, mime.types |
| Node/Express (`connect.sid`) | `Discovery/Web-Content/common.txt` | ~4.6k | `json` | `package.json`, `package-lock.json`, `.env` probes |
| Django/Flask (`csrftoken`) | `Discovery/Web-Content/common.txt` | ~4.6k | none | `/admin/`, `/static/`, `/debug/` (Django debug page), `.well-known/` |

## Sizing guidance

1. Small first, always: `common.txt`-class (<= 5k) on every host in scope.
2. Medium (~20-65k) only where the small pass found >= 3 real directories —
   that means the naming convention is guessable.
3. Large (raft-big, directory-list-2.3-big) only for engagement-prioritized
   hosts, with written time budget for the run.
4. Never concatenate lists blindly: dedupe (`sort -u`) or you pay twice.
5. API hosts: wordlist of *object nouns* (users, invoices, payments) beats
   directory lists; pair with method permutation later, not at P1.

## Rate guidance

| Situation | Setting |
|---|---|
| Default | serial probes (library scripts) or `ffuf -t 1-5` |
| Explicit authorization for faster fuzzing | `ffuf -t 10` max, watch error rate |
| Any `429` or 5xx responses appear | halve concurrency; if it persists, stop and re-plan |
| Authenticated fuzzing | same ceilings; one context at a time, labeled |
| Small/virtualized target (lab fixtures) | serial only |

Master rules apply: no resource exhaustion beyond what the engagement
authorizes in writing; fuzzing is the only phase with a concurrency ceiling.

## Backup-file patterns checklist

Run as a second ffuf pass against discovered file names (`file.php` -> list):

- `file.bak`, `file.old`, `file.orig`, `file.save`, `file.copy`, `file~`
- `file.txt`, `file.log`, `file.tmp`, `file.swp`, `.file.swp`
- `file.zip`, `file.tar.gz`, `file.rar`, `file.7z`
- dated variants: `file.2025.bak`, `file-v2.bak`, `file.bak2`
- editor/VCS residue (single GETs, never fuzz): `/.idea/workspace.xml`,
  `/.vscode/sftp.json`, `/.DS_Store`, `/.history/`, `/.git/HEAD`,
  `/.git/config`, `/.svn/entries`, `/.env`, `/.env.bak`, `/.env.prod`

Positive backup/VCS hits are handed to `50-config-baseline` (exposed-file
owner); do not download archives at P1 beyond proving existence (HEAD or
first bytes + `Content-Length` evidence).

