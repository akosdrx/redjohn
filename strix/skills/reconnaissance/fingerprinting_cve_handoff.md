---
name: fingerprinting_cve_handoff
description: Fingerprinting, CPE mapping and the 70-exploit-intel handoff (from recon_endpoint_mapping
  specialist reference library)
---

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

