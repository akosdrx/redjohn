---
name: 10-recon-endpoint-mapping
description: Use when mapping a target's attack surface before vulnerability testing - crawling pages and client-side JavaScript for endpoints, fuzzing directories and files for unlinked paths, mining hidden GET/POST parameters, fingerprinting web servers, frameworks and libraries for CVE correlation, or discovering exposed API schemas (OpenAPI/Swagger, GraphQL, WSDL).
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
