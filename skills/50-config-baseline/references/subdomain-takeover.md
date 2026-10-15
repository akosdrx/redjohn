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
