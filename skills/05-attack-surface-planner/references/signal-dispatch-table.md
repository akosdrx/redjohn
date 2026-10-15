# Signal-to-Skill Dispatch Table

This table maps reconnaissance fingerprints, infrastructure indicators, and behavioral cues to prioritized RedJohn assessment skills across Tiers 1 through 5.

## 1. Five-Tier Signal-to-Skill Matrix

| Tier | Category | Concrete Fingerprints & Surface Signals | Target RedJohn Skills | Phase |
|---|---|---|---|---|
| **Tier 1** | **Identity & SSO Fabric** | Okta (`/oauth2/`, `okta-hosted`), Entra/M365 (`login.microsoftonline.com`), Auth0 (`/authorize`, `auth0.js`), Keycloak (`/auth/realms/`), Ping Identity, SAML assertions. | `30-auth-access-control`<br>`32-mfa-captcha-audit` | P4 |
| **Tier 2** | **Perimeter Appliances** | Fortinet FortiOS (`/remote/login`), Ivanti Connect Secure (`/dana-na/`), Citrix NetScaler (`/vpn/index.html`), VMware vCenter (`/ui/login`), Palo Alto GlobalProtect (`/global-protect/`). | `70-exploit-intel`<br>`80-oracle-stack`<br>`82-proxmox-ve` | P1.5 / P8 |
| **Tier 3** | **Cloud & Edge Infrastructure** | Cloudflare (`cf-ray`, `__cf_bm`), AWS CloudFront (`x-amz-cf-id`), Akamai (`x-akamai-transformed`), Fastly, GCP Cloud Armor, Nginx reverse proxy headers. | `25-waf-edge-posture`<br>`50-config-baseline` | P2 / P3 |
| **Tier 4** | **Application Frameworks & CMS** | Next.js (`__NEXT_DATA__`), Spring Boot (`/actuator`), Laravel (`laravel_session`, Ignition), ASP.NET (`VIEWSTATE`), WordPress (`/wp-json/`), Drupal (`/core/CHANGELOG.txt`), Joomla! (`/administrator/manifests/files/joomla.xml`), PrestaShop (`/config/xml/channel.xml`). | `15-cms-ecommerce-rce`<br>`60-api-graphql-websockets`<br>`70-exploit-intel` | P1.5 / P4 |
| **Tier 5** | **Protocols & Vulnerability Classes** | GraphQL (`/graphql`, `__schema`), WebSocket (`Upgrade: websocket`), Java serialization (`rO0AB`), Python pickle markers, SSRF canary reflection. | `20-traffic-manipulation`<br>`40-injection-engine`<br>`45-rce-exploitation`<br>`55-client-side-attacks`<br>`58-logic-concurrency` | P3 / P5 / P6 |

---

## 2. Precedence and Load Budget Allocation Rules

When multiple signals fire simultaneously:
1. **Tier 1 (Identity)** and **Tier 2 (Perimeter Appliances)** take top priority for immediate execution.
2. If exact component versions are detected (Tier 1/2 confidence), route directly to **P1.5 Fast-Path Triage** (`70-exploit-intel` + `15-cms-ecommerce-rce`).
3. If an edge layer (Tier 3) is detected, run `25-waf-edge-posture` to establish direct origin exposure and normalization baselines before heavy fuzzing.
4. Cap the active platform skill roster at **8**. If more than 8 skills match, defer Tier 5 generic class skills until specific endpoint parameters are identified.
