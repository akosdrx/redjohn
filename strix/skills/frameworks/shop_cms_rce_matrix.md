---
name: shop_cms_rce_matrix
description: E-Commerce & CMS Fingerprint and P1.5 Advisory Matrix (from cms_ecommerce_rce
  specialist reference library)
---

# E-Commerce & CMS Fingerprint and P1.5 Advisory Matrix

Read-only fingerprint indicators and documented advisory classes for e-commerce
and CMS targets. Always verify exact version boundaries via `redjohn-vuln-intel`
(`vuln_intel_priority_scan`, `osv_query_package`, `nvd_search_cve`) before
claiming applicability.

---

## 1. Platform Fingerprint & Version Extraction Endpoints (Read-Only GET)

| Platform | Read-Only Fingerprint / Version Paths | Tier | High-Priority Surface Classes (Hand off to `70` -> `45`) |
|---|---|---|---|
| **Magento / Adobe Commerce** | `/magento_version`, `/pub/static/version*/`, `/rest/V1/store/storeViews`, `/graphql` | Tier 1 (if `/magento_version` returns `Magento/2.x`) | REST/SOAP XML entity & nested deserialization (`CVE-2024-34102`), email/block template preview filters (`CVE-2022-24086`), guest cart webapi routes |
| **Shopware 6** | `/api/_info/version`, `/store-api/context`, `/bundles/administration/` | Tier 1-2 | Twig template rendering in mail/document preview (`CVE-2023-22731`), API filter/hydration endpoints |
| **WooCommerce / WordPress** | `/wp-links-opml.php`, `/wp-json/`, `/xmlrpc.php`, `/wp-content/plugins/*/readme.txt`, `/feed/` | Tier 1 (from `readme.txt` `Stable tag:` or OPML generator) | Plugin REST endpoints (`/wp-json/wc-analytics`, payment/shipping plugin routes), XML-RPC brute-force/SSRF pingback, PHP object injection in unauthenticated plugin hooks |
| **PrestaShop** | `/config/xml/channel.xml`, `/modules/*/config.xml`, `/api/`, `/install/` | Tier 1-2 | Smarty template rendering in module controllers, Webservice API key scope bypass, legacy module file-upload and SQL/eval chains (`CVE-2022-36408`) |
| **Drupal / Drupal Commerce** | `/core/CHANGELOG.txt`, `/jsonapi`, `/CHANGELOG.txt`, `X-Generator: Drupal` | Tier 1-2 | Form API / render array callbacks, Twig/filter rendering, JSON:API anonymous entity listing and field exposure |
| **Joomla!** | `/administrator/manifests/files/joomla.xml`, `/language/en-GB/en-GB.xml`, `/api/index.php/v1/` | Tier 1-2 | Web Services API unauthorized access / account enumeration (`CVE-2023-23752`), unauthenticated component SQLi/RCE, template injection |
| **Laravel / Livewire / Statamic** | `/_ignition/health-check`, `/livewire/livewire.js`, `X-Powered-By` / session cookie naming (`laravel_session`) | Tier 2 | Debug mode (`/_ignition/` — `CVE-2021-3129`), `APP_KEY` signed cookie/component hydration (`CVE-2024-29291`), Blade dynamic view rendering |
| **Next.js / Remix / Node Storefronts** | `/_next/static/`, `x-powered-by: Next.js`, `/__nextjs_original-stack-frame` | Tier 2 | Server Actions / SSR route handlers, middleware header bypass (`CVE-2025-29927`), image optimizer SSRF |
| **Spring Boot / Java Commerce (Hybris)** | `/actuator/info`, `/actuator/health`, `/actuator/env` | Tier 1-2 | Actuator configuration exposure (`50`), SpEL/Thymeleaf view evaluation (`45`), Jackson/SnakeYAML deserialization |

---

## 2. Fingerprint Tier Discipline for E-Commerce Stacks

1. **Tier 1 (Exact Version String):**
   - Returned directly by a dedicated version endpoint (`/magento_version`,
     `readme.txt` `Stable tag:`, `/core/CHANGELOG.txt`) or package manifest.
   - Immediately eligible for `vuln_intel_priority_scan` and P1.5 fast-path.
2. **Tier 2 (Banner + Behavioral/Asset Confirmation):**
   - Major/minor version confirmed via asset bundle hash or API schema shape
     (`/wp-json/` namespaces, `/rest/V1/` schema).
   - Eligible for `70-exploit-intel` correlation and targeted non-destructive
     verification.
3. **Tier 3–4 (Header/Cookie Heuristic Only):**
   - Only `X-Powered-By` or cookie prefix (`PHPSESSID`, `laravel_session`)
     without version number.
   - **Never** file a version-based CVE from Tier 3–4; run read-only asset/manifest
     checks first to upgrade to Tier $\le 2$.

---

## 3. Why P1.5 Precedes P5 on Storefronts

Storefronts expose hundreds of catalog filter, sort, and facet query parameters
that can trap an agent in slow P5 SQLi/XSS fuzzing while a known Tier-1
unauthenticated REST/template/deserialization CVE sits on `/rest/V1/` or
`/wp-json/`. Always:
1. Run `cms_surface_probe.py` on the in-scope target.
2. Feed every Tier 1–2 component/plugin version into `redjohn-vuln-intel`
   (`vuln_intel_priority_scan`) and `exploit_priority_rank.py`.
3. Verify any `P1.5-FAST-PATH` candidate via `45-rce-exploitation` and
   `95-finding-verifier` before dispatching broad P5 parameter fuzzing.

