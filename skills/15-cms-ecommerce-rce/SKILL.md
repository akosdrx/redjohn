---
name: 15-cms-ecommerce-rce
description: Use when the target is an e-commerce storefront, shopping cart, or CMS platform (Magento/Adobe Commerce, Shopware, WooCommerce/WordPress, PrestaShop, Drupal, Joomla!, Laravel, Next.js, Spring) to fingerprint exact versions and prioritize P1.5 code execution surfaces before generic parameter fuzzing.
---

# CMS and e-commerce surface triage (P1.5)

E-commerce and CMS platforms fail through known versioned advisories, plugin
routes, and template/serialization endpoints far more often than custom SQL
queries. This skill pins the platform, version, and high-value endpoints in P1
so P1.5 (`70` -> `45`) can run before slow P5 fuzzing.

## The way

- Read-only first: extract exact versions (tier 1-2) from public version
  endpoints, release manifests (`joomla.xml`, `channel.xml`, `CHANGELOG.txt`),
  static asset hashes, OPML generators, and REST/GraphQL/API metadata
  using `cms_surface_probe.py` before sending any active probe.
- Calibrate soft-404s on the root and `/admin` or `/rest` prefixes first —
  storefronts frequently wrap 404s in 200 HTML catalog shells.
- Separate core platform version from third-party plugin/extension versions
  (`wp-content/plugins/*/readme.txt`, `modules/*/config.xml`, `composer.lock`,
  Shopware/Magento module routes); plugin CVEs outnumber core CVEs.
- Treat exposed REST/SOAP/GraphQL guest cart, checkout, and preview routes as
  P1.5 priority candidates for `70-exploit-intel` and `45-rce-exploitation`.
- Never send mutating payloads or serialized objects from this skill — record
  the surface + version tier and hand off to `70` and `45`.

## Handoffs

Tier 1-2 platform/plugin versions -> `70` (`vuln_intel_priority_scan` +
`exploit_priority_rank.py`); P1.5 fast-path RCE/SSTI/deserialization surfaces ->
`45`; guest/customer cart & coupon state endpoints -> `58` and `30`.

## Tools

`cms_surface_probe.py` (guarded, read-only GET/HEAD); `redjohn-vuln-intel` MCP;
platform fingerprint and CVE surface tables in `references/shop-cms-rce-matrix.md`.
