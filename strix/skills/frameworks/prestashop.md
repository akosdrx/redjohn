---
name: prestashop
description: PrestaShop, Magento/Adobe Commerce, and Shopware e-commerce security assessment prioritizing RCE, Smarty/Twig SSTI, deserialization, and module CVEs
---

# PrestaShop & E-Commerce Security Assessment

E-commerce storefronts (PrestaShop, Magento/Adobe Commerce, Shopware) frequently expose unauthenticated module controllers (`fc=module`), Smarty/Twig template preview endpoints, and Webservice/REST APIs. Always prioritize RCE, SSTI, and deserialization over slow catalog filter SQLi fuzzing.

## Reconnaissance & Version Fingerprinting

1. **PrestaShop Fingerprinting:**
   - Check `/config/xml/channel.xml`, `/Install_PrestaShop.html`, `/docs/CHANGELOG.txt`, and module manifests at `/modules/<module_name>/config.xml`.
   - Enumerate module front controllers via `/index.php?fc=module&module=<name>&controller=<ctrl>` or `/module/<name>/<ctrl>`.
2. **Magento / Shopware Fingerprinting:**
   - Check `/magento_version`, `/rest/V1/store/storeViews`, `/api/_info/version`, and `/store-api/context`.
   - Query `lookup_cve` for the core platform and every discovered module name/version.

## High-Impact Vulnerability Priorities (P1.5 Fast-Path)

1. **Remote Code Execution & Smarty/Twig SSTI (`CVE-2022-36408` and Module RCEs):**
   - Prioritize known PrestaShop Smarty cache/template injection chains, Magento email/block template filter evaluation (`CVE-2022-24086`), XML/nested deserialization (`CVE-2024-34102`), and unauthenticated module file upload endpoints (`ajax.php`, `upload.php`).
2. **Webservice & REST API Access Control:**
   - Check `/api/` (PrestaShop Webservice) and `/rest/V1/` (Magento) for unauthenticated or guest-token access to orders, customer PII, or configuration state.
3. **Module SQL Injection & LFI:**
   - Only after RCE and Auth Bypass checks are completed, test third-party module AJAX endpoints where raw SQL concatenation is common.
