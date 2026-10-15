---
name: drupal
description: Drupal and Drupal Commerce security assessment covering changelog/header fingerprinting, JSON:API, Form API render arrays, and Twig/RCE verification
---

# Drupal & Drupal Commerce Security Assessment

Drupal assessments prioritize core and contributed module version fingerprinting, Form API / render array callback injection, Twig template evaluation, and JSON:API / REST access control verification.

## Reconnaissance & Version Fingerprinting

1. **Version & Module Fingerprinting:**
   - Inspect `/core/CHANGELOG.txt`, `/CHANGELOG.txt`, `/core/install.php`, `X-Generator` HTTP response headers, and `/modules/contrib/<module>/<module>.info.yml`.
   - Run `lookup_cve(product="drupal", version="<ver>")` for core and contributed modules.
2. **API Surface Discovery:**
   - Check `/jsonapi` for exposed entity types, bundles, and user/commerce fields accessible to anonymous roles.

## High-Impact Vulnerability Priorities (P1.5 Fast-Path)

1. **Remote Code Execution (Render Arrays, Form API & File Processing):**
   - Test Form API `#post_render`, `#pre_render`, `#access_callback`, and `#lazy_builder` gadget surfaces in custom or contributed forms, as well as archive/media upload handlers.
2. **Twig Server-Side Template Injection:**
   - Audit custom inline template rendering or user-controlled Twig filter pipelines in commerce email/invoice previews.
3. **Access Bypass in JSON:API, GraphQL & Views:**
   - Verify entity access controls across unpublished nodes, private files (`/system/files/`), and Drupal Commerce order/cart endpoints.
