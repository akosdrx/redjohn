---
name: joomla
description: Joomla! CMS security assessment covering manifest fingerprinting, Web Services API, component routing, and RCE/auth bypass verification
---

# Joomla! Security Assessment

Joomla! security assessments focus on exact manifest version identification, Core Web Services API access controls, and third-party component (`com_*`) vulnerabilities.

## Reconnaissance & Version Fingerprinting

1. **Exact Manifest Extraction (Tier 1):**
   - Check `/administrator/manifests/files/joomla.xml` and `/language/en-GB/en-GB.xml` (or `/language/en-GB/install.xml`) for the exact `<version>` tag.
   - Query `lookup_cve(product="joomla", version="<ver>")` immediately once the version is confirmed.
2. **Component & Module Enumeration:**
   - Enumerate `/index.php?option=com_<name>` and `/administrator/components/com_<name>/<name>.xml`.

## High-Impact Vulnerability Priorities (P1.5 Fast-Path)

1. **Unauthenticated API & Information Disclosure (`CVE-2023-23752`):**
   - Test `/api/index.php/v1/config/application?public=true` and `/api/index.php/v1/users?public=true` on Joomla! 4.0.0–4.2.7 for leaked database credentials and user records.
2. **Remote Code Execution & Template / Deserialization Flaws:**
   - Check session serialization handlers, PHAR upload/stream triggers in media managers, and administrator template editing if privileged credentials or leaked DB credentials are obtained.
3. **Component SQL Injection & LFI:**
   - Inspect `view`, `task`, `layout`, `id`, and `list[fullordering]` parameters in third-party components (`com_*`).
