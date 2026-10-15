---
name: wordpress
description: WordPress and WooCommerce security assessment covering plugin/theme enumeration, REST API, XML-RPC, and high-impact CVE verification
---

# WordPress & WooCommerce Security Assessment

WordPress and WooCommerce vulnerabilities predominantly arise in third-party plugins, themes, custom REST API routes (`/wp-json/`), and AJAX handlers (`/wp-admin/admin-ajax.php`). Prioritize high-impact remote code execution, authentication bypass, arbitrary file upload, and PHP object injection before low-severity parameter fuzzing.

## Reconnaissance & Version Fingerprinting

1. **Core Version Identification (Tier 1-2):**
   - Inspect `/wp-links-opml.php`, `/feed/`, `/rdf/`, `/atom/`, `<meta name="generator">`, and `/wp-includes/js/wp-embed.min.js?ver=`.
2. **REST API & Namespace Enumeration:**
   - Fetch `/wp-json/` and `/wp-json/wp/v2/users` to map registered plugin namespaces (e.g., `wc/v3`, `wc-analytics`, `elementor/v1`, custom endpoints) and check `permission_callback` enforcement.
3. **Plugin & Theme Discovery:**
   - Extract `/wp-content/plugins/<slug>/readme.txt` (`Stable tag:`) and `/wp-content/themes/<slug>/style.css` (`Version:`).
   - Query every discovered plugin and version with `lookup_cve(product="<slug>", version="<ver>")`.

## High-Impact Vulnerability Priorities (P1.5 Fast-Path)

1. **Unauthenticated RCE & Arbitrary File Upload:**
   - Check plugin AJAX actions (`wp_ajax_nopriv_*`) and REST routes that accept file uploads, zip extraction, or shortcodes without capability checks (`current_user_can`).
2. **PHP Object Injection / Deserialization:**
   - Identify parameters passed to `maybe_unserialize()` or `unserialize()`, or `phar://` stream wrappers in media/import handlers.
3. **Authentication & Privilege Escalation:**
   - Audit password reset flows, user registration metadata (`wp_insert_user` / `update_user_meta` mass assignment of `wp_capabilities`), and OAuth/SSO plugin callbacks.
4. **XML-RPC & SSRF:**
   - Check `/xmlrpc.php` via `system.listMethods` for `pingback.ping` SSRF and multicall amplification.
5. **SQL Injection in Custom Queries:**
   - Focus on plugins using `$wpdb->query()` or `$wpdb->get_results()` without `$wpdb->prepare()`, especially in sorting, filtering, or REST parameters.
