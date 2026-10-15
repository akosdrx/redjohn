---
name: parameter_mining
description: 'Parameter mining: candidates, JS patterns, confirmation (from recon_endpoint_mapping
  specialist reference library)'
---

# Parameter mining: candidates, JS patterns, confirmation

Hidden GET/POST parameter discovery for P1. All names below are candidate
*names* — values are always a benign canary (`rj-pt-<engagement>-<nonce>`),
never a payload at this phase (payloads belong to `40-injection-engine`).

## Candidate lists by framework/surface

### Generic web (the `param_miner.py` built-in set)

`debug, admin, test, preview, action, redirect, next, url, file, path,
template, lang, theme, access, role, internal, draft, backup, restore,
export, format, callback, return, continue, data, query, cmd, exec, run,
command, download, view, display, page, id, type, mode, version, env, config`

### Debug/trace toggles worth their own pass

`debug, debug=1, dev, devmode, trace, verbose, profiling, sql_debug, showsql,
show_sql, log, logging, benchmark, timer, profile, xdebug, toolbar, di,
phpinfo, aspxerrorpath, test, staging, draft, preview, internal, admin`

### PHP applications

`include, include_path, page, module, action, file, dir, path, template,
tpl, lang, load, view, screen, display, step, inc, require, doc, document`

### ASP.NET applications

`aspxerrorpath, page, path, file, virtualpath, theme, skin, control,
handler, asmx, callback, method, viewstate, returnurl, ReturnUrl, next`

### Java/JSP applications

`action, method, forward, include, path, page, jsp_precompile, debug,
screenName, cmd, process, beanName, refresh, layout, return-to`

### REST/API surfaces

`fields, sparse, include, embed, expand, filter, q, query, sort, order,
limit, offset, page, per_page, page_size, verbose, debug, dry_run, format,
envelope, meta, internal, admin, sudo, as_user, act_as, scope, grant_type`

### Access/role hints (classify hits for `30-auth-access-control`)

`admin, isadmin, is_admin, role, roles, access, level, permissions, group,
priv, privileged, internal, staff, su, sudo, act_as, impersonate, user_id,
account_id, owner, org_id, tenant`

## JS regex extraction patterns

The same patterns `scripts/js_endpoint_extract.py` applies (copyable for
one-off greps; always anchored to quotes to cut noise):

```text
API call sites:
  (fetch|axios(?:\.(?:get|post|put|patch|delete))|\$\.(?:get|post|put|delete))\s*\(\s*["'`]([^"'`\s]+)["'`]

Quoted absolute endpoints:
  https?://[A-Za-z0-9.\-]+(?::\d+)?(?:/[^\s"'`<>{}]*)

Quoted site paths (>=1 segment, quoted):
  ["'`](/(?:[A-Za-z0-9\-._~!$&'()*+,;=:@%?]+/){1,6}[A-Za-z0-9\-._~!$&'()*+,;=:@%?]*)["'`]

Query parameter names:
  [?&]([A-Za-z_][A-Za-z0-9_]*)=

Secret-looking NAMES only (never capture the value; case-insensitive so
camelCase apiKey matches):
  \b[A-Za-z_]*?(?:api[-_]?key|api[-_]?secret|secret[-_]?key|access[-_]?key|access[-_]?token|auth[-_]?token|client[-_]?secret|password|passwd)[A-Za-z0-9_]*\b\s*[:=]
```

Asset extensions to filter from path results: `.css .png .jpg .jpeg .svg
.woff .woff2 .ttf .gif .ico .mp4 .webm .map` (keep `.map` only as a
sourcemap lead: `//# sourceMappingURL=`).

## Archive sources

1. `waybackurls <origin> | grep -E '\?.+=' | sort -u` — historical parameter
   names; restrict to in-scope hosts, strip values before registering names.
2. Common Crawl index lookups for the same origins (passive, no target
   traffic) — same treatment: names only.
3. Old parameter names on live endpoints are still worth probing: features
   get removed from the UI, not always from the handler.

## Confirmation workflow (delta -> D1 -> D2)

1. Baseline: GET the endpoint bare; record status/length/sha256
   (`param_miner.py` does this automatically).
2. Probe: GET with `?name=<canary>`; a delta is any of status, length, or
   body-hash change versus baseline.
3. Reproduce with a fresh cache-buster nonce (`&rjpt=<nonce2>`) — the delta
   must survive; caching deltas do not.
4. A/A calibration on the endpoint (`20` harness): identical request twice;
   dimensions that differ A/A are noise and are excluded from the claim.
5. Diff properly with `resp_diff.py` (`20-traffic-manipulation`), never by
   eyeball; attach both pairs as evidence.
6. POST/body params: edit form bodies or JSON keys in the replay harness
   instead of GET probing; keep `Content-Type` correct for the surface.
7. Classify the confirmed parameter and hand off:
   - reflected / executed / queried -> `40-injection-engine`
   - access or ownership change -> `30-auth-access-control`
   - debug output, stack traces -> `50-config-baseline`
   - business behavior change (price, state, limits) -> `58-logic-concurrency`
8. Register: `param <name> on <method> <path>, source <js|archive|candidate>,
   evidence <file>` in the surface inventory.

Dead-end rule (from master): three probe generations on one endpoint without
a surviving delta -> log the negative result and move on.

