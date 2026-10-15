# Sensitive file path list and triage

Companion to `scripts/exposure_probe.py` (which carries the same list as its
built-in set). All paths are relative to the target base URL.

## Path families

### VCS metadata (source disclosure)

| Path | Marker | Severity when 200 |
|---|---|---|
| `.git/config` | `[core]`, `[remote ` | HIGH — repo layout, remote URLs (redact any embedded credentials before evidence storage; hand the secret to the operator, never reuse it) |
| `.git/HEAD` | `ref: refs/` | MED — confirms a live repo |
| `.git/index` | binary (sha1 index) | HIGH — with objects readable, full source reconstruction |
| `.git/logs/HEAD` | `reflog` | MED — commit/author metadata |
| `.git/packed-refs` | `refs/` | MED |
| `.git/refs/heads/master`, `.git/refs/heads/main` | sha1 hex | MED |
| `.svn/entries`, `.svn/wc.db` | `svn` | HIGH (same class as git) |
| `.hg/store/00changelog.i` | binary | MED |

Safe reconstruction limits (binding): fetch git objects read-only into the
engagement workspace (dumb-HTTP object walk), analyze there, never `push`,
never create refs upstream, never touch the production repo state. If the
engagement does not authorize source retrieval, stop at proof of `.git/config`
+ `.git/index` readability.

### Environment / config files

| Path | Markers |
|---|---|
| `.env`, `.env.local`, `.env.development`, `.env.production`, `.env.staging` | `DB_`, `APP_`, `SECRET`, `API_KEY`, `SMTP_` |
| `.env.backup`, `.env.bak`, `.env.old`, `.env.save`, `env.txt` | same |
| `.htaccess` | `RewriteRule`, `AuthType` |
| `.htpasswd` | username:hash lines |
| `web.config`, `web.config.bak` | `connectionString`, `password` |
| `WEB-INF/web.xml` | `<servlet`, `<param-value` |
| `META-INF/context.xml` | `username`, `password` |
| `crossdomain.xml`, `clientaccesspolicy.xml` | `allow-access-from domain="*"` — wildcard policy is itself a finding |
| `.ssh/id_rsa` | `PRIVATE KEY` |

### Editor droppings and backups

`index.php~`, `index.php.bak`, `index.php.old`, `index.php.orig`,
`index.php.save`, `index.html.bak`, `config.php.bak`, `.DS_Store` (directory
listing), `Thumbs.db`, `*.swp`/`*.swo` (Vim swap magic `b0VIM`).
Markers: `<?php` for PHP backups, `password`/`PRIVATE KEY` generically.

### Server information pages

| Path | Markers |
|---|---|
| `/server-status`, `/server-status/` | `Apache Server Status`, `requests currently being processed` |
| `/server-info` | `Apache Server Information` |
| `/phpinfo.php`, `/info.php`, `/test.php` | `PHP Version`, `phpinfo()` |
| `/debug` | framework debug toolbar |
| `/trace.axd` | ASP.NET request traces |
| `/elmah.axd` | ASP.NET error logs |
| `/actuator`, `/actuator/health`, `/actuator/env`, `/actuator/heapdump`, `/actuator/mappings` | Spring `_links`, `propertySources`; `env`/`heapdump` are CRITICAL (secrets in memory dump) |
| `/console` (Spring Boot devtools) | websocket console |

### Dumps and archives

| Path | Markers |
|---|---|
| `backup.sql`, `dump.sql`, `db.sql`, `database.sql` | `INSERT INTO`, `CREATE TABLE`, `-- MySQL dump` |
| `database.sql.gz`, `backup.sql.gz`, `backup.tar.gz` | gzip magic `1f 8b` |
| `backup.zip`, `site.zip`, `www.zip`, `backup.rar` | zip magic `PK` |

Magic-byte sniff outranks extension: report any PK/gzip-magic hit whatever
the extension is.

## Triage rules

1. **200 + marker** = confirmed exposure. Capture the full response (or head +
   sha256 when huge). Report severity from the table.
2. **200 without known marker** = download to the engagement workspace and
   review manually before claiming anything.
3. **403** = exists but ACL-protected. Register the path as a candidate for
   verb override (P5), encoding-ladder (P5), or path-normalization bypass
   (`/.git//config`, `/%2e%67it/config`, `/.git/config/.`) — but those are
   active checks: run them only under the P5 probing discipline, not from
   this passive phase.
4. **404** = absent; keep the log line for the coverage statement.
5. **3xx** = follow once manually only if same-origin; login redirects on
   everything usually mean an edge rule, note it.
6. Size anomalies: 200 with byte-identical body to the homepage = soft-404;
   treat as 404.
7. Never POST/PUT to anything in this phase; GET only.

## Evidence

- Per confirmed exposure: `evidence/p2-exposure-<host>-<slug>.{req,resp}.txt`
  (full body when practical).
- D2: re-fetch once; confirm same status + marker.
- Secrets found in bodies: redact in stored evidence to
  `REDACTED-<first-4>...`, keep the unredacted version only in the
  engagement-namespace secret handoff to the operator.
