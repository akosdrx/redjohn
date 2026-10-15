# Wordlist selection matrix (directory/file fuzzing)

Wordlists referenced by name as shipped in the assessment container
(SecLists-style layout, `/opt/wordlists/` inside the RedJohn assessment
container). All example targets use documentation domains only.

## Selection matrix by target type

| Target type (signals) | Primary list | Size class | Extensions (`-e`) | Notes |
|---|---|---|---|---|
| Unknown / generic web | `Discovery/Web-Content/common.txt` | ~4.6k | `html,txt` | Always run first; cheapest signal per request |
| Generic, second pass | `Discovery/Web-Content/raft-medium-directories.txt` | ~32k | none | Only if first pass found real directories (same structure exists) |
| REST API (`/api`, JSON 404s) | `Discovery/Web-Content/api/objects.txt` + `raft-medium-words` for object names | ~1k + ~64k | none | Also permute `/api/v1`..`/api/v3`, underscores vs hyphens |
| Java/Tomcat (`JSESSIONID`, `Server: Coyote`) | `Discovery/Web-Content/tomcat.txt` | ~80 | none | Add probes `/manager/html`, `/host-manager/html`, `/WEB-INF/web.xml` (single GETs) |
| Java/Spring Boot (`/actuator` hint) | `Discovery/Web-Content/spring-boot.txt` | ~60 | none | `/actuator/*` endpoints; `/actuator/env` handling belongs to `50` |
| PHP (`PHPSESSID`, `.php` 404s) | `Discovery/Web-Content/big.txt` filtered | ~20k | `php,html,bak,old` | `/phpmyadmin/`, `composer.json`, `vendor/` probes |
| ASP.NET (`X-AspNet-Version`, `.aspx` 404s) | `Discovery/Web-Content/APSX.txt` / IIS shortname first | ~1k | `aspx,asmx,asp` | `aspnet_client/`, `trace.axd`, `elmah.axd` |
| WordPress (`wp-content` seen) | `Discovery/Web-Content/CMS/wp-plugins.fuzz.txt` + `wp-themes` | ~30k | none | Plus single GETs: `xmlrpc.php`, `wp-login.php`, `readme.html`, `wp-cron.php` |
| nginx static hosting | `Discovery/Web-Content/common.txt` + config names | ~5k | `conf,bak,txt` | `nginx.conf`, `nginx.conf.bak`, mime.types |
| Node/Express (`connect.sid`) | `Discovery/Web-Content/common.txt` | ~4.6k | `json` | `package.json`, `package-lock.json`, `.env` probes |
| Django/Flask (`csrftoken`) | `Discovery/Web-Content/common.txt` | ~4.6k | none | `/admin/`, `/static/`, `/debug/` (Django debug page), `.well-known/` |

## Sizing guidance

1. Small first, always: `common.txt`-class (<= 5k) on every host in scope.
2. Medium (~20-65k) only where the small pass found >= 3 real directories —
   that means the naming convention is guessable.
3. Large (raft-big, directory-list-2.3-big) only for engagement-prioritized
   hosts, with written time budget for the run.
4. Never concatenate lists blindly: dedupe (`sort -u`) or you pay twice.
5. API hosts: wordlist of *object nouns* (users, invoices, payments) beats
   directory lists; pair with method permutation later, not at P1.

## Rate guidance

| Situation | Setting |
|---|---|
| Default | serial probes (library scripts) or `ffuf -t 1-5` |
| Explicit authorization for faster fuzzing | `ffuf -t 10` max, watch error rate |
| Any `429` or 5xx responses appear | halve concurrency; if it persists, stop and re-plan |
| Authenticated fuzzing | same ceilings; one context at a time, labeled |
| Small/virtualized target (lab fixtures) | serial only |

Master rules apply: no resource exhaustion beyond what the engagement
authorizes in writing; fuzzing is the only phase with a concurrency ceiling.

## Backup-file patterns checklist

Run as a second ffuf pass against discovered file names (`file.php` -> list):

- `file.bak`, `file.old`, `file.orig`, `file.save`, `file.copy`, `file~`
- `file.txt`, `file.log`, `file.tmp`, `file.swp`, `.file.swp`
- `file.zip`, `file.tar.gz`, `file.rar`, `file.7z`
- dated variants: `file.2025.bak`, `file-v2.bak`, `file.bak2`
- editor/VCS residue (single GETs, never fuzz): `/.idea/workspace.xml`,
  `/.vscode/sftp.json`, `/.DS_Store`, `/.history/`, `/.git/HEAD`,
  `/.git/config`, `/.svn/entries`, `/.env`, `/.env.bak`, `/.env.prod`

Positive backup/VCS hits are handed to `50-config-baseline` (exposed-file
owner); do not download archives at P1 beyond proving existence (HEAD or
first bytes + `Content-Length` evidence).
