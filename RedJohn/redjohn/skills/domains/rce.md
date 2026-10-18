---
name: rce
description: Code execution, deserialization, uploads, and file inclusion. Prove the process ran your marker, then stop.
---

# RCE

The proof is a marker you chose appearing from the server's process: `id`, `whoami`, a canary echo, or a template evaluating an expression. One clean result is enough. Follow the impact ceiling in the safety skill. No shells, no new users, no second stage.

## Where execution hides

**Command and argument injection.** Shell metacharacters are the obvious case. The quieter one is argument injection: a parameter that becomes another flag (`--upload-file`, `-o`, a config path) with no shell involved. If `shell=False` would still pass your string as argv, test flags, not `; id`.

**Templates and expression languages.** Confirm evaluation (`7*7` → `49`) before any operating-system command. EL, SpEL, Freemarker, Jinja, Twig, and Smarty do not share a payload.

**Deserialization.** A gadget chain is a finding when you observe the side effect (a DNS canary, a delay you measured, a file the payload wrote and you can read back). A `rO0AB` or pickle blob in a cookie is a lead. Java, PHP, Python, and .NET chains are not interchangeable; look up the library you fingerprinted instead of pasting a generic chain.

**Uploads.** The bypass that matters is the one the server executes or serves back as that type: extension, content type, magic bytes, double extension, and archive path (`../` inside a zip) are attempts, not findings. A stored file you can only download as `application/octet-stream` is not code execution. Polyglots count when the interpreter actually runs them.

**File inclusion and traversal.** `../` that returns a file you named (`/etc/passwd`, the app's own config) is the proof. Encoding and null-byte tricks are attempts. A PHP wrapper or log poisoning becomes RCE only when you show the included content executed. Stopping at `/etc/passwd` is a file-read finding; say that, and do not dress it up as code execution.

## Known CVEs

A fingerprinted version plus `lookup_cve` tells you what to try. The advisory is not the finding. Reproduce the condition on this target or leave it as a dependency note for the `supply` mission. `fast_path_rce` advisories go first; drop them when the patched behavior is what you observe.
