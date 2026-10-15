# pentestskills authoring conventions

Every folder in this library is one skill and follows the same skeleton. These
rules exist so RedJohn's `search_skills` dispatch stays sharp and every
request-sending script fails closed against out-of-scope targets.

## Folder and file layout

```
NN-kebab-function-name/
├── SKILL.md            # the playbook (see structure below), <= 400 lines
├── references/*.md     # depth loaded on demand: attack trees, checklists, mappings
└── scripts/*.py        # small, self-contained helpers (stdlib only)
```

- Folder name = skill id. The `name:` field in frontmatter must equal the folder
  stem exactly (e.g. folder `40-injection-engine` -> `name: 40-injection-engine`).
- Frontmatter carries ONLY `name` and `description` — those are the only fields
  RedJohn reads, and token search matches against them, never the body.

## Description = dispatch trigger

Write the description as 1-3 sentences of "Use when ..." trigger phrases naming
the concrete symptoms and surface terms for that skill, and nothing that overlaps
another folder's triggers. Unique first line per skill, unique phrasing overall.
Example for `20-traffic-manipulation`:

> Use when replaying or editing raw HTTP requests, when comparing server
> responses to detect behavioral differences, or when planting and waiting on
> out-of-band (OOB) DNS/HTTP callbacks for blind SSRF, XXE or async command
> injection.

## SKILL.md structure (show the way, don't tell the steps)

Write for a capable pentester: the model already knows the textbook —
payload syntax, header thresholds, bypass tricks, tool flags. The skill
contributes what the textbook doesn't say about doing this inside the
harness on a live engagement: orientation, process honesty, safety gates,
and where the deep tables live. Principles, never numbered procedure.

Structure (target 25-45 lines, hard cap 60; `00-master` caps at 140):

1. **Title + mission** — 1-2 sentences: what this phase owns.
2. **The way** — up to 8 bullets of heuristics: judgment calls, gotchas,
   order-of-operations instincts, binding safety rules. Each bullet earns
   its place by being non-obvious or load-bearing; if the model would
   produce it unprompted, cut it.
3. **Handoffs** — routing edges in and out.
4. **Tools** — scripts, CLIs, and the pointer to `references/` for the
   lookup depth.

Rules of thumb:

- Checklists, payload lists, per-item thresholds and command syntax belong
  in `references/*.md` (lookup data, loaded on demand) or nowhere — never
  in SKILL.md.
- A heuristic beats a step: "fresh tokens before believing a swap finding"
  is a skill; "re-issue tokens then replay and compare sha256" is noise.
- Safety gates and RoE defaults stay in SKILL.md even when short — they
  are the lines that must never be missed.

## Scope guard (mandatory in every script that sends a request)

Fail closed. The canonical guard, copy-adapted per script:

```python
import ipaddress
import json
import socket
import sys
import urllib.parse


def host_allowed(target, scope):
    """Return (allowed, reason). Fail closed on any parse/DNS error."""
    try:
        parsed = urllib.parse.urlparse(target)
        if parsed.scheme not in ("http", "https"):
            return False, "scheme-not-http(s)"
        host = (parsed.hostname or "").lower().rstrip(".")
        if not host:
            return False, "no-host"
        try:
            addrs = {info[4][0].split("%", 1)[0] for info in socket.getaddrinfo(host, None)}
        except socket.gaierror:
            return False, "dns-unresolvable"
        if not addrs:
            return False, "dns-unresolvable"
        parsed_addrs = [ipaddress.ip_address(a) for a in addrs]
        nets = []
        for entry in scope.get("allowed", []):
            if entry.get("host", "").lower().rstrip(".") == host:
                return True, "host"
            if "cidr" in entry:
                nets.append(ipaddress.ip_network(entry["cidr"], strict=False))
        if nets and all(any(ip in net for net in nets) for ip in parsed_addrs):
            return True, "cidr"
        return False, "not-in-scope"
    except Exception as exc:  # fail closed on anything unexpected
        return False, f"error:{exc}"


def require_in_scope(target, scope_file):
    """Exit(2) unless target is inside the engagement scope."""
    with open(scope_file, "r", encoding="utf-8") as fh:
        scope = json.load(fh)
    ok, why = host_allowed(target, scope)
    if not ok:
        sys.stderr.write(
            "[scope-guard] refused %s (%s) engagement=%s\n"
            % (target, why, scope.get("engagement", "unnamed"))
        )
        sys.exit(2)
    return scope
```

Rules:

- Scope comes from `--scope-file PATH` or `REDJOHN_SCOPE_FILE`; absent file =
  refuse to run anything that sends a request.
- Loopback/private/reserved ranges are only reachable by listing them
  explicitly in the scope file (that is how local lab fixtures are sanctioned).
- Every request-sending script MUST implement `--self-test` which exits 0 after
  asserting: guard refuses `https://example.com` under a localhost-only scope;
  guard refuses a private IP without an explicit CIDR entry; guard allows
  `http://127.0.0.1:PORT` when that host is listed. No network needed for the
  self-test itself (test the guard logic, not a live server).
- Offline analysis scripts (no network) still implement `--self-test` with a
  fixture input.

## Script rules

- Python 3, standard library only. Self-contained: no shared imports between
  folders (skills are imported individually; a shared lib would not travel).
- No literal credentials anywhere; anything secret comes from environment
  variables. Examples use documentation domains/IPs only (`example.com`,
    `*.example`, `203.0.113.0/24`, `198.51.100.0/24`) and placeholder accounts
  (`user-a@example.com`, `user-b@example.com`).
- Human-readable output; exit 0 on success, 2 on scope refusal, 1 on other
  errors. Print the evidence expectation (which request/response to keep).

## Content rules

- CVE claims require version proof from fingerprinting, plus the advisory ID,
  plus a "verified against NVD/vendor advisory at authoring time" note. Prefer
  naming stable, well-known CVEs; never invent one.
- CWE ids: use the canonical number and name (e.g. CWE-89 SQL Injection).
- Every checklist item should be executable or observable, not advisory prose.
- Language: English.
- Evidence and memory discipline: raw evidence belongs to the engagement
  namespace; nothing in a skill may instruct copying raw evidence into global
  memory or reports without operator validation (D3).
