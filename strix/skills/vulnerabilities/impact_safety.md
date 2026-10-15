---
name: impact_safety
description: Impact safety (from rce_fast_path_verification specialist reference library)
---

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

