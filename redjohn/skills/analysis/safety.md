---
name: safety
description: Closure, severity, and impact ceiling. Every candidate ends confirmed, ruled out by a named control, or left as an open proof gap.
---

# Safety

## Close every candidate

A candidate ends in one state.

- **confirmed** — a PoC you ran, or a complete source → control → sink → impact trace that is reachable. File it.
- **ruled_out** — you can name the control, where it is, and that it runs on every attacker-reachable path before the sink. "The framework probably escapes this" is not that sentence.
- **open_proof_gap** — plausible, unconfirmed, and you cannot name that control. Record `needs_follow_up`. Carry it in `agent_finish(open_items=...)`. Do not relabel it clean because you moved on.

These do not rule a candidate out: a sanitizer you did not check in this context, a guard on a sibling route, a failed build, a service you could not start, no caller found, or "probably not deployed."

## Severity

Rate the impact you proved. A chain of assumptions is not critical.

Critical means decisive control or mass data access with evidence: unauthenticated code execution, a forgeable authentication decision, cross-tenant data, or signing-key compromise.

High means a real trust-boundary cross you demonstrated: authenticated code execution, privilege escalation, injection that reaches data, SSRF that reaches metadata or an internal service.

Medium covers stored or interaction-gated XSS, CSRF on a real action, and a high-impact bug blocked by a constraint you confirmed.

Low or informational: missing headers, cookie flags, self-XSS, an open redirect with no token theft, version banners, enumeration that only proves a name exists.

Missing evidence about exposure lowers confidence. It does not let you pretend the target is internal-only.

## Impact ceiling

Prove execution with the lightest signal that is unambiguous: `id` or `whoami`, `echo` of a unique canary, a template rendering `7*7`, or one DNS/HTTP canary for a blind sink. Stop there.

Do not open a shell, add a user, write cron or services, download a second stage, or read `/etc/shadow` and user tables to "make the proof more interesting." A data-access claim needs its own evidence and stays inside scope.

A version match, a scanner label, or a theoretical follow-on is not a finding. Say what you ran and paste the output you got.
