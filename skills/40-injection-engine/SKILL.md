---
name: 40-injection-engine
description: Use when probing input handling for server-side execution - SQL/NoSQL/LDAP injection, context-aware reflected, stored and DOM-based XSS, SSRF including internal ranges and cloud metadata endpoints, SSTI template expressions, XXE, and OS command injection.
---

# Injection engine (P5)

Where input crosses a trust boundary and gets interpreted: SQL/NoSQL/LDAP,
XSS, SSRF, SSTI, XXE, OS command. You know the classes; this is how the
harness keeps the process honest.

## The way

- Baseline first, one variable at a time, encode ladder weakest-first —
  the rung that produced the delta is part of the finding.
- Context before payload: classify where the input lands (SQL string or
  identifier, HTML body/attribute/JS string, URL, template, XML). The
  context picks the probe; a payload without its context is log noise.
- Signals are measured, not eyeballed: diffs through the `20` harness,
  boolean TRUE-vs-FALSE pairs, timing as medians over N >= 5.
- Blind classes are proved by effect — OOB canary, boolean delta, timing.
  "No error" is never "not vulnerable", and no callback is no claim.
- SSRF proves reachability, not pivoting: one benign metadata field at
  most, never credentials; a 405/token error on IMDS is itself the
  finding. Internal ranges only in scope.
- Filtered probes are data — map the filter, don't declare failure.
- Engine, DBMS and parser fingerprints from errors and evaluations feed
  `70`.
- Three generations without signal -> log the negative, move on.

## Handoffs

Execution escalation -> `45`; blind machinery -> `20`; XSS impact ->
`55`; versions -> `70`; API-shaped sinks -> `60`.

## Tools

`sqli_probe.py` (time probes RoE-gated), `xss_context.py` (offline);
sqlmap only with the safe-flag caps in the reference. Payload trees and
the context matrix live in `references/`.
