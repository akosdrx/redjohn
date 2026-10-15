---
name: zeroday_patch_research
description: Use when no public CVE matches a custom or niche attack surface and novelty
  is suspected - patch diffing upstream releases for n-day rediscovery, targeted mutation
  and replay against custom parsers, novelty and impact assessment, and handling an
  undisclosed vulnerability found mid-engagement.
---

# Zero-day research path (P8)

The branch for surfaces where `70` came back empty and the surface is
custom or niche. Everything here is timeboxed, authorized in writing, and
ends either in a downgraded n-day (back to `70`) or a documented
potentially-novel finding whose disclosure is the operator's decision.

## The way

- Entry needs all three or none: `70`'s dated no-match trail, written
  research authorization, a set timebox. Every hour is logged; research
  never eats the P9 budget.
- n-day rediscovery beats novel hunting: diff the pinned version against
  the *next patch release* only. `secdiff` triages hunks into CWE
  hypotheses; a hypothesis is a lead, not a claim.
- Target SAST/DAST blind spots: cross-service taint breaks, dynamic reflection,
  multi-step stateful workflows, and patch gaps where upstream fixes miss
  sibling routes or alternate verbs (`references/sast-dast-blindspots.md`).
- The PoC must discriminate versions — reproduces pre-patch behavior,
  not post-patch, verified against both local builds first. A
  non-discriminating probe proves a feature exists.
- A fix existing does not make the old behavior exploitable: fixes land
  for crashes and defense-in-depth too. Exploitability is claimed only
  from in-scope verification.
- Custom surfaces: sketch the input grammar, then boundary values through
  `40`'s encode ladder, then differential replay via `20`. One variable
  per request; budgets capped; an error-rate spike stops the run.
- Any public record anywhere — advisory, writeup, CVE — means it is not
  a zero-day: downgrade to `70`. The dated search trail *is* the novelty
  evidence; re-run it before delivery.
- Undisclosed findings: report carries the "undisclosed" marking, PoCs
  stay unpublished, vendor contact happens only through the operator.

## Handoffs

Impact proofs -> `45`; downgrades -> `70`; report -> `90` (undisclosed
marked); detection observations -> `85`.

## Tools

`secdiff.py` (offline), git in approved network windows. Procedures —
patch triage, grammar sketching, search discipline, disclosure rules —
in `references/`.

---

## Reference Module: `disclosure-handling`

# Disclosure handling

Operator-coordination rules, embargo notes, and what enters the report vs
what waits. A vulnerability with no CVE found mid-engagement is a business
and legal event, not just a technical finding — every rule below exists to
keep the operator in control of that event.

## 1. Operator-coordination rules (binding)

1. **Disclosure is an operator decision, never autonomous.** No agent run
   contacts a vendor, CERT, or coordinator on its own; no exception exists
   "because it is serious".
2. **Coordinate BEFORE any external report.** The moment a finding looks
   potentially novel: notify the operator in the run notes with the
   evidence trail; all further external steps wait for instruction.
3. **The client is usually the conduit.** The engagement contract typically
   makes the client the party who reports to the vendor (their vendor,
   their product, their exposure). Advise the client PSIRT path; offer to
   support with technical Q&A — through the operator.
4. **Everything stays in the engagement namespace** until the operator
   says otherwise: raw evidence, PoCs, diffs, the novelty trail (D3/D4
   gates apply exactly as to any finding).
5. Discovery timestamps are recorded from evidence files — they matter for
   any later embargo or publication timeline.

## 2. Embargo notes

- If a vendor is engaged (through the client/operator), record: report
   date, vendor case id, agreed embargo end date, status per contact.
- Coordinate release timing: the client report, the vendor advisory, and
   any writeup must not race each other. The report delivery date itself
   can leak a finding — flag the risk to the operator if the report
   audience is wider than the security team.
- Redact or move PoC detail to a confidential annex when the D4 deliverable
   has a wide audience; the annex carries the discriminator pair.
- Embargo expiry does not authorize publication: post-embargo publication
   is still an operator + vendor decision.

## 3. What enters the report vs what waits

Enters the client report (marked **undisclosed; coordinated disclosure in
progress**):

- Vulnerability description and affected component + version (tier-noted).
- Draft CWE (via `70`'s canonical table, justified inline) and conservative
   draft CVSS 4.0 vector (score LOWER where unsure; score from the official
   calculator; `cvss4_render.py` validates the vector).
- Reproduction steps sufficient for the vendor/client to remediate (the
   minimized input, environment notes, the discriminating PoC reference).
- Evidence file references (in the engagement namespace or confidential
   annex).
- Disclosure status line: who was informed, when, embargo state.

Waits (not in the deliverable without explicit operator instruction):

- Weaponized variants or chains beyond what remediation requires.
- Any detail the operator flags as holdback.
- The words "zero-day" / "0day" — the report says "undisclosed
   vulnerability" or "n-day rediscovered via patch diffing"; novelty is a
   negative-evidence statement with a date, not a label.

Never (regardless of instruction level in this library):

- Publishing PoCs (blog, repo, talk, marketplace) — that requires operator
   AND vendor sign-off and is outside an assessment engagement entirely.
- Any contact with third parties (researchers, journalists, brokers) —
   obviously prohibited; findings are the client's information.

## 4. Timeline checklist (attach to the finding record)

- [ ] Discovery timestamps captured from evidence files.
- [ ] Operator notified (date, channel, run note reference).
- [ ] Novelty trail re-run and attached (both runs kept).
- [ ] Draft CWE + conservative CVSS vector validated and attached.
- [ ] Client decision recorded: report-to-vendor path, embargo preference.
- [ ] Report entry carries the "undisclosed" marking and status line.
- [ ] D3 operator validation completed BEFORE delivery or any disclosure
      conversation.


---

## Reference Module: `novelty-assessment`

# Novelty assessment

Search-source checklist, downgrade rules, and the documentation format that
makes "no public record" an evidence-backed statement instead of a feeling.

## 1. Search-source checklist (in order; record every step)

| # | Source | Query shape | What counts as a hit |
|---|---|---|---|
| 1 | NVD / CVE search | component name + version + bug-class keywords (`struts fileupload ogln` style) | any CVE whose description matches the surface |
| 2 | Vendor advisory / PSIRT + release changelog | component + "security" | advisory, security note, or a marked security fix |
| 3 | GitHub Advisory Database (GHSA) | package name | any GHSA for the package |
| 4 | searchsploit (local, offline) | `searchsploit <component>`, `--id <CVE>` | exploit rows naming the component |
| 5 | nuclei template corpus (local) | grep template ids/descriptions for component + CVE | a template implying known vuln coverage |
| 6 | Upstream issue tracker (GitHub Issues/Jira/redmine) | component + crash/exception keywords, error strings from your probe | a filed issue describing the same behavior |
| 7 | Mailing lists: oss-security, fulldisclosure archives | component name | any report/writeup |
| 8 | General web / writeup search | component + bug-class + "vulnerability" | blog posts, conference talks, exploit writeups |
| 9 | CISA KEV catalog | component / CVE | listed CVE (also supports E:A in CVSS) |

Also re-check the exact ERROR STRINGS your probe produced — error text is
the highest-yield search key for niche software (someone else hit it first
and pasted it into a tracker).

## 2. Downgrade rules

- Public writeup OR advisory OR CVE exists -> **not a zero-day**. Hand back
  to `70-exploit-intel` as an n-day: correlate, classify, verify in-scope;
  attach this trail.
- Public PoC exists (even without a writeup) -> not novel; treat as n-day
  with exploit-availability evidence.
- **Silent fix** (patch landed without advisory/CVE) -> the vulnerability
  is undisclosed-but-known-to-the-vendor. Report as "n-day rediscovered
  via patch diffing (silent fix, no advisory as of <date>)" — never as
  novel. Re-check for an advisory before delivery; vendors often publish
  after the fact.
- Same bug class in a DIFFERENT component (e.g. the CVE is for the library
  but your finding is in the app's custom wrapper) -> not a downgrade;
  document the distinction explicitly so the report cannot be read as a
  duplicate.
- Nothing found anywhere: "potentially novel" — a negative-evidence claim
  with a freshness bound, never "confirmed zero-day" (you cannot prove the
  absence of private knowledge).

## 3. Documentation format (the search trail is evidence)

Save as `evidence/p8-novelty-<component>.md`:

```text
novelty-trail | component=ExampleWidget | version=2.3.0 | surface=custom DSL parser
searched=2026-10-12 | by=<operator/agent run id>

| # | source                    | query                              | result | relevant hits |
|---|---------------------------|------------------------------------|--------|---------------|
| 1 | NVD                       | "ExampleWidget" parser injection   | 0      | -             |
| 2 | vendor PSIRT + CHANGELOG  | security section 2.3.0..2.3.1      | 1      | silent fix candidate (commit 4f2a9c1) |
| 3 | GHSA                      | example-widget                     | 0      | -             |
| 4 | searchsploit              | ExampleWidget                      | 0      | -             |
| 5 | nuclei corpus             | grep examplewidget                 | 0      | -             |
| 6 | upstream issues           | "ParseException" depth             | 0      | -             |
| 7 | oss-security archive      | ExampleWidget                      | 0      | -             |
| 8 | web search                | ExampleWidget parser vulnerability | 0      | -             |
| 9 | CISA KEV                  | -                                  | 0      | -             |

conclusion: silent-fix candidate only; no advisory/CVE/writeup found as of
2026-10-12. Report as n-day rediscovered via patch diffing; re-run this
trail before report delivery.
```

Rules: dates on every row; error-string queries recorded verbatim; the
conclusion uses the permitted phrasing only ("no public advisory, PoC, or
writeup found across sources 1-9 as of <date>"); the trail is re-run before
report delivery and both runs are kept.


---

## Reference Module: `patch-diffing`

# Patch diffing for n-day rediscovery

Step-by-step procedure, hunk-triage heuristics, and the version-
discriminating PoC rules. Cheapest research path: most "suspected novel"
bugs in niche components are unreported-then-silent-fixed n-days.

## 1. Procedure

1. **Pin the target version** (tier <= 2 fingerprint from `10`). Tier 3/4:
   stop — diffing against a guessed version wastes the timebox.
2. **Locate the upstream repo** and its release tags (upstream first-party
   repo; note forks and distro-maintained trees separately — a distro patch
   set is its own diff stream). Fetch tags in the operator-approved network
   window: `git clone --branch <pinned-tag> --depth 50 <upstream-url>` or
   fetch just the two tags; save everything to evidence and go offline.
3. **Pick the comparison pair**: pinned version -> NEXT PATCH release
   (`v2.3.0` -> `v2.3.1`). Skip feature releases (`v2.4.0`) for the first
   pass — security fixes overwhelmingly ride patch bumps. If the patch
   release has no candidates, widen one step and re-triage.
4. **Produce the artifacts**:
   - `git diff v2.3.0 v2.3.1 > evidence/p8-diff-<component>-001.patch`
   - `git log v2.3.0..v2.3.1 --oneline > .../commits.txt`
   - changelog section for the release (many projects mark security fixes
     there before any advisory exists).
5. **Machine triage**: `python3 scripts/secdiff.py --diff fix.patch`
   (or `--dir evidence/patches/`). Ranked hunks + CWE hypotheses come out;
   candidates are leads, not findings.
6. **Commit-message correlation**: match candidate hunks to commits;
   "security", "CVE", "hardening", "validation", contributor = maintainer
   of the touched file all raise confidence.
7. **Map to a CWE hypothesis** (secdiff output + `70`'s cwe-mapping.md) and
   proceed to the discriminating PoC (section 3).

Illustration (real, well-known; verify against the upstream repo and NVD at
authoring time): Apache Log4j `rel/2.14.1` -> `rel/2.15.0` contains the
JNDI-lookup restriction fixing CVE-2021-44228 — a textbook
security-dense patch bump.

## 2. Hunk-triage heuristics (what secdiff implements)

| Signal | Weight | Notes / false positives |
|---|---|---|
| CVE id in hunks/test names (`CVE-YYYY-NNNNN`) | strongest | near-definitive when present |
| Strong keywords in added/removed lines: `inject`, `overflow`, `bypass`, `sanitiz*`, `escap*`, `auth` (NOT "author"), `permission` | high | `auth` must exclude `author*` — classic FP |
| Weak keywords: `valid*`, `fix*`, `patch*` | low | ubiquitous in changelogs; tie-breaker only |
| Sink-adjacent changes: touched or neighboring lines containing `eval(`, `exec(`, `system(`, `popen`, `subprocess`, `shell=True`, `innerHTML`, `document.write`, `deserialize`, `pickle.loads`, `yaml.load`, `memcpy`, `strcpy`, `sprintf`, `query` | high | the fix rewiring a sink's input path |
| Regression-test naming: test files whose name/content reference the CVE, a crash input, "regress", "security" | confirming | test-only churn WITHOUT those markers is usually cosmetic |
| Focused hunks (< ~40 lines, single concern) | raises rank | giant refactors hide fixes — deprioritize and re-diff per-commit |
| Huge refactor / docs / version-bump / CI-only | cosmetic | version bumps are how you FIND the pair, not candidates |

Triage output classes: `security-fix-candidate` -> `review` ->
`likely-cosmetic`; only the first two earn PoC effort, in rank order,
inside the timebox.

## 3. Version-discriminating PoC rules

The discriminator is what separates research from noise: a probe whose
output DIFFERS between the two versions of the component.

1. **Build both versions locally** in the disposable container lab
   (`v2.3.0` vulnerable-side, `v2.3.1` fixed-side).
2. **Write the probe against the hunk's changed path**, minimal input,
   benign observable (error text change, rejected/accepted field, reflected
   value, one canary callback). No destructive payloads even locally.
3. **Prove the pair**: probe on pre-patch -> signal; same probe on
   post-patch -> no signal (or the fixed response). Save both outputs —
   this pair is the finding's spine.
4. **Then, and only then, run the identical probe in-scope** — one
   request, RoE discipline, evidence pair captured. In-scope signal ==
   the target runs the vulnerable code path (D1).
5. A probe that fires on BOTH versions discriminates nothing — it proves
   the feature exists. Do not report it as the vulnerability.
6. **NEVER assume exploitability from the fix's existence.** Fixes land
   for crashes, defense-in-depth, theoretical issues, and dead code.
   Exploitability/impact is claimed only from in-scope verification within
   the engagement allowance (`45` doctrine).
7. Keep the probe in the run's evidence: `evidence/p8-poc-<component>-001/`
   with `pre-patch.txt`, `post-patch.txt`, and the in-scope pair.

## 4. Patch-Gap & N-Day Regression Analysis

Upstream security fixes frequently patch only the primary reported entry point
(e.g., filtering a single query parameter in a controller) while leaving the
underlying sink accessible via alternate routes, alternate HTTP verbs (`PUT`/`PATCH`),
alternate content types (`application/xml`, `multipart/form-data`), or legacy
API versions.

1. **Sink-Adjacent Diffing**: Use `secdiff.py` to inspect patch hunks and isolate
   the exact sanitization or sink change.
2. **Sibling Route Traversal**: Cross-reference whether sibling controllers or
   unlinked helper functions call the same unpatched sink logic.
3. **Verb & Serialization Polymorphism**: Test whether the patch checks only `POST`
   requests while the router dispatches `PUT` or deserialized JSON/XML to the
   same backend service.
4. **Regression Probing**: Re-run the discriminating probe against adjacent entry
   points to detect patch gaps without deploying weaponized payloads.
   Detailed analysis: `references/sast-dast-blindspots.md`.


---

## Reference Module: `sast-dast-blindspots`

# SAST and DAST Blind-Spot Analysis

Automated scanners (Static Application Security Testing and Dynamic Application
Security Testing) provide broad baseline coverage but reliably miss critical
vulnerability classes due to fundamental architectural limitations. This guide
documents these blind spots so the zero-day and n-day research path focuses
investigation where scanners fail.

---

## 1. SAST (Static Analysis) Blind Spots

SAST analyzers parse ASTs and construct control-flow/data-flow taint graphs from
source code without a runtime environment. They fail in specific architectural patterns:

1. **Microservice & Asynchronous Boundaries:**
   - Static taint graphs terminate when data crosses process boundaries.
   - An untrusted input written to a message bus (Kafka, RabbitMQ, SQS) or sent
     via internal RPC (gRPC, internal HTTP REST) disappears from the caller's
     taint graph.
   - Downstream microservices ingesting from the queue or RPC endpoint are
     frequently treated as trusted sources by SAST, missing critical injection
     or deserialization sinks.

2. **Dynamic Reflection, Class Loading & Dependency Injection:**
   - Framework-level dynamic invocation (Java `Class.forName()`, Spring Bean
     factories, Python `getattr()`, PHP dynamic class instantiation, Node.js
     dynamic `require()`) breaks static call graph construction.
   - Annotation-driven routing (`@RestController`, `@MessageMapping`) and
     custom aspect-oriented programming (AOP) decorators obscure source-to-sink
     execution order.

3. **Runtime Configuration & Environmental Disconnect:**
   - SAST analyzes code in isolation from runtime settings (`application.yml`,
     `.env`, Kubernetes ConfigMaps, feature flags, Vault secrets).
   - A sink that appears sanitized in code may execute with sanitization disabled
     due to an active debug flag (`DEBUG=true`, `security.strict-parsing=false`)
     at runtime.

---

## 2. DAST (Dynamic Analysis) Blind Spots

DAST scanners crawl endpoints and inject test payloads from the outside without
internal application state visibility. They fail on complex stateful surfaces:

1. **Multi-Step Stateful Business Workflows:**
   - DAST crawlers operate on single-request/single-response loops.
   - Stateful multi-phase workflows (e.g., Cart Creation -> Address Validation ->
     Discount Coupon -> Payment Gateway Handshake -> Order Fulfillment) cannot
     be traversed automatically.
   - Parameter manipulation or state-machine skips inside step 3 of a 5-step
     checkout are missed completely.

2. **Strict Anti-Automation & Ephemeral Nonces:**
   - Modern defenses (rotating single-use anti-CSRF tokens, cryptographic
     request signatures, ephemeral Proof-of-Work nonces, CAPTCHAs, TLS
     fingerprinting) block automated DAST spiders on first contact.
   - An aggressive scan payload that triggers an account lockout or session
     invalidation blinds the DAST scanner for all subsequent requests in that
     context.

3. **Unlinked, Deprecated & Shadow API Routes:**
   - DAST tools discover endpoints primarily by crawling links, HTML forms, and
     public client-side JavaScript bundles.
   - Legacy API endpoints (e.g., `/api/v1/user/export` left active after
     `/api/v2/user/export` was patched), internal debug routes, and administrative
     endpoints are never hyperlinked and remain invisible to dynamic spiders.

---

## 3. Patch-Gap & N-Day Regression Heuristics

When an upstream vendor or project publishes a security patch, automated tooling
frequently reports the vulnerability as resolved. However, patches are often incomplete:

1. **Point-Fix Syndrome:**
   - Developers frequently apply a quick check (e.g. checking `if (param != null)`)
     only on the specific parameter or controller path named in the original bug report.
   - The underlying core sink (database query helper, XML parser, template evaluator)
     remains accessible via alternate controllers, sibling routes, or alternate HTTP methods.

2. **HTTP Verb & Content-Type Polymorphism:**
   - A patch may validate input in the `POST` handler while leaving `PUT`, `PATCH`,
     or `GET` unvalidated if the framework router dispatches to the same business logic.
   - A controller configured for JSON parsing may accept `application/xml` or
     `application/x-yaml` via content negotiation without applying the same parameter sanitizers.

3. **Methodology for Patch-Gap Auditing:**
   - Use `secdiff.py` to identify the sink-adjacent diff in the patch.
   - Search the repository for all other callers of the modified sink or helper function.
   - Test whether alternate routes or unlinked legacy endpoints share the vulnerable sink.
   - Verify with the version-discriminating PoC discipline (pre-patch vs post-patch).


---

## Reference Module: `targeted-fuzzing`

# Targeted mutation, replay and bounded fuzzing

Grammar sketching, mutation ladders, budget/stop rules, and the
differential setup for custom surfaces. Everything here is model-driven
mutation through a sketched grammar — never blind random fuzzing.

## 1. Input grammar sketching (before the first probe)

Write the grammar as a table; every probe must be expressible as a row.

| Field | Type | Delimiter/encoding | Documented limits | Boundary set |
|---|---|---|---|---|
| `query` | string | URL-encoded, then JSON-quoted | len <= 200 | empty, 1, 199, 200, 201, unicode, `%00` |
| `page` | int (1-based) | plain | 1..999 | 0, 1, 999, 1000, -1, `1.5`, `0x1`, `1e3` |
| `filter` | DSL string | base64 body -> parsed | depth <= 3 | depth 4, duplicate keys, unknown ops |
| `sort` | enum-ish | comma list | `name,-date` | unknown field, empty element, doubled commas |

Steps: capture 3 real requests through the `20` harness -> decompose each
field (type, delimiter, encoding layer, limit) -> mark which layers decode
client- vs server-side -> the encode-decode ladder runs through EVERY
decoding layer found.

## 2. Mutation ladders

1. **Boundary values per field** (one per request): empty, `1`, `max-1`,
   `max`, `max+1`, negative, zero, type confusion (`1.5` into an int
   field), duplicate keys (last-wins vs first-wins divergence is a
   differential signal), nested depth one beyond the documented limit,
   unicode (`\u0000`, overlong UTF-8 `xC0xAF`), `%00` terminator.
2. **Encode-decode ladder** (from `40`, verbatim): raw -> single
   URL-encode -> double URL-encode -> Unicode overlong -> `%00`. The rung
   that first produces a delta is part of the finding.
3. **Delimiter injection** at every grammar delimiter: the delimiter
   character, its escaped form, and a premature terminator.
4. **Enum/whitelist probing**: one unknown value, one mixed-case known
   value, one deleted field, one field with wrong type.

## 3. Differential setup

- **Harness**: `20-traffic-manipulation` replay + diff (status/len/sha256).
- **Axes** (one at a time): same input across two endpoints that share the
  parser; two roles (anonymous vs authenticated); two environments (the
  custom parser vs a reference implementation, or pre-patch vs post-patch
  builds from patch diffing).
- **Baseline discipline**: capture the unmutated request's response per
  axis FIRST; every mutation's diff is against that axis's baseline.
- **Signal definition**: a response difference that TRACKS the mutation
  (present with the payload, absent with the baseline value, reproducible
  on replay). One-off glitches are not signals.
- **Invariant: one variable per request.** Stacked mutations are only for
  MINIMIZING an already-reproduced signal: shrink the input until the
  signal disappears, then step back one change — that minimal input is
  what enters evidence.

## 4. Budget and stop rules (binding)

| Rule | Default | Notes |
|---|---|---|
| Generation cap per surface per run | 500 requests | operator sets lower for fragile targets |
| Sleep between probes | >= 0.2 s | serial only; the master's concurrency allowance never applies to research probes |
| Rate ceiling | engagement RoE | never exceeded for a "few more" mutations |
| Stop 1 — signal | first reproducible differential | stop mutating, start minimizing, then verify D2 |
| Stop 2 — budget | cap reached | log the negative result for the coverage statement; move on |
| Stop 3 — error spike | 5xx rate jumps | STOP — availability risk; inform the operator immediately |
| Stop 4 — timebox | section 1 of SKILL.md | research never eats P9 budget |
| Dead-end rule | 3 generations without signal | log negative, move to the next hunk/surface |

## 5. Hygiene

- No fuzzing of third-party SaaS endpoints or out-of-scope hosts; the scope
  guard in every request-sending script enforces this — never bypass it.
- Crash artifacts (stack traces, core dumps surfaced in responses) are
  evidence, not trophies: capture, redact secrets, move on; do not retry
  "to see it again" beyond the D2 replay.
- Log-pollution awareness: mutated inputs land in target logs; keep the
  inventory for the `85` debrief.
- Everything runs inside the assessment container; nothing is uploaded
  anywhere.

