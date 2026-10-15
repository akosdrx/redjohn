# Finding record template (field-by-field)

One record per deduplicated finding. This is the shape
`scripts/finding_format.py` validates and emits; the JSON contract for the
script is the machine-readable subset (id, title, severity, cwe, cvss,
component, version, tier, evidence, poc, remediation, detection — with
`description` optional in JSON but required in the delivered record).

Markdown shape emitted by the script (prose sections verbatim from input):

```markdown
## F-001 — SQL injection in invoice search via unparameterized q filter

| Field | Value |
|---|---|
| Severity | High (D3-locked) |
| CWE | CWE-89 |
| CVSS | CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N |
| Affected component | billing-api 2.4.1 (fingerprint tier 1) |
| Evidence | evidence/p5-api-invoices-003.req.txt; evidence/p5-api-invoices-003.resp.txt; evidence/p5-api-invoices-004.req.txt; evidence/p5-api-invoices-004.resp.txt |

**Description**

<prose>

**Proof of concept**

<rendered PoC per poc-rendering rules>

**Remediation**

<per-class guidance adapted to the stack>

**Detection coverage**

<note from 85>
```

## Field guidance

### id

- `F-NNN` (zero-padded three digits), assigned after deduplication, stable
  for the engagement. Never renumber after operator review; superseded ids
  are struck through (`~~F-007~~ merged into F-003`), never reused.
- The script warns (does not fail) on other shapes; fix before D4.

### title

- Pattern: `<class> in <component> via <mechanism>`.
  Example: "SQL injection in invoice search via unparameterized `q` filter".
- No severity words, no CVE ids in the title (the CVE lives in the CVSS/CWE
  row and the description), no marketing language. One line.

### severity

- One of `Critical`, `High`, `Medium`, `Low`, `Info` (the CVSS 4.0 bands;
  `Info` is reserved for observations without a CVSS vector, e.g. missing
  header hardening).
- **D3-locked**: drafts carry `proposed` next to the value until operator
  review; the delivered value changes only with a recorded operator sign-off.
- No severity without D3 lock — a report row without a lock mark fails gate 8.
- Downgrade-on-uncertainty: torn between two values -> the lower one, with
  the justification written in the description or CVSS row.

### cwe

- Canonical `CWE-<int>` + official name, chosen from
  `70-exploit-intel/references/cwe-mapping.md` (child over parent; mechanism
  over symptom; SSTI/crypto split rules). Include the mapping's one-line
  justification in the description or as a trailing sentence in the CWE row.
- One CWE per finding; chains file the chain head and describe steps in the
  impact narrative. Never invent an id.
- The script validates the `CWE-<int>` pattern only; the pick itself is `70`'s
  contract with the operator review.

### cvss

- CVSS 4.0 vector exactly as produced by `70` (`cvss4_render.py`-validated),
  plus the numeric score with its source and date:
  `score=8.7 (official FIRST CVSS 4.0 calculator, 2026-10-12)`.
- Impact metrics describe demonstrated impact only; SC/SI/SA only with a
  named downstream system; `E:A` only with evidence.
- The script validates the `CVSS:4` prefix; scoring discipline lives in `70`.

### component / version / tier

- Component name and version from the `10` fingerprint row; tier is that
  row's confidence tier (1 exact / 2 banner / 3 banner+behavior / 4 source).
- CVE-bearing findings require tier <= 2 (per `70`); tier 3/4 findings are
  re-fingerprinted before any CVE claim enters the record.
- Config/logic findings not tied to a versioned component use
  `n/a` for version and tier (the script accepts both).

### description

- What (the flaw), where (endpoint/parameter/file), why (root cause), and
  the demonstrated impact with its exact limits. No "likely RCE": either
  execution was demonstrated (D2 evidence cited) or the limits are stated.
- Instance lists for deduplicated findings: enumerate the affected
  endpoints/parameters after the main narrative, each with its evidence refs.

### evidence

- File names only, per `evidence-gates.md` naming, never pasted bodies:
  `evidence/<phase>-<surface>-<seq>.<req|resp>.txt`.
- D2 requires BOTH runs' pairs — cite all four files (two req, two resp) or
  the run-note reference that holds the second pair.
- Keep the capture phase in the name (do not rename p4/p5 evidence to p9);
  assembly artifacts are the only `p9-*` files.

### poc

- Rendered per the SKILL.md PoC rules: minimal curl one-liner (or raw HTTP
  block when verbatim headers matter), environment preconditions (auth
  context label, state setup, tool versions), and the negative control —
  same request without the payload / with the other role's token.
- Canary strings `rj-pt-<engagement>-<nonce>`; impact proofs limited to
  `id`/`whoami`/`hostname`/canary echo; no reverse shells.
- Redacted before D4: `Bearer <session-token>`, `user-a@example.com`
  placeholders; the replay-verified runs are the pre-redaction pairs.

### remediation

- Start from `remediation-library.md` for the class, then adapt to the
  engagement stack (framework, language, deployment). Where a short-term
  mitigation and a proper fix both exist, write both and label them
  ("Short-term:", "Proper fix:").
- Code-level and concrete: exact headers, exact parameters, exact queries —
  not "validate input properly".

### detection

- The note from `85-logging-monitoring` for this finding: was the probe
  visible in the target's logs (which log/source), was any alert raised,
  what gap remains. Gaps feed the detection-coverage table and the
  hardening recommendations.
- Never guess what was logged: if `85` produced no note for the finding,
  the record says "not assessed" — that is a coverage-statement fact, not a
  placeholder to fill with prose.
