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
