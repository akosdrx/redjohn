---
name: cvss4_guide
description: CVSS 4.0 guide (from cve_exploit_intel specialist reference library)
---

# CVSS 4.0 guide

Vector field reference, worked construction examples, and the scoring
discipline this library follows. CVSS 4.0 communicates severity; it does not
rank risk and it is not a finding. The numeric score is ALWAYS produced by
the official FIRST CVSS 4.0 calculator (first.org/cvss/calculator/v4-0) —
this library never hand-computes a score for a report; `scripts/
cvss4_render.py` validates and documents vectors, and maps a supplied score
to its band.

## 1. Vector string format

```
CVSS:4.0/<base>/<threat>/<environmental>/<supplemental>
```

- Mandatory prefix: `CVSS:4.0/`.
- Base metrics come first, in canonical order:
  `AV:AC:AT:PR:UI:VC:VI:VA` then optional `SC:SI:SA` (omitted = N default).
- Threat (`E`), environmental (`CR IR AR MAV MAC MAT MPR MUI MVC MVI MVA MSC
  MSI MSA`), and supplemental (`S AU R V RE U`) groups follow in that order
  and are all optional.
- Fields are `ABBR:VALUE` joined by `/`; each metric appears at most once;
  no unknown abbreviations; values are case-sensitive as listed below.

Skeleton every card starts from:

```
CVSS:4.0/AV:?/AC:?/AT:?/PR:?/UI:?/VC:?/VI:?/VA:?
```

## 2. Field reference

### Base — exploitability

| Field | Values | Meaning |
|---|---|---|
| AV (Attack Vector) | N / A / L / P | N network-reachable across boundaries; A adjacent (same L2/VPN, Bluetooth-class); L local access or dependent session needed; P physical access needed |
| AC (Attack Complexity) | L / H | L beyond-normal effort only; H the attack must defeat mitigations or collect preceding information first |
| AT (Attack Requirements) | N / P | P = target-specific preconditions (winning a race, specific config, specific role, specific deployment mode) |
| PR (Privileges Required) | N / L / H | N none; L basic authenticated user; H administrative/privileged on the vulnerable system |
| UI (User Interaction) | N / P / A | N none; P passive (victim merely visits); A active (attacker must induce a specific action — CSRF-class) |

### Base — vulnerable system impact

| Field | Values | Meaning |
|---|---|---|
| VC / VI / VA | H / L / N | Confidentiality / Integrity / Availability impact on the vulnerable system: H total/serious, L limited, N none |

### Base — subsequent system impact

| Field | Values | Meaning |
|---|---|---|
| SC / SI / SA | H / L / N | Impact that crosses a trust boundary onto systems BEHIND/beyond the vulnerable system (SSRF -> internal services, RCE host -> pivot targets). Set only when the finding names the downstream system; default N |

### Threat metrics (contextual, optional)

| Field | Values | Meaning |
|---|---|---|
| E (Exploit Maturity) | X / A / P / U / N | X undefined (default); A attacked in the wild; P public PoC exists; U unreported; N none (fix available, no known exploitation). E:A needs evidence (in-wild reporting or in-engagement exploitation) |

### Environmental metrics (engagement context, optional)

| Field | Values | Meaning |
|---|---|---|
| CR / IR / AR | X / H / M / L | Mission weight of confidentiality/integrity/availability for THIS client deployment (H raises the impact weight — inverted intuition, operator input) |
| MAV / MAC / MAT / MPR / MUI | X + base values | Override the corresponding base metric for the engagement environment (X = defer to base) |
| MVC / MVI / MVA / MSC | X / H / L / N | Modified impact values |
| MSI / MSA | X / H / L / N / S | S = Safety — integrity/availability impact could directly cause physical harm (ICS/medical contexts); the only fields that take S |

### Supplemental metrics (reporting metadata, optional — do not change the score)

| Field | Values | Meaning |
|---|---|---|
| S (Safety) | P / N | P probable physical harm/death possible |
| AU (Automatable) | Y / N | Y no human interaction needed across the exploit chain (wormable-class) |
| R (Recovery) | A / U / I | A automated recovery; U user/manual; I irrecoverable |
| V (Value Density) | D / C | C concentrated (one target yields max payoff); D diffuse |
| RE (Response Effort) | L / M / H | Effort for the deployer to respond |
| U (Provider Urgency) | Red / Amber / Green / Clear | Vendor urgency label |

## 3. Severity bands

| Score | Band |
|---|---|
| 0.0 | None |
| 0.1 - 3.9 | Low |
| 4.0 - 6.9 | Medium |
| 7.0 - 8.9 | High |
| 9.0 - 10.0 | Critical |

## 4. Worked construction examples

Scores below were checked with the official FIRST calculator at authoring
time where a number is shown; re-verify at run time and record calculator +
date in the card.

- **Critical anchor (10.0)** — everything maximal:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H`.
  Real-world shape: an internet-facing, unauthenticated, weaponized RCE with
  downstream pivot, e.g. Log4Shell-class findings (CVE-2021-44228 — vector
  and score verifiable on NVD; verified against NVD at authoring time).
- **High band shape** — unauthenticated SSRF with proven internal reach:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N` when the
  fetch reaches named internal systems (SC raised by the downstream proof).
  Construction note: VC:L is what the fetch itself discloses; internal
  service compromise goes to SC/SI only with the downstream evidence.
- **Medium band shape** — reflected XSS requiring victim navigation (no CSP
  bypass proven):
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N` —
  UI:A because the attacker must induce the action; VI:L for session-bound
  integrity impact actually demonstrated.
- **Low band shape** — verbose error disclosure, no data returned:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`.
- **None anchor (0.0)** — all impacts N:
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N` — if you can construct
  this honestly, question whether there is a finding at all.

## 5. Scoring discipline rules

1. **Score with the official calculator.** The report carries vector + score
   + calculator + date. `cvss4_render.py` validates and documents; it never
   computes.
2. **When unsure, score LOWER and justify.** Torn between VC:H and VC:L
   because disclosure extent is unproven? Take L and write why. Conservative
   scores survive operator review; inflated ones do not.
3. **Impact from evidence only.** No "likely RCE" -> no VC:H/VI:H/VA:H
   without demonstrated execution (master §1). State the exact limit instead.
4. **E:A only with evidence** (CISA KEV entry, in-wild reporting, or
   in-engagement exploitation); otherwise E:X.
5. **SC/SI/SA name their system.** Subsequent-system impact without a named
   downstream target in the finding is inflation.
6. **AT:P for preconditions you actually needed** — races, specific roles,
   specific configurations; hiding preconditions in the narrative while
   scoring AT:N inflates the result.
7. **Environmental adjustments are engagement context, not defaults**:
   internet-facing vs internal (AV), the auth context the finding required
   (PR), client mission weight (CR/IR/AR) — all operator input, recorded as
   such. MSI:S / MSA:S only for real physical-harm contexts.
8. **Rescore on evidence change.** A D2 upgrade that demonstrates more
   impact than D1 claimed re-opens the vector; record both versions.

