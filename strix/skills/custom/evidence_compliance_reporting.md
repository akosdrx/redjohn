---
name: evidence_compliance_reporting
description: Use when verified findings must become deliverables - rendering minimal
  reproducible PoCs as curl commands or raw HTTP, writing code-level remediation per
  vulnerability class, locking CWE and CVSS classification, deduplicating findings,
  and assembling the final report with detection-coverage notes.
---

# Evidence and reporting (P9)

The last mile: dedupe, render, classify, redact, assemble. No new probing
happens here — everything in the report is already evidenced; assembly
and quality-gating are the work.

## The way

- Dedupe rule: same root cause + same component = one finding with an
  instance list; independent sinks stay separate. Stable `F-NNN` ids,
  never renumbered after operator review.
- The finding record is a contract the validator enforces: D2 pairs
  cited by file name, D3 mark, canonical CWE, CVSS vector + score,
  remediation, detection note. `[gap]` markers make missing pieces loud
  instead of silent.
- PoC rendering: the smallest reproducing request, preconditions + the
  negative control inline, raw HTTP only when verbatim headers matter.
  Redaction before D4 — originals stay in the namespace.
- Severity: vectors from `70`, scores from the official calculator,
  downgrade-on-uncertainty, and no locked severity without D3.
- The report's credibility lives in the coverage statement: what was
  tested, what wasn't, degraded modes, negative results. Exec-summary
  counts must match the technical section exactly.
- Negative routing: a new probe, an impact upgrade or a re-score goes
  back to the owning skill — assembly is not where discoveries happen.
- Compliance mapping: cross-walk canonical CWEs to ISO/IEC 27001:2022,
  NIST CSF 2.0, CIS Controls v8.1, and OWASP Top 10 via `--compliance`.

## Handoffs

Consumes `10`-`85` (findings, cards, detection notes, D3 marks); feeds
D4 delivery via the operator channel and memory drafts (operator
reviewed, engagement-namespaced).

## Tools

`poc_render.py`, `finding_format.py` (offline, execute nothing — replay
belongs to `20` inside scope). Finding template, compliance mapping,
remediation library and report skeleton in `references/`.

---

## Reference Module: `compliance-mapping`

# Compliance Framework Cross-Walk Mapping

Canonical mapping reference linking Common Weakness Enumerations (CWEs) to
enterprise compliance standards:
- **ISO/IEC 27001:2022 Annex A** (specifically Section A.5 Organizational & Section A.8 Technological Controls)
- **NIST Cybersecurity Framework (CSF) 2.0**
- **Center for Internet Security (CIS) Critical Security Controls v8.1**
- **OWASP Top 10 (2021)** & **OWASP API Security Top 10 (2023)**

Used by `finding_format.py --compliance` to decorate finding deliverables with
auditable compliance citations.

---

## 1. Canonical Mapping Matrix

| Vulnerability Class & Common CWEs | ISO/IEC 27001:2022 Annex A | NIST CSF 2.0 Subcategories | CIS Controls v8.1 Safeguards | OWASP Top 10 (2021 / API 2023) |
|---|---|---|---|---|
| **Broken Access Control & IDOR**<br>`CWE-22`, `CWE-284`, `CWE-639`, `CWE-862` | **A.5.15** (Access control)<br>**A.8.2** (Privileged access)<br>**A.8.3** (Information access restriction)<br>**A.8.20** (Network security)<br>**A.8.24** (Use of cryptography)<br>**A.8.28** (Secure coding) | **PR.AA-01** (Identities/credentials managed)<br>**PR.AA-05** (Access permissions enforced)<br>**PR.DS-01** (Data protection)<br>**PR.PS-01** (Configuration maintenance) | **Control 3** (3.3: Data protection)<br>**Control 6** (6.8: Central access control)<br>**Control 16** (16.3: Data protection, 16.10: Secure application architecture) | `A01:2021` (Broken Access Control)<br>`API1:2023` (BOLA)<br>`API5:2023` (BFLA) |
| **Cryptographic & TLS Failures**<br>`CWE-327`, `CWE-319`, `CWE-347`, `CWE-295` | **A.8.24** (Use of cryptography) | **PR.DS-01** (Data-at-rest protected)<br>**PR.DS-02** (Data-in-transit protected) | **Control 3** (3.10: Encrypt sensitive data in transit, 3.11: Encrypt data at rest) | `A02:2021` (Cryptographic Failures)<br>`API2:2023` (Broken Authentication) |
| **Injection (SQLi / Command / SSTI / Code)**<br>`CWE-89`, `CWE-78`, `CWE-1336`, `CWE-94` | **A.8.26** (Application security requirements)<br>**A.8.28** (Secure coding) | **PR.PS-01** (Configuration maintenance)<br>**DE.CM-01** (Networks/systems monitored) | **Control 16** (16.12: Sanitize inputs, 16.13: Root-cause vulnerability defense) | `A03:2021` (Injection)<br>`API8:2023` (Security Misconfiguration) |
| **Insecure Design & Business Logic**<br>`CWE-840`, `CWE-362`, `CWE-670` | **A.8.26** (Application security requirements)<br>**A.8.28** (Secure coding) | **PR.AA-05** (Access permissions enforced)<br>**PR.IR-02** (System resilience maintained) | **Control 16** (16.10: Application architecture, 16.13: Vulnerability mitigation) | `A04:2021` (Insecure Design)<br>`API6:2023` (Unrestricted Flow Access) |
| **Security Misconfiguration & WAF / Origin**<br>`CWE-16`, `CWE-942`, `CWE-693`, `CWE-200` | **A.8.9** (Configuration management)<br>**A.8.20** (Network security)<br>**A.8.21** (Security of network services) | **PR.PS-01** (Configuration baseline)<br>**PR.IR-01** (Network infrastructure resilient) | **Control 4** (4.1: Secure configuration baseline, 4.8: Manage default accounts)<br>**Control 13** (13.4: Boundary proxy/firewall) | `A05:2021` (Security Misconfiguration)<br>`API8:2023` (Security Misconfiguration) |
| **Vulnerable & Outdated Components**<br>`CWE-1104`, `CWE-1395` | **A.8.8** (Management of technical vulnerabilities) | **PR.PS-02** (Software updated/patched)<br>**ID.AM-02** (Software inventory maintained) | **Control 7** (7.1: Vulnerability management, 7.7: Remediate vulnerabilities)<br>**Control 16** (16.4: Component inventory) | `A06:2021` (Vulnerable Components)<br>`API9:2023` (Improper Inventory) |
| **Authentication, MFA & Session Failures**<br>`CWE-287`, `CWE-307`, `CWE-294`, `CWE-384`, `CWE-613` | **A.5.15** (Access control)<br>**A.8.5** (Secure authentication)<br>**A.8.26** (Application security requirements) | **PR.AA-01** (Credential management)<br>**PR.AA-03** (Users/devices authenticated, MFA)<br>**DE.CM-03** (Personnel activity monitored) | **Control 5** (5.1: Inventory accounts, 5.4: Centralize auth)<br>**Control 6** (6.3: Multi-factor authentication, 6.5: Lockout/rate limits) | `A07:2021` (Identification & Auth Failures)<br>`API2:2023` (Broken Authentication) |
| **Software & Data Integrity / Deserialization**<br>`CWE-502`, `CWE-494`, `CWE-829` | **A.8.26** (Application security requirements)<br>**A.8.28** (Secure coding) | **PR.PS-01** (Configuration maintenance)<br>**PR.DS-10** (Data integrity verified) | **Control 16** (16.4: Third-party component vetting, 16.13: Defensive coding) | `A08:2021` (Software & Data Integrity Failures)<br>`API8:2023` (Security Misconfiguration) |
| **Security Logging & Telemetry Gaps**<br>`CWE-778`, `CWE-117`, `CWE-532` | **A.8.15** (Logging)<br>**A.8.16** (Monitoring activities) | **PR.PS-04** (Log records generated)<br>**DE.CM-01** (Networks/systems monitored)<br>**DE.CM-09** (Activity baseline monitored) | **Control 8** (8.2: Audit logs collected, 8.5: Central log repository, 8.9: Log retention)<br>**Control 13** (13.1: Centralize alert monitoring) | `A09:2021` (Security Logging & Monitoring Failures)<br>`API10:2023` (Unsafe API Consumption) |
| **Server-Side Request Forgery (SSRF)**<br>`CWE-918` | **A.8.20** (Network security)<br>**A.8.26** (Application security requirements)<br>**A.8.28** (Secure coding) | **PR.PS-01** (Configuration maintenance)<br>**PR.AA-05** (Access permissions enforced) | **Control 13** (13.4: Boundary firewall/proxy)<br>**Control 16** (16.10: Secure application architecture) | `A10:2021` (SSRF)<br>`API7:2023` (Server-Side Request Forgery) |
| **Cross-Site Scripting (XSS)**<br>`CWE-79` | **A.8.26** (Application security requirements)<br>**A.8.28** (Secure coding) | **PR.PS-01** (Configuration maintenance)<br>**DE.CM-01** (Monitoring anomalous activity) | **Control 16** (16.12: Sanitize and encode inputs/outputs) | `A03:2021` (Injection)<br>`API8:2023` (Security Misconfiguration) |
| **Cross-Site Request Forgery (CSRF)**<br>`CWE-352` | **A.8.26** (Application security requirements) | **PR.AA-05** (Access permissions enforced)<br>**PR.PS-01** (Configuration maintenance) | **Control 16** (16.10: Secure application architecture) | `A01:2021` (Broken Access Control)<br>`API1:2023` (BOLA) |

---

## 2. Framework Detailed Reference

### 2.1 ISO/IEC 27001:2022 Annex A
- **A.5.15 Access control:** Rules to control physical and logical access to information and other associated assets based on business and information security requirements.
- **A.8.2 Privileged access rights:** Allocation and use of privileged access rights restricted and managed.
- **A.8.3 Information access restriction:** Access to information and application system functions restricted in accordance with the access control policy.
- **A.8.5 Secure authentication:** Secure authentication technologies and procedures established based on information access restrictions and system access policies.
- **A.8.8 Management of technical vulnerabilities:** Information about technical vulnerabilities obtained in a timely manner, exposure evaluated, and appropriate measures taken.
- **A.8.9 Configuration management:** Configurations (including security configurations) of hardware, software, services, and networks established, documented, implemented, monitored, and reviewed.
- **A.8.15 Logging:** Logs recording activities, exceptions, faults, and other relevant events produced, kept, protected, and analyzed.
- **A.8.16 Monitoring activities:** Networks, systems, and applications monitored for anomalous behavior and appropriate actions taken to evaluate potential security incidents.
- **A.8.20 Network security:** Networks and network devices secured, managed, and controlled to protect information in systems and applications.
- **A.8.21 Security of network services:** Security mechanisms, service levels, and service requirements of network services identified, implemented, and monitored.
- **A.8.24 Use of cryptography:** Rules for the effective use of cryptography (including cryptographic key management) defined and implemented.
- **A.8.26 Application security requirements:** Information security requirements identified, specified, and approved when developing or acquiring applications.
- **A.8.28 Secure coding:** Secure coding principles applied to software development.

### 2.2 NIST Cybersecurity Framework (CSF) 2.0
- **PR.AA (Identity Management, Authentication, and Access Control):** Access to physical and logical assets is limited to authorized users, services, and hardware.
- **PR.DS (Data Security):** Data is managed consistent with the organization's risk strategy to protect confidentiality, integrity, and availability.
- **PR.PS (Platform Security):** The hardware, software, and services of physical and virtual platforms are managed consistent with the organization's risk strategy.
- **PR.IR (Technology Infrastructure Resilience):** Security architectures are managed with the organization's risk strategy to protect asset availability and integrity.
- **DE.CM (Continuous Monitoring):** Assets are monitored to find anomalies, indicators of compromise, and other potentially adverse events.

### 2.3 CIS Critical Security Controls v8.1
- **Control 3 (Data Protection):** Develop processes and technical controls to identify, classify, securely handle, retain, and dispose of data.
- **Control 5 (Account Management):** Use processes and tools to assign and manage authorization to credentials for user accounts.
- **Control 6 (Access Control Management):** Use processes and tools to create, assign, manage, and revoke access credentials and privileges.
- **Control 7 (Continuous Vulnerability Management):** Develop a plan to continuously assess and track vulnerabilities on all enterprise assets.
- **Control 8 (Audit Log Management):** Collect, alert, review, and retain audit logs of events that could help detect, understand, or recover from an attack.
- **Control 13 (Network Monitoring and Defense):** Operate processes and tooling to establish and maintain comprehensive network monitoring and defense.
- **Control 16 (Application Software Security):** Manage the security life cycle of in-house developed, hosted, or acquired software.

### 2.4 OWASP Top 10 (2021) & API Security Top 10 (2023)
- **A01:2021-Broken Access Control** / **API1:2023 Broken Object Level Authorization (BOLA)** / **API5:2023 Broken Function Level Authorization (BFLA)**
- **A02:2021-Cryptographic Failures** / **API2:2023 Broken Authentication**
- **A03:2021-Injection**
- **A04:2021-Insecure Design** / **API6:2023 Unrestricted Access to Sensitive Business Flows**
- **A05:2021-Security Misconfiguration** / **API8:2023 Security Misconfiguration**
- **A06:2021-Vulnerable and Outdated Components** / **API9:2023 Improper Inventory Management**
- **A07:2021-Identification and Authentication Failures**
- **A08:2021-Software and Data Integrity Failures**
- **A09:2021-Security Logging and Monitoring Failures** / **API10:2023 Unsafe Consumption of APIs**
- **A10:2021-Server-Side Request Forgery (SSRF)** / **API7:2023 Server-Side Request Forgery**


---

## Reference Module: `finding-template`

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


---

## Reference Module: `remediation-library`

# Remediation library (per-class, code-level)

Concise, code-level remediation guidance per vulnerability class, generic
technology only. Start from the class section, then adapt to the engagement
stack; verify version-dependent advice (SameSite defaults, TLS cipher
availability, framework APIs) against the deployed stack before D4. Where a
short-term mitigation and a proper fix both exist, write both, labeled.

## SQL injection (CWE-89 / NoSQL CWE-943 / LDAP CWE-90)

Proper fix — parameterized queries; the driver binds, the SQL text never sees
data:

```
-- vulnerable:  SELECT name FROM invoices WHERE cust = '%s' % cust
-- fixed:       SELECT name FROM invoices WHERE cust = ?
-- bind:        execute(sql, (cust,))
```

ORM binding, same rule (placeholders, never string interpolation):

```
# vulnerable: session.query(Invoice).filter("cust = '%s'" % cust)
# fixed:      session.query(Invoice).filter(Invoice.cust == cust)
```

- Identifiers (column/table names) cannot be bound — use a server-side
  allowlist mapping, never client input.
- `LIKE` user input: bind the value, escape `%`/`_` in the bound value.
- NoSQL: reject operator shapes at the parser boundary (accept scalars only);
  LDAP: encode filter metacharacters with the RFC 4515 escaping routine.
- Short-term: input validation + WAF rule (bypassable; never the fix).

## XSS (CWE-79)

Context-aware output encoding — encode for the context the data lands in:

| Target context | Encoding | Notes |
|---|---|---|
| HTML body / between tags | HTML-entity encode `< > & " '` | Default context |
| HTML attribute (quoted) | HTML-entity encode incl. `"` `'`; attribute must be quoted | Unquoted attributes reject outright |
| JavaScript string literal | JavaScript unicode escapes (`\u003c` style) + encode quotes/newlines; JSON-serialize where possible | Never place raw data in a `<script>` block |
| URL / query parameter | percent-encoding per component (scheme/host/path/query each per spec) | Validate scheme against an allowlist (`http`, `https`) for `href`/`src` |
| CSS (rare) | CSS escapes for non-identifier positions; preferably no user data in CSS at all | `expression()`-class sinks are disallowed |

- Auto-escaping template engines cover the HTML body context only — the table
  above applies the moment data crosses into attributes/scripts/URLs.
- Stored XSS: sanitize on input with an HTML allowlist sanitizer only where
  rich text is a product requirement; otherwise encode on output.
- Add a Content-Security-Policy as defense in depth, not as the fix.

## SSRF (CWE-918)

Allowlist fetch + DNS pinning + metadata blocking:

```
allow_hosts = {"api.partner.example"}          # exact names, config-owned
url = parse(input)
if url.scheme not in ("https",): reject
if url.host not in allow_hosts: reject
addr = resolve_once(url.host)                  # pin: resolve ONE time
if addr is loopback/private/link-local/unique-local: reject
if addr in metadata_ranges: reject             # 169.254.169.254 etc.
fetch(url, connect_to=addr)                    # connect to the resolved IP
```

- Resolve once and connect to that address (DNS rebinding defeats
  resolve-then-check-then-re-resolve).
- Redirects: do not auto-follow; validate each hop against the same rules.
- Block cloud metadata and link-local ranges unconditionally, even behind the
  allowlist.
- Do not render the raw response body to the requester unless the allowlisted
  origin is public anyway.

## CSRF (CWE-352)

Token + SameSite:

- Per-session (or per-request) cryptographically random anti-CSRF token,
  verified server-side on every state-changing request; token never in URLs.
- Cookies: `SameSite=Lax` minimum for session cookies (`Strict` where the
  flow allows), plus `Secure` and `HttpOnly`.
- Where the product is an API consumed by scripts: prefer
  `Authorization: Bearer` headers (not cookies) or double-submit tokens over
  custom header checks alone.
- Verify `Origin`/`Referer` as an additional signal, never as the only one.
- State changes require an explicit method semantics check: no `GET`
  side effects.

## Insecure deserialization (CWE-502)

- Avoid serialized formats (Java/PHP/Python pickle/Node binary) in
  untrusted channels — use JSON with a strict schema.
- If a serialized format is unavoidable: HMAC/integrity-check the blob with a
  server-side key before parsing, restrict to a type allowlist, parse in a
  sandboxed subprocess with no network and a dropped privileges account.
- Never feed signed-but-attacker-influenced structure parsers raw bytes;
  integrity must cover the whole blob.

## Dangerous file upload (CWE-434)

Extension + content validation + storage isolation:

- Extension allowlist by purpose (e.g. `.jpg .png .pdf`), deny-by-default.
- Content validation: check magic bytes AND re-encode (images through a
  real decoder/re-encoder; documents through a sanitizer when available).
- Storage isolation: object store or separate media domain, random
  generated filenames, no execute permissions, served with
  `Content-Disposition: attachment` and a correct `Content-Type`,
  `X-Content-Type-Options: nosniff`.
- Size and rate limits; never keep the user-supplied filename on disk.

## Broken access control (CWE-862/863/639)

Centralized per-object authorization — deny by default, check at the data
layer, not in a route decorator alone:

```
def get_invoice(inv_id, actor):
    inv = db.fetch(Invoice, inv_id)      # 404 on miss
    if actor.tenant_id != inv.tenant_id: # object-level, every object
        deny()                            # 403, logged
    if not policy(actor.role, "invoice:read"):
        deny()
    return inv
```

- One authz module every handler calls; no per-endpoint ad-hoc role checks.
- Prefer non-sequential ids (UUID) but never as the only control —
  authorization is the control, unguessability is hardening.
- Deny-by-default routing: new endpoints require an explicit authz decision.
- Log denials (feeds the detection-coverage table).

## Cryptographic failures (CWE-326/327)

- Password storage: Argon2id (memory >= 19 MiB, 2 iterations, parallelism 1)
  or scrypt (N=2^17, r=8, p=1) or bcrypt (cost >= 12); unique salt per
  password; never MD5/SHA-1/SHA-256-alone for passwords.
- TLS: 1.2+ only (prefer 1.3), forward-secret cipher suites, no RC4/3DES/NULL,
  certificates with RSA >= 2048 or ECDSA >= 256, no SHA-1 signatures.
- Symmetric encryption: AEAD (AES-GCM, ChaCha20-Poly1305) with unique
  nonces; no ECB, no static IVs; random keys from a CSPRNG, rotation
  supported.
- Secrets: no hardcoded keys (CWE-798); secret manager or scoped env
  injection; keys never in logs.

## Headers / CORS (misconfiguration class)

Exact header configurations:

```
Strict-Transport-Security: max-age=63072000; includeSubDomains
Content-Security-Policy: default-src 'self'; object-src 'none';
                         frame-ancestors 'none'; base-uri 'self'
X-Content-Type-Options: nosniff
Referrer-Policy: strict-origin-when-cross-origin
Cache-Control: no-store          # on authenticated responses
```

- CORS: exact-origin allowlist (`Access-Control-Allow-Origin:
  https://app.example`), never `*` together with
  `Access-Control-Allow-Credentials: true`; validate the `Origin` header
  against the allowlist per request; do not reflect arbitrary origins.
- Cookie attributes: `Secure; HttpOnly; SameSite=Lax` (or `Strict`).
- Remove verbose/framework banners where the platform allows; that is
  hardening, not a fix for anything by itself.

## Race conditions (CWE-362/367)

Locking + idempotency keys:

- Serialize the check-then-act unit: per-key mutex in-process, or
  `SELECT ... FOR UPDATE` / conditional `UPDATE ... WHERE balance >= ?`
  in the database, so the guard and the mutation are one atomic step
  (kills TOCTOU windows on shared rows).
- Idempotency keys for payment/creation endpoints: client supplies a unique
  key; server returns the stored result on replay instead of re-executing.
- Atomic counters only (`DECR`-style guarded updates), never read-modify-write
  in application code on shared state.

## Business logic flaws (state machine / price/flow manipulation)

- State machine validation: explicit states + an allowed-transitions table
  checked server-side on every mutation; reject out-of-table transitions
  with a logged error.

```
transitions = {
  ("created", "paid"): pay_invoice,
  ("paid", "shipped"): ship,
  # no ("created", "shipped"), no return to "created"
}
```

- Server-side price/total recomputation always; client totals are display
  data. Validate quantity signs/ranges against per-role limits.
- One-time consumables (coupons, credits) decrement atomically (see race
  section); re-verification after any external step.

## Logging / monitoring gaps (feeds the detection-coverage table)

- Event coverage: authentication successes/failures, authorization denials,
  input-validation rejections, administrative actions, file upload/download,
  integrity failures — each with actor, object, source IP, timestamp.
- Redaction by design: never log full tokens, passwords, cookies, or PII
  payloads; log token prefixes/ids instead; redact at the serializer, not by
  sweeping logs later.
- Alerting: threshold alerts on auth-failure bursts, authz-denial spikes,
  and canary-pattern hits; alerts reference the runbook entry.
- Log integrity: append-only or shipped off-host; injection-safe encoding of
  logged values (newlines/CRLF stripped) so records cannot be forged.


---

## Reference Module: `report-structure`

# Report structure (section-by-section skeleton)

The delivered report is assembled in this order. Everything lives in the
engagement namespace until the redaction pass; only the redacted copy leaves
(via the operator-approved channel).

## 1. Engagement metadata (title block)

- Engagement namespace/id, scope summary (hosts/ranges from the scope file,
  not the raw file itself), test window dates, operator, methodology
  reference: `00-master-pentest-methodology` (name it in the appendix too).
- Classification/handling marking if the engagement requires one.

## 2. Executive summary

Requirements (gate 8 enforces):

- **Counts by severity** — a table of Critical/High/Medium/Low/Info counts
  that matches the technical section exactly. Recount after every edit;
  a mismatched summary fails delivery.
- **Top risks in plain language** — the 3-5 findings that matter most,
  described without jargon: what an attacker could do, what business asset
  is exposed, one sentence each. No CVSS vectors, no CWE ids here.
- Scope and dates restated; degraded coverage named up front (e.g.
  "authentication flows were tested with a single account role, so
  cross-tenant access issues are only partially covered").
- Nothing in the summary may be stronger than the evidence: same
  demonstrated-impact discipline as the finding records.

## 3. Technical findings

- Ordered by severity: Critical -> High -> Medium -> Low -> Info; within a
  band, by component then id.
- Each finding is one record per `finding-template.md` (emitted shape of
  `scripts/finding_format.py`): metadata table (severity D3-locked, CWE,
  CVSS, component/version/tier, evidence refs) then Description, Proof of
  concept, Remediation, Detection coverage prose.
- Deduplicated per SKILL.md section 2: one root cause + one component = one
  finding with an instance list; instance evidence refs inline.
- Superseded/merged ids appear struck through in the appendix index only,
  never as live rows.

## 4. Detection coverage (from 85)

A table, one row per finding class (not per instance):

| Finding class | Logged? | Alerted? | Log source | Gap / recommendation |
|---|---|---|---|---|
| SQL injection attempts | yes (app log) | no | app.log input-rejection events | add alert on rejection bursts |
| Authz denials (IDOR probes) | no | no | — | log object-level denials with actor+object |

- Content comes from the `85-logging-monitoring` notes only — no guessing
  what the blue side saw. "Not assessed" is a valid, honest row.
- Gaps become hardening recommendations with owners if the operator wants
  them tracked.

## 5. Coverage statement

What was tested, per skill/phase — including what was NOT:

- Per phase (P1-P9): surfaces covered, techniques run, and the negative
  results worth recording (e.g. "three probe generations on GraphQL
  mutations without signal — logged, moved on", per the dead-end rule).
- Degraded modes stated explicitly: single-auth-context engagements say
  IDOR/BOLA coverage is partial (dispatch-map negative routing); missing
  OOB listener says blind classes are unverified; time-budget cuts list
  which P6+ surfaces were dropped after half-budget.
- Out-of-scope observations: assets discovered but not tested, recorded as
  observations with no vulnerability claims.
- Tool coverage notes: which scanners/sources returned nothing (a dated
  "no CVE matched as of YYYY-MM-DD, sources 1-5" statement is a result).

## 6. Appendices

- **Methodology**: reference `00-master-pentest-methodology` by name and the
  phase machine; state gate discipline (D2 entry, D3 validation before
  delivery).
- **Evidence index**: file names of the evidence pairs backing each finding
  (redacted copies), grouped by finding id. No bodies inline.
- **Finding id history**: superseded/merged ids and what absorbed them.
- **Tooling**: tools and versions used per phase (assessment container CLIs,
  script names from this library).
- **Memory drafts register**: lessons proposed as drafts (class, tool note),
  tagged with the engagement namespace, pending independent review — listed
  here so promotion is auditable; the drafts themselves stay in the
  engagement namespace.

## Assembly checklist (maps to SKILL.md section 8)

1. Dedupe done, ids stable, no `[gap]` markers.
2. Every record validated through `scripts/finding_format.py` (exit 0).
3. Every PoC rendered through `scripts/poc_render.py` discipline:
   preconditions, negative control, redaction warnings resolved.
4. Detection table rows backed by `85` notes.
5. Coverage statement includes negative results and degraded modes.
6. Redaction sweep recorded; exec summary counts recounted from the
   technical section; stop-condition audit clean.

