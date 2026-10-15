---
name: oracle_stack_security
description: Use when fingerprinting identifies Oracle technology in scope - TNS listener
  enumeration, WebLogic console, management & async servlets, Oracle APEX/ORDS, EBS
  DMZ URL firewall auditing (MOS Doc 1387859.1), and Oracle Critical Patch Update
  (CPU) advisory correlation by version.
---

# Oracle stack (P8)

The fingerprint-and-check layer for Oracle DB, WebLogic, APEX, and E-Business
Suite. Exploitation goes to `45`, CVE claims to `70` — this skill pins
versions and checks posture, read-only by default.

## The way

- Observe first, query second, never mutate: TNS VERSION/STATUS/SERVICES,
  APEX/ORDS version files, and WebLogic/EBS GETs. Mutating listener commands
  are out of scope here, full stop.
- Check APEX version disclosure (`/i/apex_version.txt`), WebLogic REST management
  and async servlets, and EBS DMZ URL firewall restrictions (MOS Doc 1387859.1).
- Account candidates are *names* only; passwords come from the operator,
  bounded attempts — failed-login counters and audit rows are real
  impact. One working login means read-only session state, not sweeps.
- With a session, the grant matrix is the finding (privileges, role
  grants, UTL_*/DBMS_* executability): record it, never escalate it.
- WebLogic order is binding: fingerprint -> `70` CPU correlation -> only
  then a documented PoC via `45`. "T3 open" is a finding row by itself;
  serialized objects are never sent from this skill.
- The WAR-deployment RCE path exists only with operator credentials plus
  written approval: benign artifact, full undeploy cleanup.
- Oracle correlation is release + patch level — a bare banner cannot
  prove patch level, so the caveat ships with the claim.

## Handoffs

Versions + banners (tier <= 2) -> `70` with the CPU reading rules in
`references/`; PoC attempts -> `45`; working creds -> `30` and `85` (did
the login fire an audit event?).

## Tools

`oracle_surface_probe.py` (guarded). SID/account-name tables, APEX and EBS DMZ
checklists, and the CVE-family context (verify-at-authoring marks) in `references/`.

---

## Reference Module: `oracle-apex-ebs-surface`

# Oracle APEX, WebLogic Management & EBS DMZ Surface Reference

Detailed operational guidance for assessing Oracle Application Express (APEX),
Oracle REST Data Services (ORDS), WebLogic REST/Async servlets, and Oracle
E-Business Suite (EBS) DMZ deployments.

---

## 1. Oracle Application Express (APEX) & ORDS Auditing

Oracle APEX runs on top of the Oracle Database, typically exposed via Oracle
REST Data Services (ORDS) running standalone or deployed within WebLogic/Tomcat.

### 1.1 Read-Only Version Extraction & Admin Probing

| Endpoint | Method | Expected Artifact / Disclosure | Tier |
|---|---|---|---|
| `/i/apex_version.txt` | GET | Plain text disclosing exact APEX release (e.g. `Application Express 22.1.0.00.01` or `Application Express 23.2.0.00.05`) | Tier 1 |
| `/ords/apex_admin` | GET | APEX Internal Administration Services login console (`admin` user context) | Tier 2 |
| `/ords/f?p=4550:1` | GET | APEX Internal Workspace developer login page | Tier 2 |
| `/ords/f?p=4550:10` | GET | APEX Workspace Administrator login | Tier 2 |
| `/ords/_/db-api/stable/` | GET | ORDS Database Management REST API metadata | Tier 2 |

### 1.2 Auditing Procedures & Security Posture Checks
- **Version Disclosing Static Assets:** Request `/i/apex_version.txt`. If present, record the exact version string and map to Oracle Critical Patch Update (CPU) advisories via `70-exploit-intel`.
- **Exposed Administrative Interfaces:** Exposure of `/ords/apex_admin` or `/ords/f?p=4550:1` to untrusted networks violates defense-in-depth. Verify whether administrative interfaces require VPN/internal IP restriction.
- **ORDS Public REST Services:** Inspect whether custom REST handlers published via ORDS allow unauthenticated query execution (`/ords/<schema>/...`) without proper authorization callbacks.

---

## 2. WebLogic Management & Async Servlets

Beyond the standard WebLogic administration console (`/console`), modern WebLogic
installations expose RESTful management interfaces and web service async endpoints.

### 2.1 WebLogic REST Management & Async Path Checklist

| Endpoint | Method | Purpose / Historical Advisory | Notes |
|---|---|---|---|
| `/management/tenant-monitoring/servers` | GET | WebLogic REST Management API for server monitoring | Unauthenticated access leaks domain structure, server names, cluster configuration, and health states |
| `/_async/AsyncResponseService` | GET | WebLogic asynchronous web service callback handler | Endpoint for `wls9_async` components; associated with deserialization surfaces (CVE-2019-2725 / CVE-2019-2729) |
| `/wls-wsat/CoordinatorPortType` | GET | WebLogic Web Services Atomic Transactions (WS-AT) | Historical XML deserialization attack surface (CVE-2017-10271) |

### 2.2 Auditing Heuristics
- An HTTP 200 or 403 on `/_async/AsyncResponseService` or `/wls-wsat/CoordinatorPortType` proves the component is deployed and reachable at the network layer.
- Never send test serialized XML or Java objects during initial surface probing; record presence as Tier 2 and hand off to `70` for CPU version correlation.

---

## 3. Oracle E-Business Suite (EBS) DMZ Servlet Auditing (MOS Doc 1387859.1)

Oracle My Oracle Support (MOS) Document **1387859.1** ("Oracle E-Business Suite
Release 12.1 and 12.2 Configuration in a Demilitarized Zone") defines the
mandatory reverse-proxy URL firewall configuration for internet-facing EBS nodes.

### 3.1 Architecture of an EBS DMZ Node
- In an EBS DMZ architecture, an external web tier node handles public-facing
  products (e.g. iStore, iSupplier, iRecruitment).
- Back-office administration, financial workflows, and internal uploaders must
  be strictly blocked at the web tier / reverse proxy level.
- When the URL firewall is misconfigured or bypassed, privileged internal servlets
  become exposed to internet attackers.

### 3.2 Blocked Internal Servlet Checklist (MOS Doc 1387859.1)

| Blocked Path | Component | Impact If Exposed on DMZ |
|---|---|---|
| `/OA_HTML/BneUploaderService` | Oracle Web ADI (Applications Desktop Integrator) | Unauthenticated desktop integration servlet; historical SQL injection and file upload surfaces |
| `/OA_HTML/OA.jsp` | Oracle Application Framework runtime | Core OA Framework execution engine; exposes back-office transaction screens and functions |
| `/OA_HTML/cabo/*` | Oracle Cabo UI component library | Internal presentation libraries; version disclosure and resource enumeration |
| `/OA_HTML/oam/*` | Oracle Applications Manager (OAM) | Administrative management interfaces |
| `/OA_HTML/AppsLocalLogin.jsp` | Local EBS login interface | Allows bypassing external SSO/SAML integration to attempt direct database authentication |

### 3.3 Verification Procedure
1. Request `/OA_HTML/BneUploaderService` with a benign read-only GET.
2. If the response returns HTTP 200 or specific Web ADI XML service responses instead of 403/404, document as an **EBS DMZ URL Firewall Misconfiguration** (violation of MOS Doc 1387859.1).
3. Record headers and responses in `evidence/p8-oracle-ebs-dmz-<host>.{req,resp}.txt`.


---

## Reference Module: `oracle-cpu-cadence`

# Oracle CPU cadence and correlation

How Oracle Critical Patch Update (CPU) advisories are organized, and the exact
procedure for correlating a pinned Oracle version to advisory rows through
`70-exploit-intel`.

## 1. Cadence and structure

- Oracle CPUs publish quarterly: January, April, July, October (verify the
  current publication-day convention — historically the Tuesday closest to
  the 17th — against oracle.com/security at authoring time).
- Each CPU advisory ("Oracle Critical Patch Update Advisory <Month> <Year>")
  contains per-product risk matrices: Oracle Database, Fusion Middleware
  (WebLogic lives here), E-Business Suite, Java SE, etc.
- Each matrix row: affected product component, CVE id, CVSS base score,
  attack vector/complexity, affected versions and patch levels, and the
  package/patch that fixes it.
- Out-of-band urgent fixes arrive as "Oracle Security Alerts" instead of CPUs;
  check for both when correlating.
- Note: many fixes ship under the CPU umbrella without standalone technical
  writeups; the CPU document itself is the vendor advisory of record.

## 2. Version anchoring (what "version" means per product)

| Product | Version anchor to record | Patch-level caveat |
|---|---|---|
| Oracle Database | banner version like `19.0.0.0.0` + platform string | PSU/RU history is NOT visible remotely; a banner inside a range only proves the base release |
| WebLogic | console/error-page version like `12.2.1.4.0` + PSU/CPU patch level if disclosed | PSUs change applicability without changing the base banner; missing patch-level info caps the claim |
| E-Business Suite | `Release 12.x.y` markers, tech-stack component versions | EBS rows are per-component (Technology Components, Framework, etc.) — match the component, not the release |

Rule: an Oracle claim always cites release + (known|unknown) patch level.
Unknown patch level forces the `70` caveat rung; it never forces a "likely
vulnerable" rung on its own.

## 3. Correlation procedure with `70`

1. Take tier <= 2 fingerprints only (TNS banner, console version string, EBS
   release marker; tier table in `70`'s confidence rules).
2. Identify the product family and matrix section (DB / Fusion Middleware /
   EBS).
3. In an operator-approved network window, pull the relevant CPU advisories
   (or pre-fetched copies) covering the fingerprinted release's lifetime to
   the present; build the offline advisories file for
   `scripts/cve_correlate.py` (folder `70`) with rows keyed by product
   component + affected version range.
4. Correlate offline: version membership per row -> candidate CVE list.
5. Apply the claim ladder: correlation output is "likely vulnerable" at best
   (tier 1) or "version in range, impact unverified" (tier 2); "confirmed
   vulnerable" only via `45` in-scope reproduction.
6. Record sources + access dates; negative results are dated statements
   ("no CPU row matched as of <date>").

## 4. Affected-component reading rules

- Read the *component* column literally: "Oracle WebLogic Server" rows do not
  apply to other Fusion Middleware components on the same host, and a DB row
  naming "Core RDBMS" does not cover "Java VM" (JVM) rows — they are separate
  rows with separate scores.
- CVSS scores in the matrix are Oracle's base scores with Oracle's chosen
  metrics; the report vector is rebuilt under `70`'s CVSS 4.0 procedure from
  observed attack preconditions, not copied.
- "Attack vector: remote unauthenticated" rows on internet-facing consoles
  raise engagement priority; "requires authentication" rows chain with `30`
  findings (which account's creds exist?).
- Version ranges in the matrix are Oracle's own strings (often
  "12.2.1.4.0 and later" style); paste them verbatim into the advisories
  file — do not normalize them by hand.
- Localized advisories/translations are non-authoritative; correlate against
  the English CPU document.


---

## Reference Module: `oracle-db-surface`

# Oracle DB surface

TNS listener enumeration procedure, SID and account-name candidate tables, and
the safe-check rules that bind every database interaction in this skill.

## 1. TNS protocol basics (what the probe sends)

- Oracle listener speaks TNS (Transparent Network Substrate) over TCP 1521
  (also 1522-1540-style derivatives and 2483/2484 TLS variants in some shops).
- Minimal packet: 8-byte header — length (2 bytes, big-endian, header+data),
  packet checksum (2, zero), packet type (1; `1` = CONNECT), reserved (1,
  zero), header checksum (2, zero) — followed by connect data bytes.
- Read-only connect-data commands (the wire equivalent of `lsnrctl`):
  - `(CONNECT_DATA=(COMMAND=VERSION))` — listener banner, typically
    `TNSLSNR for <platform>: Version <x.y.z.w.v> - Production`.
  - `(CONNECT_DATA=(COMMAND=STATUS))` — listener status block (uptime,
    log/trace file paths, listening endpoints). Information disclosure by
    itself; record it.
  - `(CONNECT_DATA=(COMMAND=SERVICES))` — service/handler/instance summary;
    the primary source for SID and service names.
- Prohibited commands (state-changing, RoE-blocked by default): `REGISTER`,
  `SHUTDOWN`, `SAVE_CONFIG`, `RELOAD`, `SET`, `TRACE`. Sending any of them is
  a scope breach unless the engagement authorizes it in writing.

Procedure:

1. TCP connect (bounded timeout, ~5 s). Closed/filtered is itself a finding
   row ("listener not exposed").
2. Send VERSION packet, read up to a few KB with the same bounded timeout,
   decode ASCII, keep hex + decoded as the evidence pair.
3. If VERSION answers, send STATUS and SERVICES once each; parse service and
   instance names by hand from the response text (no third-party parser
   needed at this depth).
4. Record platform + version -> CPU correlation via
   `references/oracle-cpu-cadence.md` and `70`.

## 2. SID candidates (names only)

Use the SERVICES response first. Only if the engagement authorizes bounded
guessing, common SID names (serial, low rate, engagement-capped):

`ORCL, XE, ORCL1, ORCL2, PDB1, PROD, TEST, DEV, UAT, SIT, DB1, OEM, GRID,
ASM, APPS, EBS, SDE, DW, BI, HR, FIN, SCM, SID, DB, MAIN`

Rules: one candidate per few seconds; stop at first hit; log every attempt for
the audit trail; three failed generations without signal -> dead-end rule
(record negative result, move on).

## 3. Default / well-known account names (names only — never passwords)

| Account | Historical note (why it is a candidate) |
|---|---|
| `SYS` | DBA superuser, exists by default |
| `SYSTEM` | DBA administrative account, exists by default |
| `DBSNMP` | Oracle Enterprise Manager agent account; famous historical default |
| `SCOTT` | Sample schema account (classic `scott`/tiger pairing — name well known, password always operator-supplied) |
| `OUTLN` | Plan-stability schema, historical default |
| `CTXSYS` | Oracle Text admin schema |
| `MDSYS` | Oracle Spatial admin schema |
| `ORDSYS` | interMedia/ORDIM admin schema |
| `OLAPSYS` | OLAP catalog schema |
| `XDB` | XML DB account |
| `ANONYMOUS` | XDB HTTP listener anonymous mapping |
| `APEX_PUBLIC_USER` | APEX listener-facing account |
| `FLOWS_FILES` | APEX file-schema account |

Rules (binding):

- This table lists NAMES. Passwords are operator-supplied via env/stdin.
- Bounded attempts only, engagement-approved ceiling per account (default
  posture: verify an account *exists* via failed-auth differentiation only if
  the RoE allows it; a generic ORA-01017 does not confirm existence on all
  releases).
- Oracle accounts lock after configured failed attempts (default profile:
  10). A lockout is a denial-of-service impact on a real system — treat the
  counter as a resource budget and stop well before it.
- One working credential -> read-only session first (`SELECT * FROM
  session_privs; SELECT * FROM user_role_privs;`), then hand the session to
  `30` for context takeover. No DDL/DML, no password changes.

## 4. Privilege-escalation CHECKS (queries, not exploits)

With a credentialed session, record the grant matrix:

- `SELECT * FROM session_privs;` — effective system privileges.
- `SELECT * FROM user_role_privs;` / `dba_role_privs` (if readable).
- Dangerous grants to look for: `DBA`, `EXECUTE ANY PROCEDURE`,
  `CREATE ANY TRIGGER`, `ALTER SYSTEM`, `UTL_FILE`, `UTL_HTTP`,
  `UTL_TCP`, `DBMS_SCHEDULER` execute, `DBMS_JAVA` execute.
- JAVA presence: `SELECT * FROM all_objects WHERE object_name LIKE 'DBMS_JAVA';`
- Public grants: `SELECT * FROM dba_tab_privs WHERE grantee='PUBLIC';` (when
  readable).

Output: a table account -> privilege -> "observed via <query>" as D1; the
report states who *can* do what. Demonstrating the escalation belongs to `45`
with RoE.

## 5. Listener registration abuse / TNS poisoning (concept-level, RoE caution)

- Class: a remote client that can reach the listener and speak the
  registration protocol can register a rogue listener/database instance and
  intercept client connections (CVE-2012-1675 is the well-known advisory for
  this class — verify against NVD/vendor advisory at authoring time).
- CHECK only: (a) is 1521 reachable from our position, (b) does it answer
  STATUS/SERVICES, (c) does the listener report `REGISTRATION`-restricted
  mode / valid-node-checking indications in the status block. The finding is
  "listener exposed and answering registration-era queries from <source>";
  performing a poison is out of scope for this skill entirely.
- Encryption-at-rest (TDE) and DB-audit settings are not remotely observable:
  record "requires operator confirmation from the host" rather than guessing.

## 6. Safe-check rules (summary)

1. Read-only first: VERSION/STATUS/SERVICES, SELECT queries.
2. Never send listener-mutating commands.
3. Account-name tables only; credentials from the operator.
4. Failed-attempt budget per account; lockout-aware pacing.
5. Anything state-changing (CREATE, deployment, password ops) -> operator
   written approval + `45`/`30` ownership.


---

## Reference Module: `weblogic-surface`

# WebLogic surface

Console and T3/IIOP procedure, version-disclosure path list, the
deserialization attack-class summary with the real well-known CVE names, and
the operator-gated WAR deployment path.

## 1. Port and protocol map

| Port | Protocol | Meaning |
|---|---|---|
| 7001 | HTTP + T3 (multiplexed by content) | default admin+app listener |
| 7002 | HTTPS + T3S | default SSL listener |
| same listener | IIOP (CORBA) | `weblogic.iiop` runtime; part of the deserialization surface |

T3 detection: a client handshake string (`t3 <version>`) to 7001 gets a
protocol response naming the server version (historically `HELO:12.x.x`
style). Reading the response is observation; sending serialized objects is
`45` territory.

## 2. Version-disclosure path list (GET only)

| Path | What it historically leaks |
|---|---|
| `/console` | redirect chain to the login form; redirect target itself is a finding |
| `/console/login/LoginForm.jsp` | login page; older releases print "WebLogic Server Version: x.y.z.w" in page footer or title |
| `/console/login/LoginForm.jsp` error states | error pages with version/build strings |
| arbitrary 404 | older releases return an error page naming "WebLogic Server" + version |
| `/wls-wsat/CoordinatorPortType` | WS-AT endpoint; GET may answer SOAP/HTTP method error revealing the module exists |
| `/_async/AsyncResponseService` | AsyncResponseService endpoint; confirms async web services subsystem reachability |
| `/management/tenant-monitoring/servers` | WebLogic REST Management API; unauthenticated access leaks domain/server topology |
| `/uddiexplorer/` , `/uddiexplorer/SearchUDI.jsp` | UDDI explorer (SSRF class history) |
| `/bea_wls_internal/` | internal apps family on older releases |

Every response goes to the evidence pair regardless of status: 404-with-version
is a disclosure, 403 marks a protected-but-present endpoint (P5 verb/encoding
candidate), 200 with login form is the console surface row.

## 3. Deserialization attack-class summary

The class: WebLogic's T3/IIOP protocol handlers and several HTTP decoders have
repeatedly accepted Java-serialized (or otherwise attacker-shaped) objects and
routed them into gadget chains -> RCE; separately, JNDI-lookup injection
classes let a crafted request make the server resolve an attacker-influenced
name. Well-known real advisories per family (each: verify against NVD/vendor
advisory at authoring time; applicability is only ever decided by `70` with
version proof):

T3/IIOP Java serialization family:

- CVE-2015-4852 — the classic T3 deserialization advisory.
- CVE-2017-3248 — T3 serialization gadget chain (January 2017 CPU).
- CVE-2018-2628 — T3 deserialization RCE (April 2018 CPU).
- CVE-2020-2883 — T3/IIOP, Coherence gadget chains (April 2020 CPU).

HTTP decoder family:

- CVE-2017-10271 — WLS WSAT component (`/wls-wsat`) deserialization.
- CVE-2019-2725 — `wls9_async`/async-response deserialization RCE; widely
  exploited in the wild at the time.
- CVE-2019-2729 — follow-up in the same async family.

Console path family:

- CVE-2020-14882 + CVE-2020-14883 — unauthenticated console path-traversal ->
  privileged console -> execution; chained, heavily exploited.

JNDI lookup family:

- CVE-2023-21839 — T3/IIOP JNDI injection (January 2023 CPU era; verify
  exact CPU month at authoring time).

SSRF class:

- CVE-2014-4210 — UDDI explorer (`/uddiexplorer`) server-side request
  forgery.

Usage rules:

1. This list names CLASSES for surface prioritization. It is never evidence of
   vulnerability — version proof -> `70` -> claim ladder.
2. PoC execution goes through `45` with RoE: documented PoC, disposable
   container, benign proof (canary echo / `id`), cleanup.
3. OOB callbacks (JNDI-class PoCs) pair with the `20` listener; `nuclei -ni`
   keeps its own Interactsh off.

## 4. Procedure (binding order)

1. Fingerprint: run the path list above + T3 banner read; capture pairs.
2. Version -> `70-exploit-intel` for CPU correlation (tier rules apply; bare
   console version without patch-level info caps at "version in range, impact
   unverified").
3. Only after `70` returns a correlated advisory: attempt the documented PoC
   via `45` within RoE.

## 5. Admin console access path — WAR deployment (operator-gated)

IF (and only if) operator-supplied credentials authenticate to `/console`:

1. Written operator approval on file for a deployment action; confirm the
   target is a non-production node or the engagement explicitly accepts it.
2. Build a minimal WAR whose only behavior is echoing the engagement canary
   (`rj-pt-<engagement>-<nonce>` marker string) — nothing else.
3. Console path: Deployments -> Install -> upload WAR -> target the admin
   server (or a dedicated managed server) -> Finish.
4. Verify by requesting the servlet URL; capture request+response as the RCE
   proof pair.
5. Cleanup: undeploy, re-list deployments to show removal, keep both evidence
   pairs.
6. Any further use of console access (datasource inspection, credential
   extraction from JDBC configs) is read-only, evidence-captured, and stays in
   the engagement namespace.

Without credentials: report the console as exposed attack surface with the
version disclosure and lockout policy observations (bounded attempts per `30`)
— no brute force from this skill.

