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
