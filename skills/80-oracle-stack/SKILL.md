---
name: 80-oracle-stack
description: Use when fingerprinting identifies Oracle technology in scope - TNS listener enumeration, WebLogic console, management & async servlets, Oracle APEX/ORDS, EBS DMZ URL firewall auditing (MOS Doc 1387859.1), and Oracle Critical Patch Update (CPU) advisory correlation by version.
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
