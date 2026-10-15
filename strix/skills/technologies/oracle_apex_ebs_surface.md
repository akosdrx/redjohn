---
name: oracle_apex_ebs_surface
description: Oracle APEX, WebLogic Management & EBS DMZ Surface Reference (from oracle_stack_security
  specialist reference library)
---

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

