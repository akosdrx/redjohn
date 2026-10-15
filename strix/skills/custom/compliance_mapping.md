---
name: compliance_mapping
description: Compliance Framework Cross-Walk Mapping (from evidence_compliance_reporting
  specialist reference library)
---

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

