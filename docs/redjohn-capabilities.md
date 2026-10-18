# RedJohn képesség-, forrás- és licenckatalógus

A katalógus az aktuális `assessment/registry.py` kódjából készül. A megírt adapter, a helyi konfiguráció és a korábbi valódi mérés külön állapot.

A `redjohn assess health` mutatja az adott gép telepítési/konfigurációs állapotát motorindítás nélkül. A JSON itt platformfüggetlen kódkatalógus; a jegyzőkönyvek történeti futásokat igazolnak, jelenlegi futást nem állítanak.

21 implementált képesség, 6 hiányzó opcionális adapter és 9 tudatosan halasztott alternatíva szerepel a jelenlegi registryben. A master szerinti teljes fennmaradó munka: [követett állapot](redjohn-completion-status.md).

| Capability | Tool | Adapter | Kódstátusz | Forrás / licenc | Mérési jegyzőkönyv |
|---|---|---|---|---|---|
| `browser_discover` | Playwright + Chromium | igen | `implemented_fixture_tested` | [forrás](https://playwright.dev/python/) / Apache-2.0 | [mérés](redjohn-mime-restart-verification.md) |
| `http_observe` | RedJohn HTTP observation | igen | `implemented_fixture_tested` | RedJohn-native / project | [mérés](redjohn-verification.md) |
| `headers_audit` | RedJohn response header check | igen | `implemented_fixture_tested` | RedJohn-native / project | [mérés](redjohn-verification.md) |
| `nuclei_scan` | Nuclei | igen | `implemented_fixture_tested` | [forrás](https://github.com/projectdiscovery/nuclei) / MIT_engine_templates_separate | [mérés](redjohn-mime-restart-verification.md) |
| `ffuf_discover` | ffuf | igen | `implemented_fixture_tested` | [forrás](https://github.com/ffuf/ffuf/tree/v2.1.0) / MIT | [mérés](redjohn-ffuf-verification.md) |
| `httpx_probe` | ProjectDiscovery httpx | igen | `implemented_fixture_tested` | [forrás](https://github.com/projectdiscovery/httpx/tree/v1.12.0) / MIT_CLI_optional_datasets_and_provider_data_separate | [mérés](redjohn-projectdiscovery-verification.md) |
| `katana_discover` | Katana (standard) | igen | `implemented_fixture_tested` | [forrás](https://github.com/projectdiscovery/katana/tree/v1.8.0) / MIT_CLI_optional_datasets_and_provider_data_separate | [mérés](redjohn-projectdiscovery-verification.md) |
| `vulnx_intelligence` | VulnX | igen | `implemented_fixture_tested` | [forrás](https://github.com/projectdiscovery/vulnx/tree/v2.0.2) / MIT_CLI_optional_datasets_and_provider_data_separate | [mérés](redjohn-projectdiscovery-verification.md) |
| `session_refresh` | RedJohn explicit session refresh | igen | `implemented_fixture_tested` | RedJohn-native / project | [mérés](redjohn-authenticated-schema-oast-verification.md) |
| `workflow_execute` | RedJohn reviewed stateful workflow | igen | `implemented_pending_live_proof` | RedJohn-native / project | nincs valódi integrációs igazolás |
| `arjun_parameters` | Arjun | igen | `implemented_fixture_tested` | [forrás](https://github.com/s0md3v/Arjun/tree/2.2.7) / AGPL-3.0_LICENSE_setup_metadata_conflicts | [mérés](redjohn-specialists-verification.md) |
| `sqlmap_validate` | sqlmap | igen | `implemented_fixture_tested` | [forrás](https://github.com/sqlmapproject/sqlmap/tree/1.10.10) / GPL-2.0-or-later_with_upstream_clarifications | [mérés](redjohn-specialists-verification.md) |
| `tinja_validate` | TInjA | igen | `implemented_fixture_tested` | [forrás](https://github.com/Hackmanit/TInjA/tree/1.2.0) / Apache-2.0 | [mérés](redjohn-mime-restart-verification.md) |
| `schemathesis_validate` | Schemathesis | igen | `implemented_fixture_tested` | [forrás](https://github.com/schemathesis/schemathesis/tree/v4.31.1) / MIT | [mérés](redjohn-mime-restart-verification.md) |
| `dalfox_validate` | Dalfox | igen | `implemented_fixture_tested` | [forrás](https://github.com/hahwul/dalfox/tree/v3.2.4) / MIT | [mérés](redjohn-specialists-verification.md) |
| `oast_correlate` | Interactsh protocol 1.4.1 | igen | `implemented_fixture_tested` | RedJohn-native / project_protocol_MIT_reference | [mérés](redjohn-mime-restart-verification.md) |
| `oast_poll` | Interactsh protocol 1.4.1 | igen | `implemented_fixture_tested` | RedJohn-native / project_protocol_MIT_reference | [mérés](redjohn-mime-restart-verification.md) |
| `browser_xss_confirmation` | RedJohn Chromium XSS confirmation | igen | `implemented_fixture_tested` | RedJohn-native / project | [mérés](redjohn-specialists-verification.md) |
| `browser_post_capture` | RedJohn approved Chromium POST capture | igen | `implemented_fixture_tested` | RedJohn-native / project | [mérés](redjohn-mime-restart-verification.md) |
| `semgrep_source` | Semgrep CE (native OCaml) | igen | `implemented_pending_native_e2e` | [forrás](https://github.com/semgrep/semgrep/tree/v1.181.0) / LGPL-2.1_engine_rules_separate | nincs valódi integrációs igazolás |
| `trivy_source` | Trivy filesystem misconfiguration | igen | `implemented_pending_native_e2e` | [forrás](https://github.com/aquasecurity/trivy/tree/v0.76.0) / Apache-2.0_engine_embedded_checks_separate | nincs valódi integrációs igazolás |
| `naabu_ports` | Naabu | nincs | `adapter_not_implemented` | [forrás](https://github.com/projectdiscovery/naabu) / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `nmap_services` | Nmap | nincs | `adapter_not_implemented` | [forrás](https://nmap.org/) / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `dns_discover` | Amass / Subfinder / dnsx | nincs | `adapter_not_implemented` | [forrás](https://github.com/owasp-amass/amass) / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `wordpress_assess` | WPScan | nincs | `adapter_not_implemented` | [forrás](https://github.com/wpscanteam/wpscan) / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `cloud_assess` | Prowler | nincs | `adapter_not_implemented` | [forrás](https://github.com/prowler-cloud/prowler) / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `kubernetes_benchmark` | kube-bench | nincs | `adapter_not_implemented` | [forrás](https://github.com/aquasecurity/kube-bench) / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `feroxbuster` | Feroxbuster | nincs | `deferred_not_required` | RedJohn-native / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `gobuster` | Gobuster | nincs | `deferred_not_required` | RedJohn-native / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `rustscan` | RustScan | nincs | `deferred_not_required` | RedJohn-native / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `masscan` | Masscan | nincs | `deferred_not_required` | RedJohn-native / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `autorecon` | AutoRecon | nincs | `deferred_not_required` | RedJohn-native / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `scoutsuite` | ScoutSuite | nincs | `deferred_not_required` | RedJohn-native / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `kubehunter` | kube-hunter | nincs | `deferred_not_required` | RedJohn-native / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `binary_triage` | GDB / angr / pwntools | nincs | `deferred_not_required` | RedJohn-native / not_verified_not_redistributed | nincs valódi integrációs igazolás |
| `commix` | Commix | nincs | `deferred_not_required` | RedJohn-native / not_verified_not_redistributed | nincs valódi integrációs igazolás |

A `not_verified_not_redistributed` licenc nincs ellenőrizve; ilyen motort a RedJohn nem terjeszt. A reviewed engine-ek verziója, digestje és külön adatforrás-feltételei a hivatkozott jegyzőkönyvekben szerepelnek.

Generálás a repository gyökeréből:

```sh
PYTHONPATH=RedJohn .venv/bin/python RedJohn/scripts/update-capability-matrix.py
```
