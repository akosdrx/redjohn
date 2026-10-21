# RedJohn skill coverage és a felhasználói csomag adaptációja

Current selected profiles (2026-10-18): `tinja_validate`,
`schemathesis_validate`, `oast_correlate` and controller-owned `oast_poll`.
The three English contracts and content hashes match the bounded runtime.
See [adapter profiles](schema-oast-adapters.md) and
[actual verification](../../docs/redjohn-schema-oast-verification.md).
The dated mapping below is historical; runtime readiness and current evidence
are authoritative for supported input/actor/profile combinations.

2026-10-18: az `input-discovery`, `sql-injection-validation`, `xss-validation`
angol kontraktusok és runtime mapping frissítve a valódi GET/query adapterekhez.
A `browser_xss_confirmation` külön tartós capability. A konfigurációhiány most
readiness-szinten is `blocked_configuration`, nem futási lefedettség. Az alábbi
korábbi táblázat történeti; az aktuális szűk támogatást és a valós pozitív/javított
kontrollokat a [specialist runbook](query-specialists.md) és a
[friss mérés](../../docs/redjohn-specialists-verification.md) tartalmazza.

Current update: the English web-surface-inventory contract maps optional ffuf_discover and actual E2Es. Its content digest changed; original provenance remains. The current loader has 47 assessment and 9 domain contracts. The TUI displays that registry total (56), replacing the hardcoded 170. Registration does not prove live capability.

A meglévő 12 angol `domains/*`, `coordination/*`, `analysis/*` és `tooling/*` tartalom megmarad. A felhasználó által adott 35 kontraktus és a master prompt 12 új célfüggő kontraktusa a `redjohn/skills/assessment/<id>/SKILL.md` fájlokba került; mind a 47 assessment dokumentum és manifestleírás angol. A runtime a manifestből dolgozik, nem hardcode-olt darabszámból. A tartalom betöltése referencia, önmagában nem indít tesztet és nem bizonyít végrehajtási lefedettséget.

## Angol fordítás és megőrzött provenance

A fordítás megtartja az ID-ket, frontmatter-neveket, capability/statusz mappinget,
scope/auth/TLS/cleanup guardrailokat és a szakmai bizonyítási feltételeket. Az
eredeti forráscsomaghoz nem nyúl; Strix/HexStrike kódot és licencet nem vesz át.
A 12 új RedJohn-skill ismétlődő aktiválási mondata egyszer szerepel.

A manifest globális és skillenkénti `content_language` értéke `en`.
`source_sha256` továbbra is az eredeti skill vagy master prompt hash-e;
`translation_input_sha256` a fordítás előtti RedJohn-kontraktus, `content_sha256`
az aktuális angol dokumentum SHA-256 értéke. A `translation_revision` `1`.
Az angol tartalom nem állítja, hogy megegyezik az eredeti forrás bájtjaival.
Az aktív skillteszt az angol szakaszokat, metadataegyezést és a külön
content-hasheket is ellenőrzi; a külső forráscsomag fájljait csak ott ellenőrzi,
ahol azok ténylegesen rendelkezésre állnak.

A Codex `skill-creator/scripts/quick_validate.py` is lefutott mind a 47 mappán.
Mindegyiket a RedJohn-specifikus `version` és `status` frontmatter-mező miatt
utasítja el, mert a generikus Codex-sémában ezek nem engedettek. Ez sémakülönbség,
nem a RedJohn runtime-kontraktus hibája: a termékmezők megmaradtak, nem történt
schema-migráció egy másik validator kedvéért. A saját 10 teszt sikeres volt,
47 tartalomhash egyezett, magyar ékezetet tartalmazó skillfájl nem maradt.
Az aktuális [gépi validációs jegyzőkönyv](../../docs/measurements/english-skill-validation.json)
a pontos validator-hasht és az eredményeket külön rögzíti.

## A forráscsomag tényleges auditja

A bemenet `/Users/akosdrx/Documents/headless_strix_skillpack`. Elolvasott elemek: README angol/magyar, capability-contracts, coverage-matrix, skill/tool registry, result schema, RCE-triage és a 35 skill releváns aktiválási/input/procedure/evidence/false-positive szakasza. Az eredeti registry pontozott toolnevei koncepcionális placeholder nevek. Ezek provenance-ként maradnak a manifestben, nem lesznek RedJohn toolhívások.

A régi job-result schema egyetlen `status` enumba keverte a queued/running, passed/candidate/confirmed és coverage állapotokat. Ez nem kerül át: a RedJohn `assessment/models.py` három külön execution/coverage/finding dimenziója a mérvadó. A dedup az eredeti URL-t/querysorrendet/encodingot, actor/tenant/session/workflow különbségeit őrzi. A régi „teljes stdout megőrzése” lépést bounded capture/evidence váltotta fel.

A `browser-worker` kód, a Strix MCP server config és a korábbi schema nem kerültek a RedJohnra. Nincs letöltött/upstream Strix- vagy HexStrike-kódátvétel. A csomag saját átdolgozható indulókészletnek mondja magát; önálló LICENSE/SPDX licencfájlt nem tartalmaz. Provenance: `user_supplied_no_license_file`, a külső motorok licencét ebből nem következtetjük. A RedJohn branding és meglévő integrációk megmaradnak.

| Auditált forrásdokumentum | SHA-256 |
|---|---|
| `README.md` | `33cd97461e6edd74e44533e960e0929b3b1056d7db768a195773180ac31b4ec3` |
| `README.hu.md` | `54f28842810a23e210edf8a0cd3d92aa41a8f5a15b12f8e71796a7bbdbf88bba` |
| `skill-registry.json` | `349fb5b042978fdeeecf876a938ecf3ab30b7f84c41b4e3121765ef02a64f978` |
| `tool-registry.json` | `5db7443df8edf68fb922d429beb83435a556048063530355dff0f0bb8639cca1` |
| `capability-contracts.md` | `8e06f1f89e9223adf132bc03dd0544b93a390638e75f2d4530699a0d0951b0c9` |
| `coverage-matrix.md` | `edf6eb9e2826a9bf4cfd372996f3b71c77c11764f0a1fe812db79341d03af9ed` |
| `schemas/job-result.schema.json` | `58e6c5ca98b23575ad46e8c09b80b7bf94bc666e254b8c4159b00018cdd0d81c` |
| `rce-miss-triage.md` | `77526b174608337e0ca0a3f8cca35ae614a02d6d96666e3b153f9242e6a2800b` |

Minden adaptált skill saját eredeti SHA-256 értéke és forrásverziója a gépi manifest `provenance` mezőjében található. Új RedJohn contract version: `2.0.0`; manifest schema: `1`.

## Betöltés és tényleges mapping

`load_skills(["assessment/headless-browser-discovery"])` és az egyértelmű bare `load_skills(["headless-browser-discovery"])` is támogatott. Kategóriaütközéskor explicit namespace kell. A meglévő extra-skill könyvtárak prioritása és a régi domain-skillnevek megmaradnak. Az új szerkezet `<category>/<id>/SKILL.md`; a régi `<category>/<id>.md` is működik.

A `get_available_skills()` az assessment-neveket/leírást/statuszt a manifestből veszi; nem olvassa be előre a 47 skill teljes törzsét. `load_skills` legfeljebb a kért fájlokat olvassa, egy dokumentum plafonja 128 KiB. A metadata cache 512 bejegyzésre és fájlonként egy verzióra korlátozott. A skillbetöltés nem importálja az opcionális motorokat és nem telepít csomagot.

API: `AssessmentSkillRegistry.get`, `definitions`, `readiness`, `eligibility`. A `readiness` a kanonikus CapabilityRegistry és belső modulfájlok alapján ellenőrzi a bekötést/dependencyt. Az `eligibility` ezen felül domain/profile/body/actor/fixture feltételeket vizsgál; ez nem helyettesíti a scheduler végső engagement/policy/egress engedélyét. A registry nem enged tetszőleges shellt vagy ismeretlen capabilityt.

A történeti kezdeti állapot négy adaptere: `browser_discover`, `http_observe`, `headers_audit`, `nuclei_scan`. Az `adapter_not_implemented` specialisták leírásként betölthetők, de nem mutatkoznak kész végrehajtási képességnek. A Nuclei-skill opcionális intelligence-provider hiányában is működhet jóváhagyott template lockkal; ettől VulnX nem válik live-igazolttá.

| Skill | Valódi kötelező mapping / belső modul | Hiányzó rész / adapter | Kontraktusállapot |
|---|---|---|---|
| `engagement-scope` | policy | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `headless-browser-discovery` | browser_discover | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `web-surface-inventory` | store | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `javascript-endpoint-analysis` | browser_discover | ast_endpoint_analysis | `adapter_not_implemented` |
| `input-discovery` | arjun_parameters | arjun_parameters | `adapter_not_implemented` |
| `technology-fingerprinting` | http_observe | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `nuclei-cve-planning` | nuclei_scan | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `authentication-session` | browser_discover | controlled_session_replay | `adapter_not_implemented` |
| `jwt-security` | nincs | jwt_validation_replay | `adapter_not_implemented` |
| `authorization-idor-bola` | browser_discover | actor_object_comparison | `adapter_not_implemented` |
| `authorization-bfla-bopla` | nincs | role_function_property_comparison | `adapter_not_implemented` |
| `api-graphql-security` | schemathesis_validate | schemathesis_validate | `adapter_not_implemented` |
| `sql-injection-validation` | sqlmap_validate | sqlmap_validate | `adapter_not_implemented` |
| `nosql-ldap-injection` | semgrep_source | nosql_ldap_controlled_replay, semgrep_source | `adapter_not_implemented` |
| `xss-validation` | dalfox_validate, browser_discover | browser_xss_confirmation, dalfox_validate | `adapter_not_implemented` |
| `command-injection-validation` | commix | command_injection_lab_control, commix | `deferred_not_required` |
| `template-injection-validation` | tinja_validate | tinja_validate | `adapter_not_implemented` |
| `ssrf-validation` | oast_correlate | server_fetch_fixture_replay, oast_correlate | `adapter_not_implemented` |
| `xxe-validation` | oast_correlate | xml_entity_fixture_replay, oast_correlate | `adapter_not_implemented` |
| `path-traversal-lfi-rfi` | nincs | fixture_file_boundary_replay | `adapter_not_implemented` |
| `file-upload-processing` | browser_discover | fixture_upload_workflow | `adapter_not_implemented` |
| `csrf-validation` | browser_discover | cross_origin_state_fixture | `adapter_not_implemented` |
| `cors-validation` | browser_discover, headers_audit | cross_origin_read_fixture | `adapter_not_implemented` |
| `http-desync-assessment` | nincs | raw_http_framing_lab_harness | `adapter_not_implemented` |
| `crlf-response-splitting` | nincs | byte_exact_response_header_replay | `adapter_not_implemented` |
| `deserialization-risk` | semgrep_source, trivy_source | deserializer_fixture_validation, semgrep_source, trivy_source | `adapter_not_implemented` |
| `race-toctou` | nincs | serialized_baseline_concurrent_fixture_harness | `adapter_not_implemented` |
| `prototype-pollution` | nincs | isolated_javascript_state_harness | `adapter_not_implemented` |
| `subdomain-takeover` | dns_discover | nonclaiming_provider_ownership_validation, dns_discover | `adapter_not_implemented` |
| `business-logic-testing` | nincs | application_specific_workflow_invariants | `adapter_not_implemented` |
| `oast-correlation` | oast_correlate | oast_correlate | `adapter_not_implemented` |
| `source-dependency-analysis` | semgrep_source, trivy_source | semgrep_source, trivy_source | `adapter_not_implemented` |
| `finding-triage-retest` | store, report | finding_control_validation | `adapter_not_implemented` |
| `report-coverage` | report, store | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `execution-scheduling` | scheduler, store | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `service-discovery` | naabu_ports, nmap_services | naabu_ports, nmap_services | `adapter_not_implemented` |
| `dns-asset-discovery` | dns_discover | dns_discover | `adapter_not_implemented` |
| `wordpress-assessment` | wordpress_assess | wordpress_assess | `adapter_not_implemented` |
| `cloud-posture-assessment` | cloud_assess | cloud_assess | `adapter_not_implemented` |
| `kubernetes-benchmark-assessment` | kubernetes_benchmark | kubernetes_benchmark | `adapter_not_implemented` |
| `local-binary-triage` | binary_triage | binary_triage | `deferred_not_required` |
| `resilience-recovery` | recovery, scheduler | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `memory-context-budgeting` | resources, redjohn.llm.context_budget | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `cache-freshness-control` | cache | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `correlation-hypothesis-review` | intelligence | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `performance-regression` | intelligence, resources | runtime dependency/policy ellenőrzés | `implemented_fixture_tested` |
| `safe-reproducer-validation` | nincs | isolated_reproducer_sandbox | `adapter_not_implemented` |

## Ellenőrzés és korlátok

Történeti baseline a fordítás előtt: `../.venv/bin/python -m pytest tests/test_assessment_skills.py tests/test_assessment_resource_control.py tests/test_assessment_intelligence.py -q` a létrehozáskor **48 passed / 0.35 s**. Ebből 9 skillloader/manifest/activation/provenance teszt, 38 resource/cache/recovery/intelligence unit/fixture teszt és 1 tényleges process-tree RSS integrációs mérés. A lokális forrás-SHA ellenőrzés ezen a gépen ténylegesen lefutott; más CI gépen a külső felhasználói csomag hiánya explicit skip. A fordítás utáni célzott skill-ellenőrzés **10 passed / 0.21 s** volt; ez nem a későbbi teljes Linux E2E eredménye.

A skillteszt az integrációt, lazy listinget, namespaced/bare feloldást, override-ot, ambiguityt, path traversal tiltását, capability létezését és hiányzó adapter/dependency helyes státuszát igazolja. Nem bizonyít SQLi/XSS/SSRF/stb. detektálást. Az unsupported specialistákhoz nincs pozitív/javított live kontroll: `not_run_adapter_not_implemented`. Az eredeti RCE-fixture nincs meg: `not_reproduced_missing_fixture`. A browser/Nuclei saját élő tesztjeit a külön mérési napló tartalmazza.

A célfüggő network/CMS/cloud/Kubernetes/binary skillek csak a megfelelő target-domain, policy, dependency és credential megjelenésekor lehetnek jogosultak. Egy webes domain nem enged portscant, a fejlesztő credential chainje nem ad cloud accountengedélyt, és semmilyen recovery nem lazíthat auth/TLS/scope korlátot.


### 2026-10-18: selected TInjA / Schemathesis / Interactsh

The current implemented profiles use actual captured anonymous GET inputs,
pinned TInjA 1.2.0 / Schemathesis 4.31.1, and a host Interactsh 1.4.1 protocol
client with an owned receiver and durable late polls. Scanner/callback signals
remain candidates. Broad API/GraphQL, body/auth mutation and public DNS OAST
are separate coverage gaps. See `docs/redjohn-schema-oast-verification.md`
and `RedJohn/docs/schema-oast-adapters.md` for current evidence and bounds.
