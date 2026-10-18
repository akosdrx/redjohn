# Követelménykövetés — master prompt 2.0

**2026-10-18, aktuális ellenőrzési határ:** a korábbi, ténylegesen lezárt Ubuntu
x64/ARM64 Actions-kör SHA-ja `57141b25ed32169e24d0065b4bc21a0422e83fab`
(1225 pass/platform, 320 valódi integráció/platform, 0 fail/skip).
Az új cache/session, közös SDK/MCP/Shell-életciklus, felületi tesztek és vegyes
terhelés külön, `5cfd51d286c65558b92a6c070bcd7edd5a8b432b` forráson futnak:
[aktuális Actions](https://github.com/akosdrx/redjohn/actions/runs/39144694827).
Az elindított futás még nem sikeres eredmény. A táblák régebbi mérési soraiban
szereplő hozzáférési/tesztállapotok történeti baseline-ok; a követett teljes
feladat a completion ledgerben marad nyitott. A felhasználó az élő cloud/Kubernetes
hozzáférést igénylő igazolást későbbre halasztotta; ez nem live siker.

A teljes hátralévő feladat és annak elfogadási kapui egy helyen:
[RedJohn completion ledger](redjohn-completion-status.md). A kódkatalógus
generált, és nem téveszti össze a hiányzó konfigurációt a hiányzó adapterrel.

Állapotok jelentése: live = tényleges helyi executable/Chromium és saját HTTP(S)
szerver; fixture/unit = determinista unit/kontraktusteszt, szükség szerint explicit
mock tool vagy download; blocked = el nem végezhető futás; partial = részben
implementált. A saját fixture ellen futó valódi engine live integráció, a fake
engine/download nem az. Dokumentum létezése nem végrehajtás.

A korábbi loopback-mérések történeti baseline-ok. A jelenlegi remote HTTPS
implementáció Linux kernelhatárt és exact-request host-only auth-replayt ad;
az owned non-loopback Linux lánc eredményét a
[külön mérési jegyzőkönyv](redjohn-remote-auth-verification.md) igazolja.
A namespace-only teszt nem helyettesíti a browser–inventory–scheduler–Nuclei láncot.
A jelenlegi [POST/session bővítés](../RedJohn/docs/post-refresh-replay.md) külön
capture-reservationt, v2 bodyvaultot és explicit refresh-jobot ad; a hozzá tartozó
[aktuális mérési jegyzőkönyv](redjohn-post-refresh-verification.md) külön workload.
Az új [Chromium POST/body-token út](../RedJohn/docs/browser-post-body-tokens.md)
valódi browser-forgalmat és privát automatic-approval rule-t használ;
[külön mérési jegyzőkönyv](redjohn-browser-token-verification.md) tartozik hozzá.

| Master | Implementáció / modul | Teszt / bizonyíték | Állapot és nyitott rész |
|---|---|---|---|
| 0–2 név, meglévő munka, audit | eredeti `redjohn-agent`, `rj`, `redjohn`; `docs/redjohn-initial-state.json` | baseline 7teszt; fájlhash+dirty Git snapshot | megőrizve; nincs reset, platformcsere vagy Firecrawl |
| 3 moduláris adatfolyam | `assessment/runtime.py`, `models.py`, `policy.py`, `egress.py` | `test_assessment_pipeline.py`, `test_remote_authenticated_pipeline.py` | helyi és owned non-loopback Linux remote live; a browser coverage partial |
| 4 toolválasztás | `assessment/registry.py`, meglévő Nuclei, discovery/specialist/schema/OAST adapterek | külön engine-/kontraktus-/E2E-jegyzőkönyvek; generált capability-katalógus | 18 megírt capability; 8 hiányzó opcionális adapter; 9 tudatos alternatíva. TInjA/Schemathesis/OAST/Arjun/sqlmap/Dalfox már implementált, a runtime-konfiguráció külön feltétel |
| 5.1 döntés | `assessment/scheduler.py:IntelligentDecisionEngine` | scheduler capability/fairness/progress teszt | fixture+pipeline; nem RL |
| 5.2 technológia | `assessment/intelligence.py:TechnologyDetector`, `discovery_tools.py` | `test_assessment_intelligence.py`, valódi httpx fejléc → technológiai megfigyelés | implementált header/httpx kapcsolat; Nmap/source teljes kombinálás részleges; fingerprint nem érintettségi bizonyíték |
| 5.3 intelligence | `CVEIntelligenceManager`, `AdvisoryRecord`, `vulnx.py`; régi `tools/cve/tool.py` megmarad | valódi VulnX CLI + kontrollált HTTPS API; külön valódi publikus provider; TTL/restart/retest és hibák | implementált bounded CVE-ID lookup, tartós kvótázott metadata-cache; applicability unknown marad, validált asset-verzió/érintett tartomány nélkül |
| 5.4 korreláció | SQLite `VulnerabilityCorrelator`, bounded query és evidence check | intelligence tests | fixture; nem futtat exploitláncot |
| 5.5 reproducer | `assessment/reproducer.py` | `test_assessment_reproducer.py` | lokális header/fixed kontroll; nincs tetszőleges generált kódfuttató, nincs RCE-proof |
| 5.6 rate limit | `persistent_rate_limit.py:PersistentRateLimitDetector`, browser/HTTP/Nuclei közös SQLite | dátum/szekundum/403; 11 SQLite teszt; actual429 és restart utáni 0 új kérés | élő helyi integráció; atomikus origin/group/account ablakok és tartós cooldown |
| 5.7 optimizer | `ParameterOptimizer` | pressure/hysteresis/input allowlist unit | fixture; nem bővít policyt |
| 5.8–5.9 recovery/degrade | `FailureRecoverySystem`, `CircuitBreaker`, `GracefulDegradation`, scheduler | retrybudget/cancel/workerloss/fallback tests | fixture+live browser crash; régi teljes MCP/provider lifecycle migráció részleges |
| 5.10 performance | `PerformanceMonitor`, CLI benchmark, browser health/RSS | mért JSON és histograms | helyi live; p50/p95 esetenként bucket upper bound, pontos ciklusmérés külön |
| 5.11 cache | `cache.py:SmartCache` | LRU/bytes/TTL/oversize/singleflight/invalidation tests | fixture+valódi cache workload |
| 5.12, 10 resource/memory | `resources.py`, `host_resources.py`, `os_memory.py`, `contained_controller.py`, BrowserLimits, store quota | külön többprocesszes/RSS/Chromium/valódi kernel OOM és orphan-recovery E2E; 354 fájlos rögzített forráslista | megosztott aktív assessment-admission külön kampány-DB-k között; explicit dedikált Linux CLI hard limit exec előtt. Idle cache-ek/régi runtime-ok teljes közös kezelése és hostszintű összesített OS-keret továbbra is részleges |
| 6 headless/session | `browser.py`, `browser_tls.py`, `browser_proxy.py`, `browser_capture.py`, `body_tokens.py`, BrowserInventoryAdapter, `auth_replay.py` | valódi HTTP(S) Chromium SPA/2 actor/crash/redirect/cancel/revision; CA/SAN/SPKI; auth-engine és remote-chain teszt külön | helyi live; Linux remote kernelhatár; exact observed GET/HEAD Nuclei auth-replay; explicit64KiB JSON/form/multipart replay, valódi Chromium-capture és deklarált body-token refresh; teljes login/MFA hiányzik |
| 7 inventory/sémák | `models.py`, additív `rj_*` táblák `.state/agents.db` | encoding/query/actor/session/persistence tests | implementált core; teljes asset/service/workflow/correlation lifecycle részleges |
| 8 tartós scheduler | `store.py`, `scheduler.py`, `capture.py`, `browser_workflow.py`, `session_refresh.py` | fair/fencing/flock/restart; capture-CAS+atomikus budget; refresh-CAS; current-revision startup queue; atomic success/auth-failure outbox + same-runtime reviewed chain + persistent bounded 401/expiry recovery; külön CLI és single-runtime E2E | tartós nem idempotens POST/refresh; unknown response nem retry; soros batch, nem exactly-once network ígéret |
| 9 Nuclei | meglévő hunt + `nuclei.py`, `bounded_worker.py`, `NativeFixtureSession`, `auth_replay.py`, pinned installer és explicit fixture-lock | valódi v3.11.1 HTTP(S) marker/fixed kontroll; named actor/expiry/redirect; POST JSON/form/multipart, stabil multipart-sentinel és browser-token refresh külön E2E; mock scanner/processz/download külön | local actual-engine auth live; Linux remote worker attesztációval; saját reviewed marker, nem teljes CVE-katalógus |
| 11 cache szemantika | contextrevisions, retest bypass, stateful cachetiltás | resource-control tesztek | kész a modulban; teljes régi cache-migráció részleges |
| 12 hiba | normalizált séma, partial/blocked/unsupported elkülönítés; kvótázott kernel-OOM evidence; tartós kapacitásvárakozás | scanner parser/timeouts, actual browser/kernel faults, delayed OAST, disk fault fixture; módosító/admitted munka nincs kapacitás miatt újrajátszva | core bővítve; teljes régi provider/MCP lifecycle fault mátrix még részleges |
| 13 skillek | 47 angol lazy `assessment/*/SKILL.md`, manifest+capability registry, eredeti12 angol megmarad | `test_assessment_skills.py`, source/translation/content SHA külön, skill coverage doc | loader/fordítás igazolt; külső source változatlan; hiányzó adapter nem eligible |
| 14 kis API | `control.py`, `tools/assessment/tool.py`, eredeti agent registry | authz/revision/size/redaction/cancel tests | belső/SDK implementált; új hálózati MCP szerver nem szükséges/nincs |
| 15 scope/egress | exact origins, IP/CIDR+DNS/connectpin, profiles, actor, proxy, Linux namespace és privát attesztált relay | policy+actual HTTP(S) scope/TLS/budget; valódi namespace/bypass/cancel; remote auth-chain teszt külön | Linux kernel-egress implementált; nem támogatott host/prerequisite blocked; nem teljes hostfirewall vagy hard RAM-limit |
| 16 validation/RCE | candidate-only scanner finding, kontrollált header reproducer | positive/fixed controls és retest | eredeti RCE: not_reproduced_missing_fixture |
| 17 teszt/mérés | unit, valódi Chromium/Nuclei, Linux namespace és remote auth fixture; supervisor; benchmark/https-demo CLI | régi loopback mérés történeti; auth-engine, namespace-only és teljes remote E2E külön | helyi HTTP(S)/Nuclei live; aktuális Linux lánc külön eredmény; helyes GitHub CI auth hiányában nem igazolt, Kali/release/long soak nyitott |
| 18–20 átadás | audit, architektúra, mátrix, skillek, runbook, changelog | fájlmanifest és tesztparancsok | core vertikális szelet kész, teljes master elfogadás részleges |
| 21 forrás/licenc | `third-party-references.json`, Nuclei provenance receipt/doc, skill SHA manifest | hivatalos v3.11.1 release/commit/archive/checksum/license pin és valós binary version/hash | Nuclei MIT executable, saját Apache-2.0 fixture; nincs átvett upstream Strix/HexStrike kód |

Az opcionális, még meg nem írt adapter státusza `adapter_not_implemented`;
nem pusztán „nincs bináris”. A tudatos alternatívák `deferred_not_required`.
Egy futás hiányzó dependency/credential miatt `blocked`; ez egyik esetben sem
`no_finding_observed`. A test stub önmagában nem változtat capability státuszt.

Current vertical slice: [ffuf / assessment Web View](redjohn-ffuf-verification.md), covering master 4/8/12/13/17/20. Full master acceptance remains partial.

2026-10-18 continuation: [httpx / Katana / VulnX verification](redjohn-projectdiscovery-verification.md), with pinned workers, durable scheduler, verified HTTPS/provider egress and explicit URI/JS/platform gaps. Earlier measurements remain historical evidence.

## 2026-10-18: Arjun / sqlmap / Dalfox folytatás

| Követelmény | Implementáció | Bizonyíték / határ |
|---|---|---|
| 4.1 kijelölt paraméterfelderítés | `assessment/specialists.py`, `python_tools.py` | valódi Arjun, 2 engedélyezett név, pozitív/javított HTTPS-fixture; nem automatikus minden URL-en |
| 4.1 SQLi-specialista megfigyelt kérésből | `sqlmap_validate`, meglévő `AuthReplayVault` | valódi SQLite SELECT + sqlmap boolean-only; host-only named actor; sessionlejárat 0 célkérés |
| 4.1 XSS browser-megerősítés | `dalfox_validate`, `browser_xss_confirmation`, `browser.py`, `store.py` | Dalfox candidate után külön tartós Chromium-job, valódi nonce-alert és benign kontroll, atomikus finding-promóció |
| 8 tartós scheduler, nem egyszerre induló toolok | `runtime.py`, `scheduler.py`, `rj_specialist_followup` | runtime/store újranyitás, outbox/dedup, két valódi CLI-processz, rate-változás utáni 0 ismételt kérés |
| 10–12 korlátok és hibaágak | közös pinned runner, supervisor, proxy, resource governor | valódi TERM/KILL/process- és lease-cleanup; timeout/cancel, 429/redirect, rossz CA/digest; nincsenek negatívként jelentett hiányok |
| 13 angol skillek | 3 célzott angol kontraktus és manifest frissítve, readiness konfigurációfüggő | 44 további assessment-skill változatlan, eredeti source-provenance megőrizve |

Az új specialisták támogatott inputja GET/query. POST/JSON/form/multipart
mutáció, named-actor Dalfox/browser és stored/DOM-only XSS külön unsupported;
a korábbi Nuclei POST/session integráció megmarad. A teljes master prompt
elfogadása továbbra sem állítható. Eredmények és blokkolók:
[aktuális mérési jegyzőkönyv](redjohn-specialists-verification.md).


### 2026-10-18: selected TInjA / Schemathesis / Interactsh

The current implemented profiles use actual captured anonymous GET inputs,
pinned TInjA 1.2.0 / Schemathesis 4.31.1, and a host Interactsh 1.4.1 protocol
client with an owned receiver and durable late polls. Scanner/callback signals
remain candidates. Broad API/GraphQL, body/auth mutation and public DNS OAST
are separate coverage gaps. See `docs/redjohn-schema-oast-verification.md`
and `RedJohn/docs/schema-oast-adapters.md` for current evidence and bounds.

## Authenticated schema/OAST continuation (2026-10-18)

Selected named POST JSON/form/multipart fields, private byte-preserving transport,
protected body tokens, same-actor refresh and fresh-capture children are implemented
in `assessment/input_replay.py`, `schema_tools.py`, `oast.py`, `browser_workflow.py`.
Actual verification and explicit blocked/unsupported boundaries: [report](redjohn-authenticated-schema-oast-verification.md).

## MIME and restart continuation (2026-10-18)

Per-request body contract 2 accepts bounded equivalent MIME spelling, UTF-8
charset and quoted multipart boundary representations while preserving raw
headers and body bytes. Legacy approvals retain their exact contract. CLI
deadline denials now expose a safe constant reason; absolute authorization
expiry remains enforced. Native specialist admission stops immediately after a
complete trusted authentication failure. See the [runbook](../RedJohn/docs/mime-replay-and-restart.md)
and [actual verification](redjohn-mime-restart-verification.md).
