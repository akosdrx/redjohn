# RedJohn — a teljes feladat követett állapota

2026-10-18. A cél a master prompt fennmaradó részeinek megvalósítása. A feladat
aktív; az alábbi lista a teljes megmaradó hatókört őrzi. Egy szakasz tesztje
nem helyettesíti a teljes rendszer elfogadását. A részletes követelménykapcsolat:
[master-követés](redjohn-requirements.md); a kódból generált állapot:
[képességkatalógus](redjohn-capabilities.md).

## Legfrissebb, még le nem zárt bekötési szakasz

A közös konfigurációs factory, a korlátos host-controller és az SDK-context
`assessment_service` / `assessment_governor` bindingje már bekerült a kódba.
A CLI és TUI átadja a host által jóváhagyott konfigurációt; a privát,
aláírt run-snapshot és a control-plane írásvédett mountjai is implementáltak.
Az automatikus általános MCP-warmup hívás kikerült a runnerből; az általános
MCP-támogatás megmaradt. Ez még nem jelenti a régi eszközök teljes közös
policy-/resource-kezelését vagy a felhasználói CLI/TUI E2E lezárását.

A korábbi három konfigurációs hiba javítva. A puszta inventory-import nem kér
DNS-t vagy hálózati engedélyt; a tényleges jobok egress-ellenőrzése megmaradt.
A natív Nuclei-session és a scheduler ugyanazt a tartósan kanonizált policyt
és határidőt kapja. A policy-váltás, a határidő és a teljes engagement-cancel
leállítja a pumpot; a riport megőrzi az okok közötti különbséget.

Az új snapshot v2 aláírt, UID-/caller-/run-directory-kötött. Hibás MAC,
hiányzó kulcs és másik könyvtárba másolt snapshot stabil elutasítást ad.
A hibás resume-fájl byte-jai megmaradnak; a szabályos SDK-folytatás megtartja
az előzményt és a közös queue-t. Sikertelen indulás, riportírás és komponenszárás
hibainjektálása külön ellenőrzi a többi tulajdonolt erőforrás lezárását.

A végső célzott csomag macOS-en 104/104 sikeres, 19.61 s; Linuxon 104/104,
18.36 s. Az új 43 esetből 5 tényleges SDK/HTTPS/browser/Nuclei/processz-lock
integráció, 38 kontraktus vagy hibainjektálás. A root runner modell- és sandbox-
indítása tesztdublőrt használ; ez nem teljes felhasználói CLI/TUI E2E.

A 412 rögzített bemenetet (295 Python-forrás, promptok, runtime-adatok, Viewer,
eredeti és natív skillek) használó friss teljes kör sikeres: Linuxon 1225/1225,
macOS-en 1154 sikeres / 71 kernel-/namespace-skip, hiba nincs. A strict mypy
mindkét platformon 204 production modullal sikeres. A végső ledgerek üresek,
elveszett owner és hash-/forráslista-eltérés nincs. A külső RSS-csúcs
857.22 / 1237.13 MiB, a teljes külső idő 825.99 / 1044.18 s.
A resume-regresszió megtalálásakor az előző kört szándékosan megszakítottam;
ezek a részleges JUnitok és mérések megmaradtak, nem teljes sikeres regressziók.
A részletes [friss ellenőrzés](redjohn-host-binding-verification.md) külön jelöli
a valódi E2E-t és a tesztdublőröket; az alábbi resource-mérés történeti baseline.

| Terület / master | Jelenlegi bizonyíték | A lezáráshoz még szükséges |
|---|---|---|
| Közös CLI/TUI/agent futtatás, 3/8/14/19 | Közös factory/host-pump és caller-bound service a root/child SDK-contextben. Valódi SDK/Chromium/Nuclei, restart/fixed, HTTPS cancel/deadline és külső processz-lock integráció sikeres; privát snapshot és hibás/valid resume külön ellenőrzött. | CLI/TUI teljes felhasználói E2E, teljes provider/MCP hibamátrix és a régi eszközök ugyanazon policy/scheduler/resource-életciklusba kötése. |
| Erőforrás és memória, 5.12/10 | Külön kampány-DB-k között atomikus host-foglalás; valódi többprocesszes és Chromium E2E. A dedikált Linux CLI cgroupba lép exec előtt; OOM és árva worker ellenőrzött. | A régi runtime-ok, idle controller/cache fogyasztás és hostszintű összesített OS-keret teljes közös kezelése. Az új közös admission és a dedikált CLI hard limit külön garancia. |
| Tartós backpressure, 8/10/12 | Kérés előtti host-kapacitáshiány tartós `retry_wait`; azonos controllerben automatikus folytatás. Idempotencia, request-admission, retry-/attempt-/deadline-keret érvényes. | A teljes régi futtatási út bekötése és a hosszú terhelés alatti ellenőrzés. Nem idempotens vagy már admissiont kapott munka nem ismétlődik automatikusan. |
| Cache és hibakezelés, 5.8–5.11/11/12 | Bájtkorlátos LRU/TTL/singleflight és revision-alapú invalidálás megvan. A kernel-OOM bizonyítéka kvótázott evidence-be kerül. | Régi globális cache-ek migrációja; teljes provider/MCP timeout/cancel/shutdown hibamátrix. |
| Inventory, 7 | Tartós surface/request/input/actor/session/job/evidence core és restart-visszaállítás megvan. | Teljes asset/service/workflow életciklus, API és kapcsolatok a specialistákhoz. |
| Technológia/intelligence, 5.2–5.3 | Header/httpx megfigyelés, CVE-ID lookup, tartós kvóta és metadata-cache megvan. | Nmap/source/browser bizonyítékok teljes összekapcsolása; verzióellentmondások és érintettség szélesebb valós kontrolljai. |
| Korreláció és reproducer, 5.4–5.5/16 | Bounded gráf és előfeltétel-vizsgálat; saját helyi header/fixed kontroll. | Szélesebb valódi labláncok, validált reproducer tényleges izolált futtatása, positive/fixed/cleanup bizonyíték. |
| Auth és web-workflow, 6/8 | Privát session-vault, explicit refresh, Chromium POST-capture, body-token rotáció és friss replay működik. | Általános login/logout/MFA/egyszerhasználatos nonce workflow; állapotfüggő API/GraphQL/CRUD és cleanup. |
| További bemenetek, 6/7/9 | Korlátos UTF-8 JSON/form/multipart, MIME-variánsok és byte-megőrző replay igazolt. | További charset/XML/vendor JSON, ismételt kijelölt mezők és külön jóváhagyott file-part műveletek. A mai unsupported állapot nem negatív vizsgálat. |
| OAST, 4/12/15 | Saját receiverrel valódi HTTP(S) protokoll, késleltetett poll, POST és session refresh igazolt. | Nuclei–OAST binding; DNS/IPv6 és publikus elérhetőség külön igazolása. Publikus infrastruktúra hiányában a live bizonyíték blokkolt marad. |
| Teszt és mérés, 17 | A host-binding teljes köre Linuxon 1225 sikeres / 0 skip, macOS-en 1154 sikeres / 71 kernel/namespace-skip; hiba nincs. JUnit, memória, 412 input hash és üres végső host-ledger rögzített. A korábbi resource-snapshoton mindkét platformon 100 ütemezett HTTPS browser-ciklus / 400 HTTP-kérés / közel 497 s, lezárt page/context/proxy/foglalás igazolt. A frontend typecheck/build és a TUI fordítása azon a snapshoton sikeres. | A warmup utáni RSS-emelkedés okának profilozása, hosszú vegyes scanner/cache/maximális body/log/queue terhelés és a teljes lifecycle elfogadása nyitott. A böngészős mérés nem scanner-soak; a TUI fordítása nem interakciós E2E. Azonos régi baseline hiányában nincs kitalált gyorsulás. |
| Platform és kiadás, 17/20 | macOS ARM64 és Ubuntu ARM64 helyi tesztkörnyezet rendelkezésre áll. | Valódi Kali/AMD64 ellenőrzés, csomagolás, tiszta telepítés/upgrade és kiadási validáció. GitHub-futás csak tényleges sikeres run után igazolt; helyi reprodukáló parancs külön bizonyíték. |
| Dokumentáció, 18–21 | A képességkatalógus most a tényleges registryből generálódik. | A következő implementációk után követelmény-, migráció-, licenc-/verzió- és kiadási dokumentumok végleges összhangja. |

Az alábbi opcionális adapterek ténylegesen hiányoznak. Implementációjuk a fenti
közös inventory/policy/resource mechanizmusokat használja majd; a szerződés vagy
egy mock worker önmagában nem változtatja őket működő adapterré.

| Capability | Tool | Kötelező feltétel és ellenőrzés |
|---|---|---|
| `semgrep_source` | Semgrep | Explicit forrás-artifact, külön bounded worker, reviewed rule, pozitív/javított forráskontroll. |
| `trivy_source` | Trivy | Explicit source/image/SBOM, verziózott adatforrás és feltételek, bounded worker, valós engine. |
| `naabu_ports` | Naabu | Kijelölt IP/port scope, megfelelő egress, unprivileged profil; privilege-hiány nem automatikus jogemelés. |
| `nmap_services` | Nmap | Jóváhagyott portok, bounded service detection; NSE kizárólag reviewed allowlisttel. |
| `dns_discover` | Amass / Subfinder / dnsx | Kiválasztott felderítési mód, resolver/provider kvóta, új asset még nem aktív tesztengedély. |
| `wordpress_assess` | WPScan | WordPress bizonyíték, licenc-/adatbázisfeltételek, saját pozitív/javított kontroll; credential-hiány külön coverage. |
| `cloud_assess` | Prowler | Explicit account/project/region és auditjog. Hozzáférés nélkül a fixture nem live cloud-igazolás. |
| `kubernetes_benchmark` | kube-bench | Verzióazonosított cluster/benchmark és megfelelő hozzáférés; automatikus root/host mount/cluster-admin nincs. |

A master szerint tudatosan halasztott alternatívák: Feroxbuster, Gobuster,
RustScan, Masscan, AutoRecon, ScoutSuite, kube-hunter, binary triage
(GDB/angr/pwntools) és Commix. Nem indulnak alapértelmezésként, és nem alkotnak
még egy beágyazott orchestrátort.

Az eredeti történeti RCE-fixture hiányzik. Állapota
`not_reproduced_missing_fixture`; a saját marker/header/SSTI kontroll nem írja
ezt át bizonyított eredeti RCE-vé. A core fejlesztése ettől folytatódik.

A közös-runtime bekötés a `core/runner.py` SDK-context összeállításánál adja
át a host-oldali szolgáltatást. Az `agents/factory.py` regisztrálja az
`assessment_control` toolt; a `core/execution.py` gyermek-agentjei a szülő
context másolatát kapják. A két felületi hívó az `interface/cli.py:run_cli`
és az `interface/tui/runtime.py:TuiRuntime._run_scan`. Az
`assessment/configuration.py`, `assessment/host.py` és
`assessment/host_binding.py` használja újra a tartós assessment queue-t.
A szolgáltatásobjektum a tool-contextbe kerül, a prompt csak szűkített
metadata-t kap. A régi Shell/MCP-dispatch teljes közös policy- és
erőforrás-kezelése ettől még nyitott; a binding önmagában nem zárja ezt le.

A további lifecycle-audit konkrét találatai: az automatikus
`McpRegistry.start_warmup(max_concurrency=6)` runner-hívás már kikerült;
a `tools/cve/tool.py:_CveCache._mem` továbbra is korlátlan dictet használ;
a `runtime/session_manager.py` session-cache és lock-registry erős referenciákat
tart. Az aktív session/resource állapot nem dobható el egyszerű LRU-evictionnel:
a közös runtime-hoz kötött admission és igazolt cleanup szükséges. A meglévő
általános MCP/CVE funkciók és a felhasználó konfigurációi megőrzendők.

A régi CVE-cache külön, offline saját SQLite-korpuszú mérése 384 bejegyzésből
383 lejártat továbbra is memóriában tartott más cache-művelet után. A megmaradó
JSON-payload 50212341 B (47.89 MiB), míg az assessment cache-kerete 33554432 B.
Ez a régi cache közös kvótába kötésének hiányát igazolja; nem scanner-E2E vagy
teljes host-heap leak bizonyíték. A nyers adat:
`docs/measurements/host-binding/legacy-cache-before.json`.

A GitHub-hozzáférést ismét ténylegesen ellenőriztem: a helyi `gh` aktív fiókja
`itsolutionshu`, ezzel az `akosdrx/redjohn` repository nem oldható fel. CI-run és
push nem történt; a helyi macOS/Linux ellenőrzés ettől továbbhalad.

A forrás megőrzési baseline-ja 1506 meglévő fájlt, 70 aktív Python teszt/support
forrást, 11 host-managed engine-t, HEAD/origin/index és privát MCP-konfiguráció
hashét rögzítette. A resource-szakasz első ellenőrzése 354 rögzített fájlt
használt; a javított regresszió 396 bemenetet ellenőriz, a Viewer statikus
fájljaival és az eredeti skill-forrásokkal együtt. A 285 Python-forrásból a
70 régi teszt/support forrás továbbra is byte-azonos a megőrzési baseline-nal.

A javított resource-kód teljes regressziója sikeres, a teljes master prompt
feladata továbbra is aktív. A 201 production modult ellenőrző strict mypy
mindkét platformon a resource-snapshotra sikeres; ez nem a későbbi binding-kód
teljes ellenőrzése. A célzott tesztek, a teljes regresszió és a külön
workload-mérések eredményét külön kell értelmezni; a korábbi hibás teljes
futások megőrzött diagnosztikai bizonyítékok.
