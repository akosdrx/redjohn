# RedJohn — a teljes feladat követett állapota

**2026-10-18, felhasználói pontosítás:** az élő cloud/Kubernetes-hozzáférést
igénylő ellenőrzések későbbre halasztva; most nem kérünk és nem használunk ilyen
hozzáférést. Az adapterek, a konfiguráció- és jogosultsághatárok, valamint a
saját kontrollált célokkal elvégezhető tesztek továbbra is fejlesztési feladatok.
A halasztott élő igazolás nem sikeres integráció és nem negatív vizsgálat.

2026-10-19. A kiválasztott regressziós és integrációs csomag teljes hosted Ubuntu 24.04 x64/ARM64
validációja lezárult a `fd7c0d41df9204e57d8136194336bee2e2378a93` source commiton
(tree `1cda168ca12323c4c078e221e6a2e51e87a6c8ec`). A részletes követelménykapcsolat:
[master-követés](redjohn-requirements.md); a kódból generált állapot:
[képességkatalógus](redjohn-capabilities.md).

**2026-10-20 pontosítás:** a fenti történeti futás nem igazolt WPScan runtime-ot
vagy Trivy SBOM advisory matchinget. Ezek nyilvános runtime-bekötése elkészült, és
az új [natív futás](https://github.com/akosdrx/redjohn/actions/runs/39498243803)
lezárult: mindkét architektúrán **4 WPScan + 7 SBOM E2E sikeres, 0 fail/error/skip**,
source SHA `9f3a1a037b2f44bf1b503e2c796a0682f1ba146c`. Ugyanezen a forráson a
[teljes Ubuntu-kör](https://github.com/akosdrx/redjohn/actions/runs/39498243880) is
**sikeresen lezárult**: platformonként **1558 Python-regresszió + 454 valódi
integráció + 14 frontend + 21 Go**, 0 hiba/error/skip. A 207 Python-mock és a
6 frontend fetch-dublőr külön címkézett; 3 Darwin-eset Linuxon nem alkalmazható,
nem futott és nem sikeres teszt. A külön natív körben további 3 ismételt kernel
orphan-recovery kontroll sikeres platformonként. [Részletes mérések és fájllista](redjohn-artifact-runtime-verification.md).
Az új teljes push-futás 2 vegyes ciklust mért (x64 19.281431 s, ARM64 16.866308 s);
ez nem új 20 perces soak. A korábbi hosszú terhelés igazolása történeti marad.
[Pontos hatókör](redjohn-artifact-runtime.md).

**2026-10-21 hosszú terhelés:** az új `3cc92d20ee37fe54663dc7c25a73aeb802f98ef1`
SHA-n a kézzel indított [39505094482 futás](https://github.com/akosdrx/redjohn/actions/runs/39505094482)
**mindkét architektúrán sikeresen lezárult**. Platformonként 120 valós ciklus /
360 scheduler-job; benchmarkidő x64 **1208.382665 s**, ARM64 **1205.942122 s**,
minimum 1200 másodperces, ütemezési várakozást is tartalmazó ciklusablakkal.
Mind a 15 invariant igaz; a teljes csomag platformonként 1558 regresszió +
454 valódi integráció + 14 frontend + 21 Go, 0 hiba/error/skip.
[A nyers időadatok különbsége, RSS-mérések, verziók, artifact-hashek és korlátok](redjohn-long-soak-3cc92d2.md).

## Aktuális fejlesztési és igazolási határ

**2026-10-21: új, közös kernelhatárral lezárt teljes kör.** A
[`39526474772` Actions-futás](https://github.com/akosdrx/redjohn/actions/runs/39526474772)
`fc1f70dceffa23db653e3bd24d40e27aa7947b21` forrásán mindkét hosted Ubuntu 24.04
architektúrán **1585 Python-regresszió + 456 valódi integráció + 14 frontend +
21 Go** sikeres, nulla fail/error/skip. A regresszióból 208 explicit mock;
a frontendből 6 fetch-dublőr. A 3 Darwin-eset Linuxon nem alkalmazható.
Platformonként **120 ciklus / 360 scheduler-job / 720 kérés**, kifejezetten mért
ciklusablak x64 **1200.156791 s**, ARM64 **1200.326945 s**; valódi pre-exec
**2 GiB owner / 4 GiB aggregált cgroup**, nulla swap és igazolt cleanup.
Minden korábbi aktív teszteset megmaradt. A kernelkorlát és ez a hosszú Ubuntu-kör
lezárt; az alábbi történeti táblák ezeket nem nyithatják újra hiányként.

A memóriafeltárás eredménye részleges, számszerű: a lezárt cache 6,291,462 bájtos
payloadja nullára csökken; a külön glibc-diagnosztika x64-en 48,861,184,
ARM64-en 30,728,192 resident bájtot adott vissza. A fennmaradó controller-private
emelkedés **44,724,224 / 50,884,608 B**, teljes oka továbbra sincs igazolva;
általános szivárgásmentességet nem állítunk.
A [külön modelles futás](https://github.com/akosdrx/redjohn/actions/runs/39526571218)
mindkét platformon hozzáféréshiány miatt **blokkolt**: nincs kijelölt modell és
dedikált CI-secret; platformonként egy JUnit error, nulla valódi modellhívás.
[Teljes fájllista, parancsok, rollback, nyers mérések és artifact-hashek](redjohn-resource-closure.md).

A következő végrehajtott változtatások és az új igazolás követése:
[teljes terhelés memóriakorlátja és tiszta Python-környezet](redjohn-resource-closure.md).
Az alábbi régi baseline-táblák nyitott soraiból **nem aktuális hiány** a reviewed
login/MFA/logout, GraphQL/CRUD workflow, inventory lifecycle, bővített charset/XML/
multipart replay, bounded legacy cache és helyi anonim target-MCP. Ezek már
implementáltak; a `3cc92d2` teljes x64/ARM64 integrációs JUnitja például 5 auth,
1 GraphQL, 2 wire-replay, 45 input-replay és 4 target-MCP esetet igazol
platformonként. A generált registry feltételes kódstátusza nem írja felül a
konkrét SHA-hoz kötött natív jegyzőkönyvet, és nem állít minden új hoston készséget.
Az aktuális nyitott core igazolás a valódi modelles CLI/TUI-hozzáférés és a
fennmaradó controller-memória teljes attribúciója. A globális workload-kernelkorlát,
a hosszú hosted kör és a dokumentációs hiánylisták pontosítása elkészült.

A korábbi, teljesen lezárt és mindkét architektúrán (`Ubuntu 24.04 x64 / Python 3.13.16`
és `Ubuntu 24.04 arm64 / Python 3.12.3`) **sikeres (`conclusion: success`)** forrás a
`fd7c0d41df9204e57d8136194336bee2e2378a93` commit:

- **Teljes Ubuntu-validáció ([Run 39241380765](https://github.com/akosdrx/redjohn/actions/runs/39241380765), attempt 2):**
  platformonként **1548 Python-regresszió** (`1341` `unit_contract_or_mixed` + `207` `mock_contract`),
  **443 valódi integráció** (`real_integration`), **14 frontend** (`8` unit/contract + `6` fetch-dublőr),
  **21 Go TUI teszt**, valamint **120 ciklusos / >1200 másodperces vegyes terhelés (`mixed_soak`)**
  (`x64`: `1206.78s` aktív ciklusidő / `1208.65s` teljes idő, `781324288 B` peak RSS, `5822` minta;
  `ARM64`: `1206.21s` aktív ciklusidő / `1208.02s` teljes idő, `804315136 B` peak RSS, `5720` minta;
  mind a 15 erőforrás-/izolációs soak-invariant `true`). Hiba és teszt-skip **0** (`failed=0, errors=0, skipped=0`);
  a 3 `Darwin`-specifikus shell-eset (`tests/test_legacy_shell_darwin_live.py`, amelyek macOS-en helyben `3 passed` eredménnyel futnak)
  és a 4 külön opcionális candidate-fixture eset (`tests/test_wpscan_observe_live.py`) expliciten
  a `non-applicable-integration.json` jegyzékben szerepel. Mindkét platform **789 forrás- és 295 bizonyítékfájl-hashe**
  (`evidence-index.json`) függetlenül ellenőrizve (a hivatkozott Actions-futás artifactjaiból; a régi helyi méréskönyvtár nem része az aktuális checkoutnak).
- **Natív komponens smoke ([Run 39241380785](https://github.com/akosdrx/redjohn/actions/runs/39241380785), attempt 1):**
  x64 és ARM64 oldalon egyaránt **1548/1548 Python-regresszió** és **24/24 valódi natív komponenseset**
  (`cleanup-proof`: 1, `lab`: 4, `memory`: 6, `network`: 8, `preparation`: 1, `service`: 4),
  **0 hiba, 0 skip**. Mindkét platform **789 forrás- és 73 bizonyítékfájl-hashe** (`native-evidence-index.json`)
  ellenőrizve (a hivatkozott Actions-futás artifactjaiból).

A korábbi `9ff92a8abf4e5ad516bef7b3ce4dd297ea82055c` source commit
[39151591978 futása](https://github.com/akosdrx/redjohn/actions/runs/39151591978) és
a `61f209e0d0e9bc094316017da0de613b907aeecf` forrás
[39157069204 natív futása](https://github.com/akosdrx/redjohn/actions/runs/39157069204)
megőrzött köztes mérföldkövek ([fázis 3](redjohn-github-actions-master-phase3.md),
[fázis 4 natív](redjohn-github-actions-master-phase4-native.md)).
A helyi Git `HEAD` (`115c7958232f1be5b34fe95159b21b86e85af06f`), `.git/index`
(`95c507103b42959002663306e132127a1c2fbc4b0d3c04b4c2b97283ad8419db`) és
privát MCP-konfiguráció (`~/.redjohn/mcp-servers.json`) végig változatlan maradt.

A teljes megvalósított és célzottan igazolt műszaki terjedelem:

- Semgrep/Trivy offline source, asset/service/workflow inventory, kétactoros
  autentikált CRUD és tartós restart/refresh a történeti futásban igazolva.
  A Trivy offline CycloneDX SBOM-profil külön új igazolási kör; lásd a fenti pontosítást.
- Naabu/dnsx külön engedélyezett IP/port/resolver scope-pal, tartós kvótával és
  izolált workerrel (8 valódi x64/ARM64 natív és integrációs eset).
- Nmap 7.992 korlátos, saját próbaprofillal kész; mind a 4 valódi natív eset
  sikeres x64/ARM64 oldalon (SSH/HTTP/false relay-open/cancel). A build, pontos
  verzió/licenc/probe és az előző Naabu-open bizonyíték is ellenőrzött.
  Ez szűk szolgáltatásmegfigyelés, nem általános NSE/product-version audit.
- Login/logout/MFA és egyszerhasználatos inputok tartós flow-val, Chromium
  capture-rel és Nuclei-replayjel; valódi pozitív/javított esetek sikeresek.
  A megszakított MFA után létrejött ismeretlen szerveroldali session külön
  bizonytalanság, nem automatikus siker vagy rollback.
- Pinned GraphQL-séma/operation és privát object-ID állapot, kétactoros valódi
  TLS CRUD/restart/cross-actor kontroll.
- V3 vendor JSON UTF-16 és XML Latin-1 Chromium–Nuclei lánc, valamint a specialisták
  kiválasztott ismételt mező/text-file/XML profiljai és automatikus refresh-e:
  [pontos mérések és korlátok](redjohn-extended-input-replay.md).
- Az általános MCP megmaradt. A verzió-/séma-/account-/repository-kötött
  provider műveletek és az anonim exact-GET target MCP külön határokkal futnak;
  4 valódi izolált target-MCP eset sikeres x64/ARM64-en. Autentikált/mutáló target
  MCP és attesztálatlan távoli végrehajtás továbbra is blokkolt.
- A Linux opt-in CLI/TUI/SDK tulajdonos és örökölt leszármazottainak közös
  cgroup-memóriakeretéből mind a 6 natív kontroll, a `cleanup-proof` (`test_cleanup_quarantine_live.py`)
  és a Chromium/SDK/MCP/native együttes eset (`test_owned_memory_live.py`) is sikeresen lefutott
  mindkét hosted Ubuntu 24.04 architektúrán.
- Owned local header-regression (`lab_validation`, `redjohn-owned-header-lab-1`) és
  proof-bound korreláció (`ProofBoundCorrelation`): mind a 4 valódi Linux izolációs E2E eset
  (`positive`, `slow`, `oversized`, `cancel`) sikeresen lefutott `x64` és `ARM64` alatt
  mind a natív smoke (`39241380785`), mind a teljes Ubuntu-validáció (`39241380765`) során:
  [részletes leírás](redjohn-owned-lab-component.md).
- WPScan offline komponensmegfigyelő adapter (`redjohn-wpscan-observe-1`) és Ruby/gem/licenc
  provenance-audit implementálva (`redjohn-wpscan-observe-component.md`, `redjohn-wpscan-component-audit.md`).
- Cloud/Kubernetes manifest-előkészítés külön capabilityvel kész; a natív
  kube-bench izolált verzióparancsa valóban sikeres mindkét hosted architektúrán.
  Ez nem cluster-benchmark; csak a verzióparancs engedett. Élő cloud/Kubernetes audit
  a felhasználói döntés szerint halasztott, Prowler teljes immutable függőségpillanatkép hiányában blokkolt.

Az alábbi táblák történeti baseline-ok. A legfrissebb teljes és hosszú igazolás a fenti
`fc1f70dceffa23db653e3bd24d40e27aa7947b21` forrás; a régebbi hosszú soak
adatai a saját SHA-jukhoz tartoznak. A külön mérési dokumentumok rögzítik a hatókört.

## Korábbi közös-runtime baseline

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

Az alábbi táblázat történeti hiánylista, nem a jelenlegi registry állapota:
a Semgrep/Trivy szűk source-, Naabu/dnsx- és Nmap-profil azóta implementált és
fent SHA-hoz kötött bizonyítékkal szerepel. A fennmaradó szélesebb módokhoz a
közös inventory/policy/resource mechanizmus és valódi igazolás szükséges;
egy mock worker nem igazol működő integrációt.

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
a `tools/cve/tool.py:_CveCache._mem` korlátlan dictet használt;
a `runtime/session_manager.py` session-cache és lock-registry erős referenciákat
tartott. Ezek az új [bounded cache/lifecycle](redjohn-legacy-cache-lifecycle.md)
implementációban javítva vannak. Az aktív session/resource állapot nem dobható el egyszerű LRU-evictionnel:
a közös runtime-hoz kötött admission és igazolt cleanup szükséges. A meglévő
általános MCP/CVE funkciók és a felhasználó konfigurációi megőrzendők.

A régi CVE-cache külön, offline saját SQLite-korpuszú mérése 384 bejegyzésből
383 lejártat továbbra is memóriában tartott más cache-művelet után. A megmaradó
JSON-payload 50212341 B (47.89 MiB), míg az assessment cache-kerete 33554432 B.
Ez a régi cache közös kvótába kötésének hiányát igazolja; nem scanner-E2E vagy
teljes host-heap leak bizonyíték. A nyers adat:
`docs/measurements/host-binding/legacy-cache-before.json`.

A GitHub-hozzáférés később a connectorral ténylegesen helyreállt: a hitelesített
fiók `akosdrx`, a repository `akosdrx/redjohn`; admin/push/pull hozzáférés ellenőrizve.
A helyi `gh` továbbra is `itsolutionshu`, nem módosult. A teljes Ubuntu-mátrix
GitHub Actionsbe került. A korábbi 925 pass / 300 capability-skip után a Chromium/
namespace-blokkolás jobhoz kötött enforcing AppArmor-profillal javítva; a globális
userns-korlátozás bekapcsolva marad, a nem jogosult profilváltás tiltása szigorodik.
A [teljes tényleges újramérés](https://github.com/akosdrx/redjohn/actions/runs/39139076653)
lezárt státusza **success**: x64 és ARM64 platformon egyaránt **1225 sikeres,
0 hibás, 0 skip**, ebből 320 valódi integráció. A Chromium–inventory–Nuclei,
autentikált replay/session refresh, scanner-, scheduler-, kernel OOM- és cleanup-
láncok ezen a konkrét SHA-n igazoltak: `57141b25ed32169e24d0065b4bc21a0422e83fab`.
[Pontos SHA-k, mérések és korlátok](redjohn-github-actions-sandbox-verification.md).
Új teljes helyi Ubuntu-regresszió nem indult; Colima megmaradt célzott hibakeresésre.

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
