# REDJOHN — TELJES FEJLESZTÉSI MASTER PROMPT

**Verzió:** 2.0 · **Követelményállapot:** 2026-10-17 · **Nyelv:** magyar

Ez implementációs megbízás a meglévő **RedJohn** projekthez. A dokumentum a korábbi, Strix-forkot feltételező master prompt HELYÉBE lép. Nem egy már elkészült implementáció leírása. Az alább javasolt új modulnevek, kontraktusok és konfigurációs mezők követelmények; létezésüket ne feltételezd a repositoryban.

## 0. NEM MEGVÁLTOZTATHATÓ ALAPOK

1. A projekt neve **RedJohn**, és az is marad. Ne nevezd át a repositoryt, alkalmazást, csomagot, CLI-t, UI-t, konténerprojektet, adatbázist vagy publikus API-t Strixre, HexStrike-ra vagy másra. A már meglévő technikai azonosítókat csak bizonyított kompatibilitási okból változtasd, dokumentált migrációval. Kötelező külső szerzői és licenchivatkozásokat őrizz meg: ez nem termékátnevezés.
2. **A RedJohn aktuális kódja az elsődleges.** Ne feltételezd, hogy változatlan Strix-fork, hogy Python a teljes backend, vagy hogy Caido, Playwright, MCP és egy adott adatbázis már működik benne. A felhasználó szerint Nuclei már van: ezt vizsgáld meg és használd újra, ne telepíts automatikusan második példányt.
3. **Headless browser kötelező:** Playwright + Chromium vagy a meglévő, igazoltan kompatibilis Playwright-réteg. A browseres felderítés nem váltható ki pusztán HTTP-crawlerrel.
4. **Firecrawl kizárt.** Új Firecrawl-függőséget, adaptert és konfigurációt ne hozz létre. Régi integrációt a migrációban kapcsold ki; ne törölj meggondolatlanul felhasználói adatot.
5. Strix és HexStrike kizárólag **külső referencia vagy célzott komponensforrás**. A szükséges forrást letöltheted izolált referencia-munkakönyvtárba, de ne másold rá a RedJohnra, ne indítsd el egy második teljes platformként, és ne importáld ellenőrizetlenül a teljes eszközarzenált.
6. A platform előzetesen engedélyezett célokon, kezdeti konfigurálás után önállóan működjön. A futási szabályokba nem illő feladatot automatikusan blokkolja és dokumentálja. A teljes automatizálás nem jelent korlátlan célválasztást vagy megengedett hatások önkényes bővítését.
7. A feladat tényleges kódmódosítás, integráció, teszt és dokumentáció. Ne állj meg tanácsnál, roadmappnél vagy működőnek nevezett stuboknál. Valódi környezeti blokkolónál adj konkrét státuszt és a rendelkezésre álló környezetben ellenőrzött részmegoldást. Ne állíts futtatást, hálózati ellenőrzést vagy benchmarkot bizonyíték nélkül.

## 1. A MEGOLDANDÓ PROBLÉMA

A korábbi működés lassú volt, sok LLM-inputot használt, és egy ismert RCE mellett hosszan SQLi-vizsgálatra koncentrált. A régi RCE pontos mechanizmusa, kérése és fixture-je nincs automatikusan megadva: ne találd ki.

A RedJohnban a következő láncot kell mérhetővé és tartóssá tenni:

`engedélyezett felület -> megfigyelt végpont -> bemenet és állapot -> alkalmazható teszt -> tényleges végrehajtás -> bizonyíték -> validált megállapítás -> lefedettség és újrateszt`

A cél nem minél több toolindítás vagy minél több LLM-agent. A cél releváns vizsgálatok megbízható végrehajtása, kisebb token- és memóriaigénnyel, ismétlés és elkalandozás nélkül. Nem vállalható általános, minden hibára kiterjedő detektálási garancia.

## 2. REPOSITORY AUDIT ÉS MEGLÉVŐ MUNKA VÉDELME

Első lépésként ténylegesen vizsgáld meg a hozzáférhető repositoryt és a futtatási környezetet.

- Olvasd el a README, AGENTS, fejlesztői útmutató, lockfile, konfiguráció, migráció és CI releváns részeit.
- Rögzítsd az aktuális verziót, git állapotot és a már módosított fájlokat. Ne használj destruktív resetet, clean parancsot vagy felhasználói módosítást felülíró másolást.
- Térképezd fel a browser-, proxy-, HTTP-replay-, Nuclei-, agent-, skill-, memória-, scheduler-, job-, adatbázis-, MCP- és riportkódot.
- Listázd a ténylegesen telepített toolokat, verziókat, indítási pontokat, input/output formátumokat és elérhető teszteket. A tool létezése, adaptere, regisztrációja és E2E működése négy külön állapot.
- Mérj baseline-t helyi, reprodukálható fixture-ön, ha van ilyen. A hiányzó baseline legyen `baseline_unavailable`, ne kitalált szám.
- Készíts `docs/redjohn-implementation-audit.md` dokumentumot: meglévő képesség, hiány, újrahasznosítás, szükséges változtatás, kompatibilitási kockázat.
- Készíts követelménykövetést: követelmény -> modul/fájl -> teszt -> státusz -> bizonyíték. A követelmények a repository tartós állapotában maradjanak, ne csak chatelőzményben.

### Külső kód célzott átvétele

Strix és HexStrike esetén ellenőrizd a tényleges upstream URL-t és az adott commitot. Rögzítsd a forrást, commitot, érintett fájlokat, licenceket, szükséges függőségeket és az átvétel indokát. A tool, wrapper, szabálykészlet és adatbázis feltételeit külön ellenőrizd. Ne következtesd a wrapper licencéből az összes mögöttes eszköz felhasználhatóságát.

A RedJohn architektúrájához illő kis komponenst vagy tesztet emelj át. Egy kedvező README-állítás nem helyettesíti az implementáció és a hibakezelés ellenőrzését. Ne futtass letöltött installscriptet ellenőrzés nélkül. Ne küldj privát kódot, hitelesítő adatot vagy belső címet külső szolgáltatásnak engedély nélkül.

## 3. CÉLARCHITEKTÚRA: MODULÁRIS REDJOHN, NEM ÚJ PLATFORM

A meglévő technológiai stacket használd. Új keretrendszer, külön adatbázis vagy szolgáltatás csak tényleges hiány és indok alapján kerülhet be.

Logikai adatfolyam:

`EngagementPolicy -> Discovery/Browser/Traffic -> SurfaceInventory -> DecisionEngine + Scheduler -> ToolWorkers -> EvidenceStore -> Validation/Correlation -> Findings/Coverage/Retest`

Keresztmetszeti szolgáltatások:

`ResourceGovernor + MemoryBudgetManager + RateLimitDetector + FailureRecoverySystem + GracefulDegradation + SmartCache + PerformanceMonitor`

A logikai moduloknak nem kell külön mikroszolgáltatásban vagy külön LLM-agentben élniük. Kezdetben jól elkülönített, tesztelhető modulok és csak a szükséges izolált workerek készüljenek. A meglévő adatbázist, feladatsort és objektumtárat használd újra. Ne tegyél be automatikusan Neo4j-t, Redis-t, Temporal-t, LangGraphot vagy más nagy komponenst csak a neve miatt.

Két független konfigurációs dimenzió legyen:

- **Célterület:** `web`, `network`, `source`, `cms`, `cloud`, `kubernetes`, `binary-lab`.
- **Hatásprofil:** `safe-production`, `active-staging`, `isolated-lab`.

Például a `cloud` célterület nem jelent automatikus módosítási jogot; a `web` cél nem engedélyez minden mögöttes IP-n portszkennelést.

## 4. TOOLVÁLASZTÁS — KONKRÉT PRIORITÁSOK ÉS KIZÁRÁSOK

Az alábbi a döntési alap, nem egyszerre telepítendő és elindítandó programlista. Minden adapterhez ellenőrzött telepítési mód, capability-leírás és teszt kell. Az opcionális csomagok ne növeljék a core image-et és ne töltődjenek be induláskor.

### 4.1. Elsődleges web/API-képességek

| Tool / komponens | RedJohn-feladat | Integrációs döntés |
|---|---|---|
| Playwright + Chromium | Headless SPA/UI, elkülönített tesztidentitások, hálózati események, böngészős bizonyíték | Kötelező browser-réteg; meglévő integráció újrahasznosítása. |
| Crawlee PlaywrightCrawler | Crawl-frontier, kérelemsor, újrapróbálás, párhuzamosság | Használd, ha a meglévő crawlerből ezek hiányoznak. Már megfelelő saját queue esetén ne legyen második queue csak a Crawlee kedvéért. |
| Meglévő proxy/traffic, például Caido | Kérés–válasz rögzítés és replay | Előbb auditáld. Caido hiányában ne állítsd, hogy elérhető; használj megfelelő meglévő vagy minimális új traffic adaptert. |
| ProjectDiscovery httpx | Élő HTTP-szolgáltatások és válaszmetaadatok, technológiai jelzések | Ajánlott adapter, főleg több engedélyezett assetnél. Ne keverd a Python `httpx` klienskönyvtárral; a bináris eredetét ellenőrizd. |
| Katana | Gyors link-, JS- és endpointfelderítés | Ajánlott kiegészítő crawler. Standard módot használd előszűrésre; szükséges headless futása ugyanabból a browser-erőforráskeretből fogyasszon. |
| Nuclei + nuclei-templates | Ismert hibák, konfigurációk és adott technológiák célzott ellenőrzése | A meglévő motort erősítsd meg. A motor és template-csomag külön verziózott elem. |
| ProjectDiscovery VulnX | CVE/intelligence-lekérdezés és priorizálási bemenet | Egyetlen intelligence adapter. A régi CVEMap integrációhoz kompatibilitási réteg lehet; ne telepíts két független motort ugyanarra. Nem vulnerability scanner. |
| ffuf | Korlátozott útvonal-/paraméterfelderítés | Elsődleges általános fuzzoló, közös kéréskerettel. |
| Arjun | Megfigyelt végpontok további paraméterneveinek felderítése | Kijelölt bemeneteken, nem minden URL-en automatikusan. |
| sqlmap | SQLi-jelzések specialistával történő ellenőrzése | Valós rögzített kérésből, megengedett profilban. Nem korlátlan adatbázis- vagy shell-hozzáférés. |
| Dalfox | XSS-jelzések célzott vizsgálata | Böngészős kontextussal és megerősítéssel összekapcsolt adapter. |
| TInjA | Template injection vizsgálata | Input- és bodyformátum-támogatást telepített verzióból ellenőrizd; JSONL-fájl támogatása nem bizonyít JSON-body-támogatást. |
| Schemathesis | OpenAPI/GraphQL, generált és állapotfüggő API-tesztek | Séma és tesztadatok esetén. Módosító teszthez fixture és cleanup szükséges. |
| Interactsh | OAST-események gyűjtése és korrelációja | Lehetőleg saját fogadó; a nyers callback nem automatikusan sérülékenység vagy RCE. |
| Semgrep | Forráskód-/adatfolyam-elemzés | Forráskód rendelkezésre állásakor, külön workerben. |
| Trivy | Függőség, image, SBOM és releváns konfiguráció vizsgálata | Artifact/source hozzáférés esetén; nem helyettesíti a dinamikus webes vizsgálatot. |

A katana/httpx/Nuclei saját böngészős funkciói nem indíthatnak észrevétlenül új, korlátlan Chromium-poolt. Egy közös resource governor szabályozza a kapacitást. Nem követelmény, hogy különböző motorok technikailag ugyanazt a Chromium-processzt használják: ezt csak dokumentált, tesztelt támogatással tedd.

### 4.2. Célfüggő hálózati és tartalomfelderítés

| Tool | Döntés | Szabály |
|---|---|---|
| Naabu | Elsődleges portfelderítő a `network` profilban | Explicit engedélyezett IP/CIDR/porttartomány; nem elég egy webes domain megadása. |
| Nmap | Szolgáltatásazonosítás és kijelölt hálózati ellenőrzések | Elsősorban a már felfedezett portokon; NSE csak konkrét, felülvizsgált scriptallowlisttel. |
| Amass | Opcionális mélyebb DNS/assetfelderítés | Asset discovery igény esetén. A HexStrike `amass_enum` függvénynév nem telepítési parancs. |
| Subfinder + dnsx | Opcionális könnyebb DNS-felderítés és feloldás | Csak ha új képességet adnak. Ne fusson Amass mellett automatikusan ugyanaz az összes kutatás. A felfedezett cím még nem engedélyezett aktív tesztcél. |
| Feroxbuster | Opcionális rekurzív content discovery | Kijelölt ffuf-alternatíva vagy mérhetően indokolt második passz. |
| Gobuster | Opcionális helyettesítő | Meglévő bevált integráció vagy külön capability esetén; ne duplikálja automatikusan a másik két directory toolt. |
| RustScan | Opcionális portscanner-alternatíva | Naabu mellett nem alapértelmezett. Csak mérhető előny vagy kompatibilitási szükség alapján. |
| Masscan | Halasztott, külön hálózati profil | A web/API-core-ba ne telepítsd. Nagy, explicit engedélyezett címtartomány igénye esetén külön terv, csomag és terheléskorlát. |
| AutoRecon | Ne legyen beágyazott core orchestrator | A RedJohn schedulerét ne duplikálja. Szükség esetén külső eredményimport; csak indokolt, felügyelhető külön workflowban válhat futtatóvá. |

A felsorolt alternatívák miatt ne építs minden motorhoz azonnal teljes adaptert. A tudatosan kihagyott tool kerüljön a capability-mátrixba `deferred_not_required` indokkal. A felhasználó meglévő, jól működő alternatíváját ne cseréld le puszta ízlésből.

### 4.3. Technológia- és hozzáférésfüggő specialisták

- **WPScan:** WordPress bizonyíték esetén, külön `cms` csomag. API-/adatbázis-hozzáférés hiányában részleges lefedettséget jelents. Licencet és adatbázisfeltételeket ellenőrizd; az integráció ne feltételezzen ingyenes korlátlan adatforrást. Jelszópróbálgatás nem alapfunkció.
- **Prowler:** elsődleges opcionális cloud-posture adapter, explicit account/project/subscription/region és legkisebb szükséges, jellemzően auditjogok mellett. A teljes Prowler UI/agentplatformot ne telepítsd csak a CLI-ellenőrzésekért.
- **ScoutSuite:** alternatív cloud-audit vagy indokolt összehasonlító futás. Prowlerrel együtt ne induljon automatikusan minden accounton.
- **kube-bench:** opcionális Kubernetes-konfiguráció/benchmark ellenőrzés, megfelelő verzióval és hozzáféréssel. Ne adj automatikusan root-, host mount- vagy cluster-admin-jogot egy hibás futás javítására.
- **kube-hunter:** opcionális, alapból kikapcsolt Kubernetes-lab adapter; futtatás előtt ellenőrizd a karbantartási és kompatibilitási állapotot. Nem általános webscanner. Aktív módhoz elkülönített engedélyezett lab kell.
- **GDB, angr, pwntools:** csak külön `binary-lab` fejlesztői/elemző csomag, ha helyi bináris-fixture és konkrét elemzési cél van. GDB crash/backtrace triage, angr erőforráskorlátos elemzés, pwntools helyi tesztharness. Nem általános automatikus web-RCE keresők, és nem kerülnek a core image-be.
- **Commix:** opcionális command-injection diagnosztika kizárólag explicit, eldobható labprofilban. Ne csinálj belőle általános távoli parancsvégrehajtó szolgáltatást.

A felhasználó által említett `gdbdebug`, `pwntoolsexploit`, `angranalyze`, `powlerassess`, `scoutsuite audit`, `trivy scan`, `kube hunter scan`, `kube bench check` neveket normalizáld a megfelelő toolra. A HexStrike `gdb_debug`, `pwntools_exploit`, `angr_analyze`, `prowler_assess`, `scout_suite_audit`, `trivy_scan`, `kube_hunter_scan`, `kube_bench_check` wrappernevei NEM garantált RedJohn-hívások vagy shellparancsok. A helyes terméknév Prowler.

## 5. HEXSTRIKE-INSPIRÁLT SAJÁT MODULOK

Valós szolgáltatásokat készíts, nem osztálynév mögé rejtett általános promptot. Mindegyikhez legyen típusos input/output, tulajdonolt állapot, teszt és telemetria. Ezek a RedJohnban javasolt felelősségek, nem állítások a HexStrike belső minőségéről.

### 5.1. IntelligentDecisionEngine

Feladata a releváns tool/skill/profil kiválasztása az inventory, megfigyelt technológia, aktív policy, erőforráskeret és lefedettség alapján.

- Először determinisztikus jogosultság-, capability-, input- és költségszűrés történjen.
- Ezután megmagyarázható rangsor: új lefedettség, konkrét bizonyíték, bizonytalanság csökkentése, prioritás, frissesség, várható költség.
- A súlyok legyenek konfigurálhatók; kezdetben ne állíts tanuló/RL-optimalizációt tanítóadat és mérés nélkül.
- A fingerprint befolyásolja a prioritást, de a bizonytalan fingerprint ne zárjon ki minden általánosan alkalmazható tesztet.
- LLM csak a szabályokkal nem eldönthető hipotézisekhez kell; tipikus routing és továbblépés modellhívás nélkül menjen.
- Output: `plan_ref`, kiválasztott jobok, elutasított lehetőségek és indokok, becsült keret, prerequisite-ek, coverage delta.
- Az engine javasol; a scheduler foglal erőforrást; a policy végső engedélyt ad. Egyik sem írhatja át önkényesen a másik állapotát.

### 5.2. TechnologyDetector

Kombinálja a böngészős megfigyelést, fejléceket, asseteket, httpx-jelzéseket, engedélyezett Nmap-eredményt és forrásmanifestet. Tartson bizonyítékot, időbélyeget, szereplő/asset kontextust és minőségi jelzést. Külön kezelje a termékazonosságot és a verzióbizonyosságot. Rejtett verzióból, általános fejlécből vagy egy bundle stringjéből ne találjon ki konkrét érintett kiadást. Az ellentmondó forrásokat őrizze meg, ne írja felül némán.

### 5.3. CVEIntelligenceManager

Egy adapteren keresztül kezelje a VulnX/CVEMap átmenetet és szükség szerint a hivatalos advisory/NVD/OSV/KEV/EPSS adatokat. Minden rekordhoz forrás, lekérés ideje, adatverzió és frissesség tartozzon.

A termékverzió-illesztés legyen strukturált és tesztelt. `potentially_affected`, `confirmed_affected`, `not_affected`, `unknown` állapotok különüljenek el. CVE-adatbázisbeli egyezés nem önmagában dinamikusan bizonyított finding. Adatforráshiány ne akadályozza a CVE-független webteszteket. Privát assetlistát ne küldjön ki automatikusan külső keresőnek.

### 5.4. VulnerabilityCorrelator

Készíts bizonyítékalapú kapcsolatmodellt az assetek, identitások, objektumok, technológiák és findingek között. Kapcsolattípusok például közös gyökérok, előfeltétel, elérhetőség és lehetséges hatásnövekedés.

A lánc `hypothesized`, `partially_supported`, `validated_in_lab` vagy `rejected` legyen. Két scannerüzenet nem két független bizonyíték. Minden élhez legyen előfeltétel és evidence reference; a bizonytalan élet ne számolja automatikusan bizonyított teljes láncnak. Kezdetben elég a meglévő adatbázis és bounded graph-query; ne töltsd a teljes gráfot az LLM-be vagy RAM-ba. Maximalizált mélység és bejárt csomópontszám kell.

A modul korrelál és ellenőrzési tervet javasol. Nem indíthat korlátlan exploitláncot, új hálózati célt, pivotot vagy jogosulatlan adathozzáférést.

### 5.5. AIExploitGenerator — kontrollált reprodukció és regresszió

A kért képességet a RedJohnban biztonságos reprodukciós modul formájában valósítsd meg. A publikus komponensnév maradhat `AIExploitGenerator`, belül lehet `SafeReproducerGenerator`; ez nem a RedJohn átnevezése.

Bemenete már megfigyelt finding/hypothesis, rögzített kérés, megengedett helyi lab-fixture és ellenőrzési cél. Kimenete minimális, nem destruktív tesztreproducer, kontroll, elvárt assertion, cleanup és regressziós teszt. A tervben konkrét actor/asset/fixture referenciák szerepeljenek.

Generált kód csak ellenőrzött izolált környezetben, külső hálózat nélkül vagy szigorú laballowlisttel futhat, CPU/RAM/időkorláttal. Statikus ellenőrzés, schema validation és outputkontroll szükséges. Ne töltsön le és futtasson automatikusan nyilvános exploit-repositorykat. Ne generáljon reverse shellt, perzisztenciát, credential theftet, adatkimentést vagy univerzális távoli exploitkit-et.

A generált teszt szintaktikai sikere nem bizonyítja a hibát. Hibás és javított labváltozaton külön ellenőrizd. A sikertelen validálás ne legyen confirmed finding.

### 5.6. RateLimitDetector

Figyelje a 429-et, a releváns 503-at, a `Retry-After` mezőt, a válaszidőket és a konfigurált szolgáltatói kereteket. A `Retry-After` másodperc és HTTP-dátum alakját kezelje. A 403 önmagában nem biztos rate limit: lehet jogosultsági tiltás vagy challenge.

Origin/endpointcsoport/account szintű közös korlátozás és cooldown legyen. A megfigyelés a resource governorhoz menjen; a toolok összeadódó forgalma se lépje túl a keretet. A válasz a lassítás, várakozás, kisebb batch vagy korrekt `blocked/rate_limited` státusz. Ne legyen automatikus proxy-/identitásrotáció vagy CAPTCHA-megkerülés a limitek kijátszására.

### 5.7. ParameterOptimizer

Csak típusos, előre engedélyezett mezőket optimalizáljon: concurrency, batchméret, timeout, bounded depth, input subset és evidence-részletméret. A kockázati profil, scope, credential és maximális hatás nem optimalizálható felül.

A változtatásnak legyen indoka, régi/új értéke és időbélyege. Egyszerre kevés paramétert módosítson, legyen hiszterézis és plafon. Scannerargumentum-stringet ne generáljon és ne hajtson végre szabad szövegből. A kevesebb teszt miatti mesterséges gyorsulás ne számítson minőségi javulásnak.

### 5.8. FailureRecoverySystem

Normalizált hibaosztályból és jobállapotból válasszon recovery-tervet. Kezelje a timeoutot, process crash-t, OOM-ot, sessionlejáratot, hálózati hibát, formátumeltérést, provider-kiesést és bizonytalan mellékhatást. A részletes szabályok a 12. fejezetben kötelezők.

### 5.9. GracefulDegradation

Képességszintű folytatás legyen, dokumentált minőségveszteséggel. Például CVE-provider nélkül tovább futhat a browseres inventory; browserhiba mellett a HTTP-felderítés folytatható, de nem nevezhető teljes SPA/DOM-lefedettségnek. OAST nélkül egy vak teszt nem válhat negatív eredménnyé.

Fallback csak ekvivalens, policyben engedélyezett capability esetén. Nem lehet fallback az auth eltávolítása, TLS-ellenőrzés kikapcsolása, nagyobb jogosultság vagy tágabb scope. A coverage-ben legyen `coverage_lost`, `fallback_used` és magyarázat.

### 5.10. PerformanceMonitor

Gyűjtsön job/fázis/tool szintű időt, resource usage-t, queue waitet, kérésmennyiséget, tokent, cache-metrikát, hibaarányt, új bemenetet és validált findinget. A monitor alapból megfigyel; a resource governor a kapacitás egyetlen írója legyen. Ne jöjjön létre több, egymással versengő automatikus szabályozó.

A telemetria maga is bounded legyen: histogram/aggregáció és korlátozott címkekészlet; titok, teljes URL, egyedi request ID és nyers body ne legyen metrikacímke. A részletek hozzáférés-védett logban/evidence store-ban maradjanak.

### 5.11. SmartCachingSystem

Valós, bájtkorlátos LRU + TTL és kontextus-/verzióérzékeny invalidálás kell. A cache nem bizonyítéktár és nem felejtheti el észrevétlenül a tesztállapotot. Részletek a 11. fejezetben.

### 5.12. MemoryBudgetManager és ResourceGovernor

Ezeket a felhasználó memóriaigénye miatt külön felelősségként is hozd létre vagy a meglévő erőforráskezelésben implementáld. Egyetlen koordinált admission-control kezelje a browser, scanner, Python/Node worker, cache és LLM-context kereteit. Egy űrlapfelderítő agent ne indíthasson újabb böngészőt pusztán azért, mert nem látja a másik worker költségét.

## 6. HEADLESS BROWSER, CRAWLER ÉS SESSIONKEZELÉS

Playwright/Chromium szükséges az első működő end-to-end lánchoz. A felderítő rutin lehetőleg ne igényeljen LLM-hívást minden navigációhoz.

- Közös browser-service és szabályozott workerpool; külön BrowserContext az elkülönítendő identitásokhoz/tenanthez, külön folyamat vagy erősebb izoláció az egymástól nem megbízható megbízásokhoz.
- Session/storage state, frissítés és tesztaccount-referenciák hozzáférés-védetten; nyers cookie/token ne kerüljön promptba vagy Gitbe.
- Automatikus sessionrotáció ne változtassa meg az identitást a teszt közben. Állapotfrissítésnél növeld a sessionrevisiont és invalidáld a releváns cache-t.
- Gyűjtsd a linkeket, DOM-formokat, SPA-route-okat, fetch/XHR-, iframe- és szükség esetén WebSocket-metaadatokat. Különítsd el az observed/imported/inferred endpointokat.
- Ne kizárólag `networkidle` eseményre várj; tartós kapcsolatoknál konfigurált readiness-feltétel és véges határidő kell. A sikertelen readiness ne legyen sikeres felderítés.
- JavaScriptet ne kapcsold ki memóriaoptimalizálás címén. Kép/font/media blokkolása csak külön, mérhető felderítési profilban; releváns validáláskor ne változtasd meg némán a böngésző viselkedését.
- Service worker, cache, CSP, iframe és browserrouting okozta láthatósági korlátokat jelezd. A normál Browser API metaadata nem garantált nyers, bájthű protokollcapture.
- Ismeretlen hatású gombok és formok csak engedélyezett tesztadatokon; logout, törlés, fizetés, emailküldés és külső integráció külön művelethatár. A HTTP-metódus önmagában nem dönt a veszélytelenségről.
- A harmadik féltől betöltött, megengedett statikus erőforrás nem válik aktívan tesztelhető céllá. Különítsd el a navigáció/teszt hatókörét a szükséges passzív erőforrásbetöltéstől.
- Azonos inventoryba dolgozzon a browser és Katana. Ne duplikálják korlátlanul egymás crawl-frontierjét.

A browser pool életciklusát cancellation és kivétel esetén is zárd le: page, context, listener, trace, HAR, CDP session, tempfájl és szükség esetén a processfa felszabaduljon. A leak elrejtésére szolgáló periodikus újraindítás nem helyettesíti a hiba feltárását; kontrollált recycling viszont lehet üzemeltetési védelem.

## 7. SURFACE INVENTORY ÉS ADATSÉMÁK

Használd vagy migráld a RedJohn meglévő adatmodelljét. Minimum entitások:

`engagement, scope_revision, asset, service, actor, session_revision, workflow, request_observation, endpoint, input_surface, technology_observation, job, attempt, capability, evidence, finding, coverage, correlation_edge`.

A vizsgálati kulcs őrizze a releváns különbségeket:

`engagement + endpoint + method + content_type + input_location/name + actor/tenant + session_revision + workflow_state + test_family + profile_version + tool/template_version`.

Az endpointcsoportosítás nem tüntetheti el az eredeti útvonalat, querysorrendet, ismételt paramétert, encodingot vagy bodyformátumot, ha ezek a teszt szemantikájához számítanak. A nyers kérés külön referenciával maradjon meg; a titkok helyettesítése a végrehajtói oldalon, auditált secret reference alapján történjen.

A teljes corpus RAM-ba töltése helyett indexelt lekérdezés, lapozás, chunkolt beszúrás és streamelt feldolgozás kell. A felfedezett asset csak policyellenőrzés után kerülhet aktív jobba.

### Három független státuszdimenzió

Ne keverd a futás eredményét, a lefedettséget és a sérülékenység bizonyítottságát.

- `execution_status`: queued, running, retry_wait, succeeded, failed, cancelled, timed_out, resource_exhausted.
- `coverage_status`: not_tested, completed, partial, blocked, unsupported, inconclusive.
- `finding_status`: candidate, confirmed_weakness, confirmed_impact, false_positive, fixed, reopened.

Egy sikeresen futott scanner üres eredménye csak az adott tesztre vonatkozó `no_finding_observed` lehet, nem globális „biztonságos”. A régi skillpack összekevert enumjait szükség esetén migráld és teszteld; ne emeld át kritikátlanul a sémát.

## 8. DETERMINISZTIKUS SCHEDULER ÉS SPECIALIST WORKEREK

A scheduler tartós feladatsorral, explicit állapotátmenetekkel és bounded batch-végrehajtással működjön.

- Alaplefedettségi minimum és fair elosztás legyen a releváns tesztcsaládok között; egy SQLi-hipotézis ne használja fel az egész kampányt.
- A második passz konkrét candidate vagy lefedettségi hiány miatt kapjon további keretet.
- Ugyanazt a próbát ne indítsa újra pusztán agent-újratervezés miatt. Explicit retest, releváns állapot-/verzióváltozás vagy engedélyezett recovery indokolhat új attemptet.
- Idempotens jobkulcs, lease/heartbeat, tulajdonos, attemptszám és deduplikált eseménykezelés szükséges.
- Ne ígérj általános exactly-once hálózati mellékhatást. Kérésküldés utáni crash esetén ismeretlen állapot lehet: előbb reconciliation, nem vak újraküldés.
- Módosító workflowhoz és tesztobjektumhoz lock/serialization vagy izolált fixture kell. Race-tesztek saját, engedélyezett concurrency-harnessben menjenek, ne véletlen workerütközésként.
- A rutin polling, parsing, replay, retry és jobválasztás ne igényeljen modellenkénti fordulót.

Minden adapter minimum kontraktusa:

`capabilities`, `validate_input`, `prepare`, `run`, `stream_events`, `normalize`, `cancel`, `cleanup`, `healthcheck`.

A név a stackhez igazítható, de a felelősségek nem hagyhatók el. Capability-metadata: valódi toolnév, verzió/digest, támogatott content type/input, profil, auth/replay támogatás, privilege, licenchivatkozás, cancellation, erőforrásosztály és adapterteszt-státusz.

A futtató típusos engedélyezett opciókból építsen argumentumlistát, `shell=False` vagy azzal egyenértékű módon. Ez önmagában nem elég: tiltsd az illetéktelen config-/outputfájlokat, a flagszerű célértékeket, a rejtett auto-update/network lépéseket és a worker munkakönyvtárán túli írást. Ne adj tetszőleges `additional_args` vagy shell mezőt az LLM-nek.

A stderr/stdout külön, folyamatosan ürítve és korlátozva legyen. A parser kezelje a részleges outputot, bannerrel kevert JSON-t, toolverzió-eltérést és truncationt. A JSON-séma hibája ne legyen üres találati lista. Exit code 0 nem elég, ha nem volt érvényes target vagy ellenőrzés.

## 9. NUCLEI ÉS INTELLIGENCE SPECIÁLIS SZABÁLYAI

A meglévő Nuclei-integrációból indulj. Tarts külön lockot a binárishoz és a template-bundle-höz. Template-kiválasztáskor capability, tényleges input, template ID, várható hatás, technológia és policy számít; puszta severity/tag nem megfelelő engedélyezés.

Template-aláírás az eredet/sértetlenség egyik ellenőrzése, nem biztonságos hatás bizonyítéka. A kiegészítő fájlokat és a teljes futtatott bundle-t is rögzítsd digesttel. Generált template-et ne írj automatikusan alá és ne futtass productionon attól, hogy átment egy szintaktikai ellenőrzésen.

A file/code/headless vagy nagyobb hatású képességeket ne engedélyezd globálisan; explicit profil és erőforrásfoglalás kell. Az összes scanner által használt hálózati és OAST-célra legyen policy. A template-eket kampány közben ne frissítsd észrevétlenül.

Az intelligence cache és a template-index külön adat. Ismert CVE nem azonos a cél érintettségével, a cél érintettsége pedig nem automatikusan bizonyított kihasználhatóság. A riport különítse el ezeket.

## 10. MEMÓRIAOPTIMALIZÁLÁS — NÉGY KÜLÖN RÉTEG

### 10.1. LLM-context és tokenköltség

- A teljes HTML, JS bundle, HAR, HTTP-body, screenshot, scannerlog és korábbi chathistory ne kerüljön minden fordulóban a modellhez.
- Az agent referenciákat, rövid structured summaryt, coverage deltát és kiválasztott bizonyítékrészletet kapjon.
- Releváns skillek/tooldefiníciók igény szerinti betöltése; egyszerre ne legyen minden sérülékenységcsalád teljes leírása kontextusban.
- A tokenbudget tartalmazza a rendszerutasítást, tool schemas, skillek, előzmények, inputok és tervezett output keretét. A meglévő modellproviderhez illeszkedő mérést használj; becslést jelölj becslésként.
- Tartós strukturált kampányállapot és provenance; a modellösszefoglaló nem írhatja felül a nyers bizonyítékot.
- A rutincrawler/scanner/parse ciklusok célja 0 belső LLM-hívás. Új jelzésnél vagy valódi döntési szükségnél kapcsolódjon be a modell.
- A tömörítéshez használt LLM költségét is számold; ne költs több tokent a takarékosságra, mint amennyit megspórol.

### 10.2. Python/Node/worker RAM

- Bounded queue, limitált in-flight batch, streamelt JSONL/XML/log parsing, lemezre/objektumtárba írt evidence.
- Nagy body vagy artifact több másolata ne éljen egyszerre RAM-ban. A limitet kitömörítés után is alkalmazd; parser-, archívum- és decompression-bomb elleni keret kell.
- Lazy loading a nehéz adaptereknél; cloud/binary csomagok importja csak aktiváláskor.
- Python/Node heap mérése mellett figyeld a child processokat és Chromiumot is. Egy Python-allokációs profiler önmagában nem adja a teljes platformmemóriát.
- Ha lehetséges, cgroup/container memória legyen az összfogyasztás mértéke. A process RSS-ek egyszerű összege megosztott lapokat többször számolhat; a módszert dokumentáld.
- Folyamatosan növekvő queue/cache/listener/loglista helyett méretkorlát, lejárat, aggregáció és backpressure.
- Fejlesztői profilban heap snapshot/allocation profiling, üzemi profilban alacsony overheadű mérés. A profilozó se tároljon korlátlan trace-t.

### 10.3. Browser RAM és életciklus

- Teljes folyamatra, browserpoolra és megbízásra vonatkozó keret; admission-control új context/page/process indítás előtt.
- Max aktív page/context/process; idle timeout és ellenőrzött bezárás.
- HAR/trace/screenshot csak kiválasztott bizonyítékhoz vagy mintavételezve, fájlméret- és retentionkorláttal.
- Elszállt page/context újraépítése előtt állapot- és mellékhatásellenőrzés. Ne ismételj véletlenül módosító formbeküldést.
- Crawlee saját automatikus skálázását hangold össze a globális governorral. Ne két külön szabályozó növelje egymástól függetlenül a concurrencyt.
- BrowserContext izoláció a sessionök elválasztására jó; a kompromittált browserfolyamat ellen külön OS/container határ szükséges.

### 10.4. Tartós memória, bizonyíték, telemetry

- Külön életciklus a cache, kampányállapot, audit és immutable evidence számára.
- Evidence-eviction nem történhet LRU miatt; megőrzési szabály szerinti törlés külön, auditált művelet.
- Tárhelykvóta, logrotáció, TTL a tempfájlokra, reference-alapú garbage collection, hozzáférési jogok.
- A teljes index vagy correlation graph ne legyen kötelezően memóriában.

### Konfigurálható resource envelope

A tényleges gép/container alapján állíts be és validálj `total_memory_budget`, `worker_memory_budget`, `browser_concurrency`, `cache_max_bytes`, `queue_max_items`, `artifact_max_bytes`, `max_model_input_tokens` és hasonló kereteket. Ezek tervezett RedJohn-mezők, nem meglévő frameworkflag-ek.

Példaként használható soft/high watermark és alacsonyabb resume watermark hiszterézissel; az értékeket dokumentált mérésből válaszd, ne jelents be minden gépre működő százalékot. Soft nyomásnál új admission visszafogása, cacheürítés és idle felszabadítás; magas nyomásnál új jobok szüneteltetése, biztonságos checkpoint/cleanup. A hard OS-limit végső védőháló, nem normál ütemezési eszköz.

## 11. SMART CACHING — LRU, TTL ÉS HELYES TESZTSZEMANTIKA

A cache célja a felesleges feldolgozás csökkentése, nem a friss mérések helyettesítése.

- Bájtméret és elemszám szerint korlátozott LRU; lejárt elemek eltávolítása; túl nagy objektum ne szorítsa ki korlátlanul a hasznos hot setet.
- Kulcs: tenant/engagement, releváns asset, actor, sessionrevision, policyrevision, workflowállapot, inputfingerprint, tool/profile/template verzió és ismert alkalmazás/deploy revision.
- Nyers token/cookie ne legyen cachekulcs vagy log. Használj belső secret/session referenciát és verziót.
- Intelligencerecord, immutable JS-parszolás és élő hálózati eredmény eltérő TTL-t és invalidálást kapjon. Forrást és időbélyeget mindig őrizz.
- Egyidejű azonos, cache-elhető lekérdezéshez single-flight/szinkronizált refresh; a waiterek és a refresh is kapjanak határidőt.
- Friss validálás és retest alapból bypassolja a korábbi aktív teszteredmény-cache-t.
- Auth/authz, session, CSRF/CORS, race és OAST esetén a releváns állapotváltozás kötelező invalidálás vagy cachetiltás; időérzékeny eredményt ne használj régi bizonyítékként.
- Timeout, parserhiba, rate limit és jogosultsági hiba nem cache-elhető „nincs sérülékenység” eredményként.
- Azonos kérés történeti eredménye felhasználható tervezésre, de a felhasználónak látnia kell, hogy új vagy korábbi mérésről van szó.
- DNS/scope-jogosultságot az aktuális kapcsolat előtt újra ellenőrizd; lejárt cache nem engedélyezhet új hálózati célt.
- Cache-hit/miss, frissesség, bájtméret, eviction, refresh és invalidálási ok legyen mérve, titokmentesen.

## 12. ENHANCED ERROR HANDLING ÉS RECOVERY

### 12.1. Hibaséma

Minden belső és MCP/API-hiba normalizált, géppel feldolgozható rekord legyen:

`code, category, message, retryable, terminal, job_id, attempt_id, tool_id, cause_ref, retry_after, partial_evidence_refs, coverage_effect, recovery_action`.

A felhasználói szöveg magyar lehet; a hibakód stabil és nyelvfüggetlen. A belső stack trace és titok ne menjen az LLM-hez vagy publikus API-ba.

### 12.2. Kötelező hibapolitika

| Hibaosztály | Kezelés |
|---|---|
| scope/policy denial | Végleges tiltás; sem retry, sem tágabb fallback. |
| input/schema/unsupported body | Javítható adatprobléma vagy unsupported; ugyanazt ne ismételd. |
| tool missing/API key missing | Opcionális capability kikapcsolása és coverage gap; kötelező core-nál világos blokkolás. |
| tool version/schema mismatch | Adapter álljon le; raw bizonyíték megőrzése és explicit inkompatibilitás. |
| authentication expired | Legfeljebb konfigurált reauth a meglévő actorral; sessionrevision-váltás; nincs anonim fallback. |
| transient network/429/provider outage | Véges backoff+jitter, szerver által jelzett várakozás és közös deadline. |
| 403/challenge | Osztályozás; ne nevezz mindent rate limitnek, és ne kezdj megkerülésbe. |
| timeout | Részleges evidence; csak idempotens/safe lépést próbálj újra, összkereten belül. |
| parser error/truncated output | Partial/inconclusive; a truncation ténye megőrzendő. |
| OOM/browser crash | Új admission megállítása, cleanup/checkpoint, alacsonyabb keret; mellékhatásvizsgálat retry előtt. |
| disk full/evidence write failed | Bizonyítékigényes tesztek kontrollált leállítása; ne dobj el bizonyítékot és ne jelents megerősítést. |
| cancellation/shutdown | Új feladatok megállítása, child processfa leállítása, lezárt audit és felszabadított lease. |
| unknown execution outcome | Reconciliation vagy inconclusive; nem automatikus újraküldés. |

### 12.3. Recovery mechanika

- Max attempt, összesített retrybudget és abszolút kampánydeadline; ne legyen egymásba ágyazott végtelen retry az adapterben, MCP-ben és agentben.
- Circuit breaker külön provider/origin/tool szerint, cooldownnal és korlátozott half-open próbával. Ne indíts sok párhuzamos helyreállítási próbát ugyanarra a hibára.
- Bulkhead: egy browser- vagy toolkiesés ne rántsa le a teljes koordinátort. A függő jobok korrekten várjanak/blokkolódjanak, a függetlenek folytathatók.
- Watchdog, heartbeat, cancel propagation, process group felügyelet, véges TERM/KILL grace period.
- A cleanup `finally` ágban és újraindításkor is idempotensen fusson. A cleanup hiba is naplózott hiba, ne tűnjön el.
- Sessionfrissítésnél, rate limitnél és toolhibánál a változás visszakerül az inventory/scheduler állapotába; az agent ne maradjon régi feltételezésekkel.
- Késői OAST-eredmény auditáltan hozzákapcsolható a korábbi teszthez, de a terminális jobállapotot ne változtassa vissza észrevétlenül futóvá.
- A végső riport a kiesést és elveszett lefedettséget is mutassa, ne csak az összesített pass/fail darabszámot.

## 13. SKILLEK — MEGLÉVŐ 35 CSOMAG ÉS CÉLFÜGGŐ BŐVÍTÉS

Ha elérhető a korábbi `headless_strix_skillpack.zip`, olvasd be. A fájlnév örökölt referencia, nem terméknév. Ellenőrzött skillleírásokat emelj át a RedJohn saját loaderébe; a Strix-specifikus konfigurációt ne másold át változtatás nélkül.

A csomag nem előfeltétele az implementációnak: hiányakor a következő azonosítókhoz készíts RedJohn-native `SKILL.md` dokumentumot a leírt szerződéssel. Ne állítsd, hogy a régi pack a jelenlegi repóban már integrált.

### Megőrzendő funkcionális skillkészlet

```text
engagement-scope
headless-browser-discovery
web-surface-inventory
javascript-endpoint-analysis
input-discovery
technology-fingerprinting
nuclei-cve-planning
authentication-session
jwt-security
authorization-idor-bola
authorization-bfla-bopla
api-graphql-security
sql-injection-validation
nosql-ldap-injection
xss-validation
command-injection-validation
template-injection-validation
ssrf-validation
xxe-validation
path-traversal-lfi-rfi
file-upload-processing
csrf-validation
cors-validation
http-desync-assessment
crlf-response-splitting
deserialization-risk
race-toctou
prototype-pollution
subdomain-takeover
business-logic-testing
oast-correlation
source-dependency-analysis
finding-triage-retest
report-coverage
execution-scheduling
```

### Új, célfüggő skillek

| Skill | Funkció / aktiválás |
|---|---|
| `service-discovery` | Naabu/Nmap tervezése és leletfeldolgozása explicit network scope esetén. |
| `dns-asset-discovery` | DNS/asset-kapcsolatok és az observed/authorized különbség kezelése. |
| `wordpress-assessment` | WPScan bekötése igazolt WordPress-felülethez. |
| `cloud-posture-assessment` | Prowler vagy kiválasztott ScoutSuite accountkontextusban. |
| `kubernetes-benchmark-assessment` | kube-bench/konfigurációs ellenőrzés; labvizsgálat külön profilban. |
| `local-binary-triage` | Helyi crash és bináris-fixture elemzés külön labcsomagban. |
| `resilience-recovery` | A nem rutin recovery-tervek felülvizsgálata; a rutin helyreállítást programkód végzi. |
| `memory-context-budgeting` | Komplex erőforrásprobléma elemzése; a normál budgetkezelés nem LLM-feladat. |
| `cache-freshness-control` | Frissességi és invalidálási eltérések elemzése. |
| `correlation-hypothesis-review` | Bizonyítékkapcsolatok és nem bizonyított láncfeltevések értékelése. |
| `performance-regression` | Összehasonlítható benchmark és lefedettségvesztés vizsgálata. |
| `safe-reproducer-validation` | Kontrollált labreproducer és javított kontroll értékelése. |

A működés a registryből induljon, ne hardcode-olt 35/47 darabszámból. A domainfüggő skill csak akkor aktiválódjon, amikor van hozzá tényleges cél, capability és jogosultság. Nem kell tizenkét új agent az új skillnevekhez.

### Kötelező skill-szerződés

Minden skill tartalmazza:

- cél és pontos aktiválási feltételek;
- előfeltételek, szükséges actor/tenant/workflow/fixture;
- támogatott és nem támogatott input/bodyformátumok;
- kanonikus capability-k és valóban bekötött RedJohn-toolmapping;
- hatásprofil és futási keretek;
- sorrend, kontrollmérés, eredménykritérium, false-positive szempontok;
- finding/coverage státuszok és bizonyítékkövetelmény;
- timeout, stop, cleanup és recovery szabályok;
- verzió, hivatkozások, pozitív/javított kontrollteszt referenciája.

Registry betöltésekor ellenőrizd, hogy a deklarált tool létezik-e és tudja-e a szükséges képességet. Dokumentum vagy `SKILL.md` létezése nem jelent végrehajtási lefedettséget. Stub/unsupported capability legyen látható, ne jelenjen meg kész skillként.

## 14. KICSI MCP/API VEZÉRLŐFELÜLET

A meglévő RedJohn toolrendszerhez illeszkedj. MCP akkor kell, ha a választott agent/host használja; a belső hívásokat ne kényszerítsd fölöslegesen hálózati MCP-roundtripbe. Ne adj az LLM-nek több tucat scanner nyers kapcsolóit.

Javasolt logikai műveletek, amelyek a RedJohn elnevezéseihez igazíthatók:

1. `surface_search`: szűrt és lapozott inventory.
2. `surface_get`: egy asset/endpoint részletes, méretkorlátos nézete.
3. `plan_next_batch`: megmagyarázott, kerettudatos terv.
4. `jobs_submit_batch`: kizárólag validált jobtervek engedélyezett profilból.
5. `jobs_get_status`: kompakt státusz és delta.
6. `jobs_cancel`: explicit megszakítás és leszármazott jobok kezelése.
7. `evidence_get`: mezőválasztott, kitakart bizonyítékrészlet.
8. `coverage_get`: hiányok és tényleges lefedettség.
9. `findings_get`: findingek és kapcsolataik.
10. `system_health`: elérhető capability-k, resource pressure és degradált funkciók.

Nem kell pontosan tíz külön tool, ha a meglévő API tisztán összevonja őket. A cancel és a health ne maradjon ki csak egy mesterséges darabszámkorlát miatt.

Minden hívás: schema/inputvalidáció, hívóazonosság és engagement-hozzáférés, policyrevision, audit, response-size korlát, redaction és stabil hibakód. A kliens által megadott engagement ID önmagában nem hozzáférési jogosultság. Az evidence reference is hozzáférésellenőrzött legyen.

Ne legyen `run_any_command`, szabad shell, tetszőleges programkód vagy ellenőrizetlen URL-fetch. MCP tool output és target content nem módosíthatja az agent utasításait, skilljeit vagy a policyt. A konzol/debugger portok ne legyenek nyilvánosak.

## 15. FUTÁSI BIZTONSÁG ÉS HATÓKÖR

Három hatásprofil marad:

- `safe-production`: megadott célokon jóváhagyott alacsony hatású vizsgálatok; sem itt, sem másutt nem ígérhető abszolút mellékhatásmentesség.
- `active-staging`: tesztidentitások, elkülönített tesztobjektumok és aktív validálás, szabályozott cleanup.
- `isolated-lab`: eldobható, kifejezetten tesztcélú környezet a nagyobb hatású diagnosztikához.

Programkód és infrastruktúra kényszerítse ki a host/origin/IP/CIDR/port/account/region/workflow/actor határokat. Új redirect, DNS-feloldás és tényleges kapcsolódási cél előtt ellenőrizd a megengedettséget. A domainbirtoklás nem jelent automatikus jogot egy közös CDN/IP összes szolgáltatásának vizsgálatára. Cloud login esetén ne használd automatikusan a fejlesztő teljes helyi credential chainjét.

A browser URL-routing önmagában nem minden hálózati protokollra kiterjedő védelmi határ. Legyen worker/network namespace/proxy/egress enforcement, különösen scanner subprocessok és raw-socket toolok esetén. A szükséges DNS és infrastruktúrakapcsolatok is legyenek kontrolláltak. Ha a környezet ezt nem tudja, az érintett hálózati profil legyen blokkolt, ne csak figyelmeztetéssel nyitott.

SSRF/OAST esetén a célalkalmazással indíttatott kapcsolat külön határ: a scanner egressszűrése nem szabályozza a cél szerverét. Csak megengedett fogadó vagy explicit labdestináció adható tesztparaméterként. Könyvtár-/fájlvizsgálatnál kontrollált fixture, nem érzékeny adat legyen a bizonyíték.

További követelmények: titoktár, minimális mount és capability, áttekintett függőségek, rögzített verziók, audit, kill switch, hozzáférésvédett evidence, jelentésekben HTML-escaping. TLS-validálást, Chrome sandboxot vagy célkorlátot ne kapcsold ki általános „hibaelhárításként”.

## 16. FINDING VALIDATION ÉS RCE-REGRESSZIÓ

A finding tartalmazza az elvárt és megfigyelt viselkedést, a kontrollt, actor/workflow kontextust, pontos evidence reference-eket, ismételhetőséget, tool/skill/template verziót, CWE-besorolást és — csak megalapozott esetben — CVE-kapcsolatot.

A technikai súlyosság, bizonyítási szint és üzleti kockázat külön adat legyen. CVSS/EPSS/KEV nem helyettesíti a tényleges bizonyítékot. A validátor nem nevezheti az LLM magas confidence értékét vagy két agent egyetértését független mérésnek.

A korábbi RCE-kimaradás diagnosztikai lánca:

1. Felfedezte-e a releváns végpontot?
2. Rögzítette-e a bemenetet és a pontos bodyformátumot?
3. Elérte-e a szükséges identitással és workflowállapotban?
4. Felismerte-e a releváns mechanizmust: command injection, SSTI, komponenshiba, fájlfeldolgozás vagy más?
5. Valóban támogatja-e ezt a kiválasztott adapter?
6. Lefutott-e a vizsgálat, és megőrződött-e a bizonyíték?
7. Helyesen különült-e el a gyengeség és a ténylegesen igazolt hatás?
8. Javított kontrollváltozatban megszűnt-e az indikáció?

Egy 500-as válasz, egyszeri időeltérés vagy külső callback önmagában nem RCE-bizonyíték. Az SSTI/command injection és az abból elérhető hatás külön állítás.

Az eredeti RCE-fixture hiányában készíts ártalmatlan helyi regressziós tesztet a pipeline egyes elemeihez, de az eredeti hibát jelöld `not_reproduced_missing_fixture` állapottal. Szimulált marker-válasz a routingot tesztelheti, de nem bizonyít valódi RCE-detektálást. A riport ezt a különbséget is mondja ki.

## 17. TESZTEK, FAULT INJECTION ÉS MEMÓRIA-BENCHMARK

### 17.1. Unit és kontraktustesztek

- név-/azonosítómegőrzés, konfigurációs kompatibilitás;
- inventory és tesztkulcs, session/tenant elválasztás, paraméter/encoding megőrzés;
- capability routing, unsupported input, hibás verzió, hiányzó bináris;
- fair scheduler, idempotencia, deadline, retrybudget, cancel és lease recovery;
- toolargumentum-validálás és kontrollálatlan konfiguráció tiltása;
- státuszdimenziók és parserhibák helyes leképezése;
- LRU valós sorrend, bájtlimit, TTL, oversized elem, invalidálás és single-flight;
- cél-/hívójogosultság, secret redaction, túl nagy toolválasz;
- rate-limit dátum/másodperc feldolgozás és 403 elkülönítése;
- korrelációs előfeltételek, nem bizonyított élek és téves confirmed státusz tiltása.

### 17.2. Integrációs és E2E tesztek

Készíts reprodukálható helyi SPA/API fixture-t JavaScript-navigációval, fetch/XHR-rel, formokkal, JSON és szükség szerint XML/multipart bemenettel, legalább két elkülönített identitással. Legyen browser -> traffic -> inventory -> scheduler -> adapter -> evidence -> validation -> report -> retest lánc.

A mock adapter és a valódi binárissal futó teszt legyen külön tesztcsoport. A fontos, elérhető core adapterekhez valós, kontrollált integrációs ellenőrzés is szükséges. Opcionális cloud/Kubernetes integrációhoz credential nélkül kontraktus-/fixture-teszt készülhet, de az állapot `mock_tested_not_live_verified` maradjon.

### 17.3. Kötelező hibainjektálási esetek

Browser crash, megszűnő worker, scanner timeout, megszakított stdout, hibás JSON/XML, túlméretes body, evidence-tárhelyhiba, 429/Retry-After, lejárt session, intelligence-provider kiesés, cachelejárat, versengő refresh, scope-on kívüli redirect, OAST-késés, MCP cancellation és koordinátor-újraindítás.

A teszt ne csak azt nézze, hogy nem dobott kivételt: ellenőrizze a job státuszát, elveszett lefedettséget, nem ismételt mellékhatást, partial evidence-t és process/lease cleanupot is.

### 17.4. Memória- és teljesítményvizsgálat

- Ismétlődő helyi crawl/workload: bemelegedés után több azonos ciklus, kontrollált browserpool és külön cachekvóta.
- Mérd a controller, Python/Node worker és Chromium memóriahasználatát, a cgroup/host módszer dokumentálásával.
- Vizsgáld a heap/process növekedését, file descriptort, listener/page/context/process darabszámot, valamint a lezárás utáni állapotot.
- A teszt futási ideje és adatmennyisége a CI-ben konfigurálható; hosszabb soak külön parancsból fusson. Az agent csak a ténylegesen végrehajtott időt jelentse, ne ígérjen háttérben elkészülő eredményt.
- A legnagyobb engedélyezett body/log/queue mellett is ellenőrizd a backpressure-t és a korlátokat; OOM ne normál sikerág legyen.
- Hasonlítsd össze a régi és új RedJohnt azonos modell, fixture, scope, seed, account és keret mellett, amikor ez elérhető.

Kötelező metrikák: input/output token, model calls, model-cost vagy jelölt becslés, teljes/fázisidő, HTTP-kérések, queue wait, p50/p95 végrehajtási idő, peak memory, cache-hit és eviction, hibák/retry, deduplikált és ismételt jobok, új bemenetek, confirmed/candidate találatok, false positive és ismert fixture false negative, valamint unsupported/blocked/inconclusive lefedettség.

Ne optimalizálj pusztán kisebb tokenre vagy több findingre: megőrzött vizsgálati lefedettség és helyes eredmény nélkül az összehasonlítás félrevezető. Ne ígérj előre százalékos gyorsulást vagy memóriajavulást.

## 18. VÉGREHAJTÁSI SORREND ÉS KÉPESSÉGSZINTEK

A függőségek mentén dolgozz, de minden szakaszban működő vertikális szeletet készíts.

1. RedJohn audit, baseline, név/kompatibilitás megőrzése és követelménykövetés.
2. Core policy, browser/traffic, inventory, bounded evidence flow és meglévő Nuclei útvonal.
3. Tartós scheduler, státuszdimenziók, worker contract, cancellation, resource governor.
4. httpx/Katana/VulnX/ffuf és a releváns web/API specialisták valódi bekötése.
5. Decision/technology/intelligence/correlation modulok, skillrouting, kontrollált reprodukció.
6. Memory/cache/recovery optimalizálás és fault-injection ellenőrzés; ezek alapkorlátai már a korábbi szakaszokban is éljenek.
7. Indokolt network/CMS/source/cloud/Kubernetes bővítések capabilitycsomagonként; a binary-lab és feleslegesen átfedő alternatívák ne késleltessék a core elkészítését.
8. E2E, retest, mérés, dokumentáció és reprodukálható átadás.

Különböztesd meg az alábbi állapotokat a mátrixban:

`implemented_and_live_tested`, `implemented_fixture_tested`, `adapter_not_implemented`, `unsupported_input`, `blocked_missing_dependency`, `blocked_missing_credentials`, `blocked_by_policy`, `deferred_not_required`.

A helyi környezetben nem telepíthető opcionális motor miatt ne állítsd le az egész munkát; írj tesztelt capability/hibaágat. Ettől az opcionális adapter még nem lesz valós E2E-ben igazolt. A core részeket ne nevezd elkészültnek, ha csak mockkal működnek.

## 19. ELFOGADÁSI KRITÉRIUMOK

A változtatás akkor tekinthető megfelelőnek, ha:

- a felhasználó továbbra is RedJohnként indítja és látja a projektet; meglévő saját módosításai és kompatibilitási pontjai megmaradnak;
- Firecrawl nélkül valódi headless Chromium járja be a helyi SPA-fixture-t, és legalább két tesztidentitás elválik;
- a felületleltár és tesztállapot újraindítás után is megmarad;
- a meglévő Nuclei integráció nem duplikálódik, az elérhető fontos adapterek valós kéréseket és értelmezett eredményt kezelnek;
- a scheduler több releváns tesztcsaládot kiszolgál, és egy érdekes jelzés nem éhezteti ki a többit;
- a RedJohn-specifikus döntési, intelligence-, korrelációs, cache-, memória- és recovery-moduloknak valódi tesztelt logikájuk van;
- a generált reprodukció kizárólag kontrollált labteszt, nem univerzális távoli exploitvégrehajtó;
- bounded queue/cache/output/browser működés és működő cancel/process cleanup igazolható;
- a 429, sessionlejárat, toolhiba és unsupported input nem jelenik meg sikeres negatív vizsgálatként;
- cache nem rejti el a retestet, új sessiont, állapotváltozást vagy engedélymódosítást;
- a skillek a tényleges capabilitykre mutatnak, dinamikusan töltődnek, és hiányzó adapterhez nem ígérnek lefedettséget;
- van lefuttatott unit/integrációs/E2E teszt, megjelölt korlát és mérési jegyzőkönyv;
- futtatható parancsokkal, konfigurációval, migrációval és hibaelhárítási útmutatóval átadható az eredmény.

## 20. KÖTELEZŐ ÁTADANDÓK

A meglévő szerkezethez igazítva hozd létre vagy frissítsd:

- repository audit és követelménykövetés;
- architektúra és fejlesztési döntések;
- tool/capability/licenc/forrás-verzió mátrix, az elutasított és opcionális toolok indokával;
- skill coverage és valódi adaptermapping;
- normalizált input/result/error sémák és kompatibilitási migrációk;
- resource-, cache-, retry- és profile-konfiguráció, titokmentes példákkal;
- memory/performance benchmark és fault-injection tesztleírás;
- RCE-miss diagnosztika és kontrollált regressziós fixture;
- ténylegesen működő core, specialist adapterek, MCP/API-kapcsolatok és riport;
- unit/integrációs/E2E tesztek és CI vagy reprodukálható tesztparancs;
- README, CHANGELOG, troubleshooting, dependency/third-party notices.

A végső válasz magyarul, tényszerűen tartalmazza: mi működik, mely fájlok módosultak, hogyan indul, mely parancsokat futtattad, milyen teszteredmények és mért értékek születtek, mi maradt blokkolt/halasztott/nem támogatott. A valós futást különítsd el a mockteszttől, becslést a méréstől, dokumentációt az implementációtól.

A feladat végrehajtásához szükséges hozzáféréseket ténylegesen ellenőrizd. Ha nincs repository vagy terminál, ne állíts kódmódosítást; nevezd meg a hiányt és csak a valóban elkészíthető artefaktumot add át. A környezet megléte esetén kezdd a tényleges auditot és implementációt, ne újabb általános ötletlistát adj.

**Most a RedJohn repositoryt vizsgáld meg, majd implementálj és tesztelj. A RedJohn neve változatlan marad.**

---

## 21. ELSŐDLEGES REFERENCIÁK A FEJLESZTŐ AGENTNEK

A követelmények mérnöki döntések; nem az upstream projektek által garantált RedJohn-képességek. Az alábbi dokumentációkat a prompt előkészítéséhez ellenőriztük; a konkrét telepítési API-t, verziót és licencet az implementáció időpontjában újra kell vizsgálni. A lista nem engedély nyilvános demócélok automatikus szkennelésére.

### Referenciaprojektek és névnormalizálás

- Strix, referencia és célzott újrahasznosítás: https://github.com/usestrix/strix
- HexStrike, a felsorolt modul- és wrappernevek forrása: https://github.com/0x4m4/hexstrike-ai
- CVEMap régi címe, jelenleg VulnX-re irányít: https://github.com/projectdiscovery/cvemap
- ProjectDiscovery VulnX, vulnerability intelligence: https://github.com/projectdiscovery/vulnx

### Browser és felderítés

- Playwright sessionizoláció: https://playwright.dev/docs/browser-contexts
- Crawlee AutoscaledPool: https://crawlee.dev/js/api/core/class/AutoscaledPool
- ProjectDiscovery httpx: https://docs.projectdiscovery.io/opensource/httpx/overview
- Katana: https://github.com/projectdiscovery/katana
- Naabu: https://docs.projectdiscovery.io/opensource/naabu/overview
- Nmap referencia: https://nmap.org/book/man.html
- Amass: https://github.com/owasp-amass/amass
- ffuf: https://github.com/ffuf/ffuf
- Feroxbuster: https://github.com/epi052/feroxbuster
- Gobuster: https://github.com/OJ/gobuster
- RustScan, upstream átirányítással: https://github.com/RustScan/RustScan/blob/master/README.md
- Masscan: https://github.com/robertdavidgraham/masscan
- AutoRecon, upstream átirányítással: https://github.com/AutoRecon/AutoRecon

### Specializált ellenőrzések és audit

- Nuclei template-bevezető: https://docs.projectdiscovery.io/templates/introduction
- Nuclei template-aláírás: https://docs.projectdiscovery.io/templates/reference/template-signing
- TInjA: https://github.com/Hackmanit/TInjA
- WPScan, dokumentáció és licenc: https://github.com/wpscanteam/wpscan
- Prowler: https://github.com/prowler-cloud/prowler
- ScoutSuite: https://github.com/nccgroup/ScoutSuite
- Trivy: https://trivy.dev/docs/latest/guide/
- kube-hunter: https://github.com/aquasecurity/kube-hunter
- kube-bench: https://github.com/aquasecurity/kube-bench
- pwntools: https://docs.pwntools.com/en/stable/
- angr: https://docs.angr.io/en/latest/index.html

### Memória és HTTP hibaszemantika

- Python allokációs megfigyelés: https://docs.python.org/3/library/tracemalloc.html
- HTTP 429: https://www.rfc-editor.org/rfc/rfc6585.html
- HTTP-szemantika és Retry-After: https://www.rfc-editor.org/rfc/rfc9110.html

### További, implementációkor ellenőrizendő upstream kiindulópontok

Ezek a korábbi toolterv kiegészítő hivatkozásai; a futtató agent ellenőrizze a jelenlegi dokumentációt, kiadást és a RedJohnhoz szükséges konkrét funkciót.

- Arjun: https://github.com/s0md3v/Arjun
- Dalfox: https://github.com/hahwul/dalfox
- sqlmap: https://github.com/sqlmapproject/sqlmap
- Schemathesis: https://github.com/schemathesis/schemathesis
- Interactsh: https://github.com/projectdiscovery/interactsh
- Semgrep: https://github.com/semgrep/semgrep
- Commix: https://github.com/commixproject/commix
- Subfinder: https://github.com/projectdiscovery/subfinder
- dnsx: https://github.com/projectdiscovery/dnsx
- GDB: https://sourceware.org/gdb/
