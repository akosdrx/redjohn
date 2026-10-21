# RedJohn: Arjun / sqlmap / Dalfox ellenőrzés

2026-10-18. A meglévő RedJohn repositoryban készült célzott bővítés; a
RedJohn név, origin és korábbi integrációk megmaradtak. Ez a három
specialista GET/query támogatásának igazolása, nem a teljes master prompt
elfogadása.

## Tényleges implementáció

- `arjun_parameters`: valódi Arjun 2.2.7, megfigyelt anonim GET-végpont,
  2–16 jóváhagyott név és korlátozott stabilitáskontroll; pozitív/javított mérés.
- `sqlmap_validate`: valódi sqlmap 1.10.10, konkrét rögzített GET/query input
  és evidence-reffel jelölt hipotézis; level 1/risk 1/boolean-only. A fixture
  tényleges SQLite SELECT-et futtat, a javított változat paraméterezett.
  A named-actor hitelesítést a meglévő host-only vault adja; a token nem
  kerül CLI-argumentumba, inputfájlba, SQLite evidence-be vagy normál logba.
- `dalfox_validate`: valódi Rust Dalfox 3.2.4, egyetlen host-generált ártalmatlan
  nonce-payload. A JSON/exit code és a host által látott forgalom együtt számít.
- `browser_xss_confirmation`: külön tartós job/outbox, valódi sandboxolt
  Playwright/Chromium, benign kontroll és célból érkező nonce-alert. Nincs
  `page.evaluate`/init-script által előállított hamis bizonyíték. A már meglévő
  candidate findinget csak külön host browser-proof után, a fenced finish
  tranzakcióban lépteti `confirmed_weakness` állapotba.
- A meglévő SQLite scheduler, scope/IP/DNS/TLS-proxy, resource governor és
  rate-limit szolgáltatás újrahasznosul. Egyetlen kiválasztott worker fut;
  hibás/tiltott kérésnél azonnali process-stop, véges deadline, külön drainelt
  stdout/stderr, valódi timeout/cancel/process- és lease-cleanup működik.
- A hipotézis újrarögzítésével kapott másik `hint_ref` önmagában nem enged
  új vizsgálatot. A session/surface/tool/profile és explicit retest továbbra
  része a kulcsnak. A provenance-ref a tárolt jobban megmarad.
- 3 angol skill-kontraktus és a manifest frissült, a konfigurációhiány
  readiness-szinten is blokkolt. A többi skill eredeti tartalma és source-provenance
  megmarad. Általános MCP/Nuclei/POST/session munkafolyamat nem lett lecserélve.

## Valós és kontraktusellenőrzések

A `test_specialists_contract.py` schema/argumentum/pin/idempotencia/parser
ellenőrzéseit külön kell kezelni a `test_specialists_live.py` valódi CLI-,
Chromium-, SQLite- és HTTPS-eseteitől. Az utóbbi tartalmazza az újraindítást,
friss hint-ref dedupját, pozitív/javított kontrollt, named-actor replayt és
lejáratot, két külön CLI-processzt, valódi cancel/timeoutot, rossz CA/digestet,
429-et és scope-on kívüli redirectet. A hibás pin tesztjében helyesen nem
indul engine. A teljes csomag korábbi mockteszteket is tartalmaz: az ott
kiírt 35 bájtos fake Nuclei installer-receipt nem live-binárisbizonyíték.

A végső futások adatai a `measurements/specialists/` alatt találhatók.
A `source-hashes.json` 313 fájlt rögzít, köztük 262 Python-forrást; ugyanaz
a forrásállapot ment a Linux-futtatóba. A telepített valódi executable/bundle
hasheket a platformonkénti `binary-integrity.json` és a külön receipt-ek adják.

| Ellenőrzés | macOS ARM64 | Ubuntu ARM64 |
|---|---:|---:|
| Teljes Python csomag | 843 pass, 21 skip, 312.98 s | 864 pass, 0 skip, 429.07 s |
| Strict mypy | 194 modul, 0 hiba | 194 modul, 0 hiba |
| Külön teljes lánc RSS-mintavétel | 528.02 MiB, 16.75 s, 2 pass / 2 kernel-skip | 924.20 MiB, 31.33 s, 4 pass |

Ruff és formátumellenőrzés sikeres. A viewer build 2261 modullal lefutott,
a strict TypeScript ellenőrzés sikeres; a négy buildelt asset byte-azonos
a meglévőkkel. Go test/vet sikeres, a négy csomagban nincs Go unit teszt.
A memória külső process-tree RSS-mintavétel, a minták között 100 ms sleep
és további ps-overhead; nem pontos 10 Hz-es vagy hard RAM-mérés.

## Mért workload és értelmezés

A lánc minden szakasznál újranyitja a store-t/runtime-ot. A Dalfox-processz
megszűnik a browser follow-up előtt; a gyermek új runtime-ból is végrehajtható.
A teljesen befejezett jobok, valamint egy új evidence-ref-fel újratervezett
azonos hipotézis újraküldése nem ad új célkérést. Külön CLI-kör ellenőrzi
a processzújraindítást és a rate-változás utáni dedupot.

A saját fixture SQL-hintje explicit, operator által kijelölt teszthipotézis.
Ez nem bizonyít automatikus SQLi-hintgenerálást. A SQLMap-jelzés candidate
marad; a browserrel megerősített XSS külön gyengeségszint. A javított kontroll
negatívja csak az itt lefuttatott vizsgálatokra vonatkozik.

A memóriaadat process-tree RSS összeg, benne a pytest/controller, a kiválasztott
worker és szükség esetén Chromium. Megosztott lapok többször számolhatók; ez
nem kizárólagos engine-heap, nem OS hard RAM-limit és nem általános gyorsulási
ígéret. Rövid kontroll-workload futott, hosszú soak nem. A phase-outputban
közölt finding-record számot nem szabad a SQLite-ban deduplikált findingek
számával összekeverni; az utóbbi külön `derived-cases.json` adat.

## Indítás és reprodukció

Repo-root: `/Users/akosdrx/Documents/rjkali`. A binárisok/bundle-ök a
meglévő `.tools` alatt maradtak. A pin- és profilkonfiguráció operator által
jóváhagyott értékeket igényel; a dokumentációs példa nem éles céllista.

```sh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment health
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/path/approved-engagement.json \
  --output /absolute/path/redjohn-run --max-jobs 16
PYTHONPATH=. REDJOHN_REQUIRE_SPECIALIST_E2E=1 \
  .venv/bin/python -m pytest tests/test_specialists_contract.py \
  tests/test_specialists_live.py -q -s
```

A teljes futás parancsa `python -m pytest tests -q -s
-p no:cacheprovider --junitxml=...`, előre telepített pinned engine-ekkel és
`REDJOHN_REQUIRE_FFUF_E2E=1`, `REDJOHN_REQUIRE_PD_E2E=1`,
`REDJOHN_REQUIRE_SPECIALIST_E2E=1` változókkal. Linuxon
`REDJOHN_REQUIRE_REMOTE_E2E=1` is kötelező volt. Mindkét futtatón
`REDJOHN_TELEMETRY=0`, `OPENAI_AGENTS_DISABLE_TRACING=1`. A mérési JSON-ok
külön `REDJOHN_*_MEASUREMENTS` kimenetet kaptak.

Strict típusellenőrzés: a repository gyökerében
`.venv/bin/python -m mypy redjohn --no-incremental`.
Ruff: `.venv/bin/ruff check redjohn scripts tests`.
Frontend: `npm run build -- --outDir /tmp/redjohn-specialists-viewer
--emptyOutDir`, majd `tsc --noEmit --incremental false --noUnusedLocals
--noUnusedParameters`. Go: `go test ./...`, `go vet ./...`.

Részletes angol runbook, források/licencek és inputhatárok:
[query-specialists.md](query-specialists.md). Titokmentes példa:
[assessment-query-specialists.json](../examples/assessment-query-specialists.json).
A GitHub workflow frissült, de itt GitHub Actions-futás nem történt; saját,
repo-mount nélküli eldobható Ubuntu ARM64 VM adta a Linux bizonyítékot.

## Blokkolt, nem támogatott és nem igazolt részek

- macOS alatt nincs a szükséges Linux kernel-egress; a távoli workerprofil
  fail-closed. A helyi loopback-fixture nem helyettesíti ezt. Linuxon valódi
  nem-loopback HTTPS/namespace lánc futott.
- Az új specialistákban POST/JSON/form/multipart mutáció, ismételt selected
  query-paraméter, named-actor Arjun/Dalfox/browser, stored XSS és általános
  DOM-only/OAST vizsgálat unsupported. A korábbi Nuclei POST/session út él.
- Tényleges SQL-fixture: SQLite. Más engedélyezhető DBMS-profil nem kapott itt
  pozitív/javított live kontrollt. Egress/scheduler integráció nem jelent
  általános sérülékenységdetektálási garanciát.
- A scanner-hypothesis nem confirmed impact. A hiányzó eredeti RCE-fixture
  továbbra is `not_reproduced_missing_fixture`, nem negatív eredmény.
- A RAM-admission kooperatív; nincs minden host-folyamatot/több külön DB-t
  lefedő globális hard governor. Kali/AMD64 kiadás, kereskedelmi csomagolás
  és hosszú terhelési soak nem lett igazolva.
- sqlmap GPL-2.0-or-later + upstream clarifications: az upstream az exec +
  output parsing integrációt is a saját derived-work értelmezésébe sorolja.
  Proprietary redistribution nincs tisztázva; a külön processz önmagában nem
  licencmentességi állítás. Arjun LICENSE AGPL-3.0, a setup.py GPL-metaadata
  eltér, dicttoxml függősége GPL-2.0. A teljes rögzített licencek megmaradnak
  az opcionális telepítésben; RedJohn licencmetaadata nem lett átírva.

## Megőrzés és takarítás

A rögzített HEAD/origin/index és a privát MCP-konfiguráció hash-e változatlan.
A 60 meglévő teszt/support fájlból 59 byte-azonos; a skill-readiness teszt
az immár implementált adapterek állapotához igazult. Két új aktív tesztfájl
marad. A 47 skillből 44 byte-azonos; három célzott angol kontraktus frissült.
Baseline fájl nem hiányzik. Részletek: `measurements/specialists/preservation.json`.
A generált debugadatok csak a folytatás ellenőrzéséig maradtak ideiglenes
könyvtárban; a végső takarítást az új schema/OAST-jegyzőkönyv rögzíti. Az
opcionális engine-ek megmaradnak, a saját Linux VM az új adapterkört is kiszolgálta.

## Korábbi ellenőrzési kör diagnosztikája

A dedup-javítás előtti teljes Linux-futás 862 sikeres tesztet adott, kihagyás
nélkül. Az első macOS-körben 840 siker, 21 skip és egy failure volt:
`test_worker_timeout_retains_partial_output_and_cleans_descendants` az 1 s
deadline mellett egyszer nem kapta meg a várt stdout-markert. A változatlan
supervisor-csoport külön újrafuttatva 45/45 lett; a hiba pontos oka nem
bizonyított. A teszt követelménye és forrása változatlan maradt. A diagnosztika
a `measurements/specialists/diagnostics/` alatt külön megmarad; a fenti végső
eredmények a dedup-javítás utáni teljes futásokból származnak.

A végső Linux-ellenőrzést megelőző külön kör 839 pass / 25 failure volt.
Ekkor a típusellenőrző ugyanabban a VM user-cgroupban futott: a valós
resource governor admissiont blokkolt, több E2E előfeltétele emiatt hiányzott.
A kód és a tesztek lazítása nélkül, külön futtatott teljes kör 864/864 lett.
A típusellenőrzés külön ugyanezen forrásokon sikeres. Az előző hibás kör
logja/XML-je külön diagnosztikaként megmarad. Ez erőforrás-blokk, nem negatív scan.

A jelenlegi átadás kumulatív fájllistája: [redjohn-changed-files.md](redjohn-changed-files.md).
A későbbi schema/OAST-kör teljes csomagja a korábbi integrációkat ismét ellenőrzi;
a fenti 843/864 eredmény a saját 313 fájlos történeti forrásállapothoz tartozik.
