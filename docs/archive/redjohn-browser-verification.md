# RedJohn headless browser – tényleges ellenőrzés

Mérés dátuma: 2026-10-17. A RedJohn neve és meglévő agent-browser/Caido
integrációja változatlan. A tesztek kizárólag a helyi, eldobható HTTP-fixture-t
érték el. Firecrawl nem vett részt a fejlesztésben vagy futtatásban. Strixből és
HexStrike-ból nem került át browserkód.

## Audit és implementáció

A korábbi `redjohn/tools/agent_browser/README.md` sandboxban telepített
`agent-browser@0.26.0` CLI-t dokumentál; a repositoryban ehhez nem tartozott
host-side determinisztikus crawl, browser admission vagy browser integrációs
teszt. A `redjohn/runtime/caido_bootstrap.py`, `redjohn/tools/proxy/caido_api.py`
és `redjohn/tools/proxy/tools.py` valódi bootstrap/capture/replay kód. Ezeket az
új implementáció nem módosította. A Caido helyi futását ez a browser-teszt nem
igazolja.

Az új `redjohn/assessment/browser.py` egy governor által lefoglalt Chromiumot
használ. Minden discover futás új contextet és page-et kap; az actor és a
sessionrevision minden megfigyeléshez kapcsolódik. Legfeljebb egy futás dolgozik
ugyanabban a service-ben. Az opcionális Playwright import csak aktiváláskor
történik. JavaScript és a Chromium sandbox engedélyezett; TLS-ellenőrzés marad.

A crawl-frontier, összes visited page, request-metaadat, form, input, DOM-bejárás,
URL-hossz és futási idő külön korlátos. Linkekből kizárólag explicit
`navigation_urls` allowlistre kerülő URL navigálható; ismeretlen gombot vagy
formot nem aktivál a kód. A browser által kezdeményezett módosító kérés
metaadata megmarad, de `sent=False`, és az adapter nem küldi el. Formérték,
cookie, authfejléc, response body és screenshot nem kerül az eredménybe.

A valós teszt feltárta, hogy a Playwright route callback nem elegendő a teljes
redirectlánc védelmére. Ezért a `browser_proxy.py` HTTP proxy tényleges
connect előtt újra ellenőrzi a policyt. A loopback proxymegkerülést Chromium
`<-loopback>` beállítása tiltja; QUIC, nem proxizott WebRTC és WebSocket
forgalom letiltott. A proxy legfeljebb 16 kapcsolatot kezel, 16 KiB request
headerrel, 64 KiB streambufferrel, 8 MiB irányonkénti wire-limittel és 10 s
kapcsolati deadline-nal. CONNECT és HTTPS explicit nem támogatott ebben az új
adapterben: a TLS-alagút nem tenné lehetővé az összes HTTP-kérés számlálását és
redirectellenőrzését. A közös request-admission callback az actual outgoing
connect előtt fut; a válaszobserver csak content-type/retry-after fejlécet ad.

A policy jelenleg kizárólag `isolated-lab`, `local-fixture`, literal-loopback
célokat enged. Az új browser adapter ezekből kizárólag HTTP-t támogat. A proxy
nem OS/network namespace, és nem nyers HTTP-capture. Távoli
profilhoz a hiányzó infrastruktúra-egress miatt explicit blokkolás tartozik.
Az admission memóriafoglalás nem OS-hardlimit vagy tömörített body elleni teljes
browser RAM-garancia. Ezek nem teljesített production képességek.

## Függőségek és forrás

- Python 3.13.16; Playwright Python 1.58.0; hozzá tartozó Chromium bundle 1208,
  tényleges Chromium `145.0.7632.6`.
- A Playwright telepített disztribúciójának `License-Expression` mezője
  `Apache-2.0`; licencfájlok a disztribúció `dist-info/licenses/LICENSE`,
  `playwright/driver/LICENSE` és `playwright/driver/package/LICENSE` helyén.
  A Chromium saját és harmadik féltől származó licenceit a bundle őrzi meg.
- Elsődleges API-források: [Browser](https://playwright.dev/python/docs/api/class-browser),
  [BrowserContext](https://playwright.dev/python/docs/api/class-browsercontext),
  [Page](https://playwright.dev/python/docs/api/class-page).

Telepítés a használt virtuális környezetben:

```sh
.venv/bin/python -m pip install 'playwright==1.58.0' 'psutil==7.2.2'
.venv/bin/python -m playwright install chromium
```

A psutil a méréshez rendelkezésre állt; az adapter nem importálja és nem igényli.
A resource governor a saját process-tree mérését használja.

## Lefuttatott parancsok és eredmények

Munkakönyvtár: `/Users/akosdrx/Documents/rjkali/RedJohn`.

```sh
REDJOHN_BROWSER_SOAK_CYCLES=20 .venv/bin/python -m pytest tests/test_assessment_browser.py -q -s
.venv/bin/python -m ruff check redjohn/assessment/browser.py redjohn/assessment/browser_proxy.py tests/test_assessment_browser.py
```

A valódi Chromium suite: **5 passed in 13.23 s**, nincs browser-mock vagy
szimulált Chromium. A tesztcsoport ellenőrzi a következőket:

- SPA által generált link, fetch, XHR, iframe és multipart form;
- Alice/Bob cookie/session elválasztás, 20 friss contextben;
- ismeretlen form és logout nem fut; automatikus JSON POST nem ér célhoz;
- scope-on kívüli redirect megáll a proxyban, a célhandler nem kap kérést;
- readiness timeout, max request, explicit cancel és valódi CDP `Browser.crash`;
- request-admission kampánybudget és 429/Retry-After válaszcallback;
- page/context/governor lease cleanup siker, hiba, crash és cancellation után.

Az alap ismétlődés 5 ciklus. A `REDJOHN_BROWSER_SOAK_CYCLES` 3–1000 közötti
értékkel konfigurálható. A fenti futtatás 20 ciklust hajtott végre; nem többórás
soak.

## Mért értékek

| Metrika | Tényleges érték |
|---|---:|
| SPA ciklus | 20 |
| Tényleges HTTP-kérés a fixture-ben | 100 |
| LLM model call / input token / output token | 0 / 0 / 0 |
| Létrehozott / lezárt context | 20 / 20 |
| Létrehozott / lezárt page | 20 / 20 |
| Aktív context / page két ciklus között | 0 / 0 |
| Browserrel együtt élő process-tree darabszám, minden mintában | 6 |
| Process-tree darabszám indítás előtt / lezárás után | 2 / 2 |
| Első / utolsó RSS-minta, bájt | 412205056 / 437551104 |
| Megfigyelt peak RSS, bájt | 439697408 |
| Futásonkénti idő minimum / maximum, másodperc | 0.285695 / 0.482055 |

A mérési módszer `process_tree_summed_rss_shared_pages_may_be_counted_multiple_times`:
controller és gyermekfolyamatok RSS-összege; közös lapokat többször számolhat.
Ez nem Python heap vagy garantált hard-limit. A 20 mintában a memória időnként
csökkent; a rövid futás nem bizonyít általános vagy hosszú távú leakmentességet.
A page/context/process darabszám ténylegesen visszaállt a tesztben. A korábbi,
LLM által vezérelt agent-browser azonos konfigurációjú baseline-ja hiányzik:
`baseline_unavailable`; gyorsulási százalékot nem állítunk.

## Tartós pipeline E2E

```sh
.venv/bin/python -m pytest tests/test_assessment_pipeline.py -q -s
```

Az első önálló futás: **1 passed in 1.95 s**; a pipeline tényleges futása
1.371086 s. Valós Chromium és helyi HTTP: 23 perzisztált surface, 4 eredeti job
(Alice/Bob discovery, header audit, hiányzó Nuclei blokkolva), 2 bizonyítékhoz
kötött header candidate. A JSON/HTML riport escaping ellenőrzött. Új
store/runtime ugyanabból az `.state/agents.db` fájlból visszaolvasta az
inventoryt, jobokat és evidence-t; azonos jobkulcsok újrabeküldése 0 új kérést
okozott. Külön `retest_revision` új jobot hozott létre a javított HTTP-header
kontrollon: 0 új candidate. Összesen 10 tényleges HTTP-kérés és 10 tartós
request-budget charge, 0 LLM-hívás. A régi candidate-ek történetileg megmaradnak;
automatikus `fixed` lifecycle-átvezetést ez a teszt nem állít.

Az integrált teszt ellenőrzi a megismételt queryparaméter és `%2f` encoding
megőrzését, SPA history route megfigyelését, dinamikus link inferred státuszát,
JSON/XML/multipart bemeneteket, valamint a blokkolt POST `sent=False` evidence-t.
A Nuclei itt ténylegesen hiányzó capability (`failed/blocked`), nem mock scanner
és nem sikeres negatív vizsgálat. Valódi Nuclei-végrehajtást ez nem bizonyít.

A később hozzáadott regressziók külön ellenőrzik a hiányzó actor state-et,
magasabb sessionrevisionhöz adott régi state-et és az eltérő wrapperrevisiont:
mindhárom esetben 0 hálózati kérés és 0 browserindítás történik. Valódi Chromium
401-es válasz esetén a névvel/revisionnel/tenanttel ellátott részleges evidence
megmarad, a job `failed/blocked/authentication_expired`, 1 attempt és 1 kérés;
nincs anonim fallback vagy vak retry.

Utolsó együttes parancs:

```sh
.venv/bin/python -m pytest tests/test_assessment_browser.py tests/test_assessment_pipeline.py -q -s
.venv/bin/python -m ruff format --check redjohn/assessment/browser.py redjohn/assessment/browser_proxy.py tests/test_assessment_browser.py tests/test_assessment_pipeline.py
.venv/bin/python -m ruff check redjohn/assessment/browser.py redjohn/assessment/browser_proxy.py tests/test_assessment_browser.py tests/test_assessment_pipeline.py
.venv/bin/python -m mypy redjohn/assessment/browser.py redjohn/assessment/browser_proxy.py --follow-imports=skip
```

Eredmény: **10 passed in 11.98 s**, 4 saját Python fájl formázása és Ruff
ellenőrzése sikeres; a 2 browser modul elkülönített mypy ellenőrzése sikeres.
Ez nem a teljes repository mypy igazolása. Az utolsó integrált pipeline
1.263613 s, 23 surface, 10 kérés, 2 kezdeti header candidate, 0 candidate a
javított header retestben, 0 ismételt kérés restart után, 0 model call.

Utolsó célzott pipeline-regressziós futás: **7 passed in 6.76 s**. Két új
regresszió ellenőrzi a scheduler teardown-határait. A cleanup közbeni cancellation
egy gyors fake adapterrel azt igazolta, hogy csak 1 job fut, a második attemptje
0 marad, mindkettő cancelled/partial, a kampány stopped, 0 HTTP és 0 aktív lease.
Ez kontraktusteszt, nem valódi scannerfutás. A másik teszt két valódi Chromiumot
használó runtime szekvenciális batch-eit futtatja ugyanazon DB-n: a batch végén,
a coordinator lock elengedése előtt a browserprocess és minden lease felszabadul,
a processzszám visszaáll. Az első batch-en belül 2 context ugyanazt a service-t
használja, a második runtime 1 contextet futtat. Ez külön workload a fenti,
folyamatos service-reuse mellett mért 20 ciklustól; a korábbi mérési számokat
nem módosítja.

A hiányzó Chromium executable külön, valódi környezeti regressziót kapott:
új Python subprocess saját, szándékosan hiányzó `PLAYWRIGHT_BROWSERS_PATH`
értékkel, az eredeti browsercache módosítása nélkül. A service stabil
`chromium_executable_missing` hibát ad, a pipeline `failed/blocked` és
`blocked_missing_dependency`; 0 kérés, 0 context/page/proxykapcsolat, 0 lease
marad. A nyers Playwright hiba, executable path és indítási argumentumok nem
jelennek meg a visszaadott eredményben. Egyéb Playwright launchhiba stabil
`browser_launch_failed`, sandboxkikapcsoló fallback nélkül.

A legutóbbi pipeline suite **8 passed in 7.79 s**; saját Ruff és a két
browsermodul elkülönített mypy ellenőrzése sikeres. Ez a futás és a megelőző
7 tesztes futás külön verzióállapotok; a 20 ciklus önálló service-mérése
változatlanul külön benchmark.

Az összes ciklus ideje másodpercben:

```json
[0.410677,0.291566,0.304401,0.323593,0.312794,0.314097,0.307822,0.299795,0.319686,0.333961,0.300424,0.482055,0.315494,0.315954,0.306867,0.320894,0.297474,0.324687,0.294276,0.285695]
```

RSS-minták bájtban:

```json
[412205056,418463744,423510016,426852352,430292992,433242112,436240384,426524672,429768704,432783360,435568640,426131456,429015040,431554560,434192384,436813824,439697408,432340992,434946048,437551104]
```

## Lefedettségi határ

Ezek browser- és proxyintegrációs ellenőrzések. Nem bizonyítanak Caido replayt,
Nuclei-találatot, authz hibát, RCE-t, teljes cross-browser működést vagy távoli
production egress enforcementet. Service worker és WebSocket funkció explicit
láthatósági korlát; nyers HTTP request body hiányában body-alapú specialist
végrehajtás külön rögzített kérésforrást igényel. Timeout, 429 és blokkolt
mutating request partial/inconclusive lefedettséget eredményez, nem negatív
sérülékenységi eredményt.
