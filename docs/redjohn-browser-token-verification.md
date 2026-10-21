# RedJohn: automatikus Chromium POST-capture és body-token frissítés

Történeti baseline. A refresh utáni újraindítás nélküli, egyworker-es
folytatás aktuális igazolása a
[continuous refresh jegyzőkönyv](redjohn-continuous-refresh-verification.md).

Ellenőrzés: 2026-10-17, a meglévő `/Users/akosdrx/Documents/rjkali` checkoutban.
A korábbi POST/refresh jegyzőkönyv történeti baseline; az alábbi az új
böngészős képesség és a kért 84 mypy-hiba javításának külön igazolása.

## Működés

- A külön `browser_post_capture` képesség tényleges headless Chromiumot használ.
  Az engedélyezett alkalmazás JavaScriptje állítja elő a JSON/form/multipart
  POST-ot; a host proxy a tényleges byteokat fogja el. A normál
  `browser_discover` továbbra is csak olvasó módú.
- Privát, 0600-as, identity/session/policy/URL/media-type/expiry szerint kötött
  szabály kell az automatikus jóváhagyáshoz. A teljes 2xx proxyválasz után a
  pontos body csak a privát vaultba kerül; inventory/evidence kizárólag digestet,
  bytehosszt, identityt és valódi elküldési/befejezési bizonyítékot kap.
- A capture tartós foglalást, atomi budget-admissiont és fencinget használ.
  A módosító browser-job nem idempotens. Contextváltás előtt lezárja a contextet
  és befejezi vagy bizonytalanként elkeríti a még futó capture-kéréseket.
  A vault kézi credential-módosítását nem írja felül; a credential lejáratát
  nem hosszabbítja meg. Az eltérő, előzetesen konfigurált endpoint-credentialök
  elkülönülnek.
- Explicit privát mezőkötés alapján frissül a JSON string, formparaméter vagy
  multipart szöveges mező. Csak a kiválasztott érték bytejai változnak; más
  mező, paramétersorrend, whitespace és bináris feltöltés megmarad. Header,
  cookie vagy explicit provider-válaszmező szolgáltathat új tokent.
- Sikeres refresh után 7 → 8 revízió, valódi cache-invalidation és
  `fresh-capture-required` állapot következik. A friss body önmagában nem
  replay-jogosultság. A következő coordinator-startup a privát szabály
  `start_url` és `current` revíziója alapján deduplikált browser-jobot sorol be.
  Csak a tényleges új capture jóváhagyása nyitja meg az új Nuclei-replayt.
- Multipart esetén az új Chromium-boundary engedett eltérés: a frissítés utáni
  capture összehasonlítása kizárólag a validált boundary framinget hagyja ki,
  minden partfejlécet, sorrendet, payloadot és uploadot pontosan ellenőriz.
  A reviewzott Nuclei-template fix publikus Content-Type/body sentinelt
  használhat; a host injektálja a privát aktuális boundary-t és bodyt.
  Régi lockot vagy sorban álló jobot nem írunk át.
- Az eredeti 84 mypy-hibát típusos SQLite/JSON-szerződések, strukturális
  worker/rate-limit protokollok, szűkített Optional-ágak és típusos execution
  verziómezők javítják. Nincs blanket ignore vagy kikapcsolt ellenőrzés.

## Teszt és mérés

| Ellenőrzés | Tényleges eredmény |
|---|---|
| Teljes Linux Python-csomag | **478 passed / 1 skipped**, 479 eset, **158,01 s**, nulla failure/error |
| Teljes macOS Python-csomag | **473 passed / 6 skipped**, 479 eset, **102,52 s**, nulla failure/error |
| Strict mypy, projektkonfigurációval | **22 forrásfájl sikeres**; az eredeti 84 hiba megszűnt |
| Ruff + formatter | Sikeres; **80 fájl** formátuma ellenőrizve |
| AST / natív angol skill-hash | **231 Python-fájl / 47 assessment contract** sikeres |
| Viewer `npm run build` | **2260 modul, 2,73 s**; a nagy chunk figyelmeztetés megmaradt. Saját temp-outputba épült, a meglévő static bundle megmaradt. |
| TUI `go test ./...` | Sikeres; **4 package, nincs tesztfájl**, ezért fordítási ellenőrzés |

A hat macOS-skip a három Linux-kernel-izolációs teszt és a három remote E2E.
Ugyanezek Linuxon ténylegesen lefutottak. Linuxon egyedül az eredeti,
repositoryn kívüli felhasználói skillpack forrásfájljainak hash-összehasonlítása
maradt ki: ez a csomag nem került a VM-be. A natív angol tartalomhash-ek ott is
helyesek; az eredeti forrás összehasonlítása macOS-en sikeres volt.

| Új, valódi Chromium → capture → scheduler → Nuclei → refresh E2E | Mérés |
|---|---|
| Időtartam | **31,645189 s** |
| Valódi HTTPS-kérés / SQLite request charge | **19 / 19** |
| Forrás | **2 GET**, **6 Chromium POST-capture**, **10 Nuclei POST-replay**, **1 refresh POST** |
| Külön CLI-folyamat | **17** |
| Bodyformátum / capture-revízió | JSON, form, multipart; **7 és 8** |
| Pozitív candidate / fixed kontroll | **6 candidate**, mindhárom formátum fixed kontrollja **0** új finding |
| Refresh / restartduplikáció / credential-trap | **1 / 0 / 0** kérés |
| Body-token / session | Mindhárom formátumban igazolt tokenváltás és **7 → 8** revízió |
| Multipart template-bundle | **Változatlan SHA-256** a Chromium új boundary-ja mellett |
| Modelhívás | **0** |
| Mintavételezett processfa-RSS maximum | **1 022 496 768 byte = 975,13 MiB**, legfeljebb 16 folyamat |
| Mintavétel | **1258 minta**, 25 ms célköz; legnagyobb megfigyelt köz **152,25 ms** |

A processfa-mérés a CLI-t és tényleges leszármazottait, a Chromium/namespace/
Nuclei workereket is követi. Közös lapokat többször számolhat; a mintavétel nem
bizonyít abszolút maximumot. A systemd stdout végén szereplő 736 kB service-
érték eltérő mérési határ, ezért nem használjuk worker-memóriaként. A korábbi
SDK-only POST-workload kisebb RSS-e más feladatot mért; nincs százalékos
memória- vagy sebességjavulási állítás.

Az új browser-tesztfájl **8 esetet** tartalmaz: valódi Chromium mindhárom
formátummal és változatlan readonly-defaulttal; külön endpoint-credentialök;
operator-vaultmódosítás; lejárat; továbbá valódi HTTPS lost-response,
Content-Length truncation, túlméretes válasz és bounded drain-cancel. Az utóbbi
esetekben uncertain állapot, nulla új approval/surface, SQLite-újranyitás után
nulla további POST és egy request charge az elvárt eredmény.

Az új body-token tesztfájl **30 esetet** tartalmaz, unit-kontraktusokat és valódi
HTTPS/engine-integrációkat külön. A valódi provider-teszt mindhárom bodyt
frissíti; a hiányzó tokenforrás bizonytalan eredmény és nulla automatikus resend.
A külön valódi Nuclei multipart-teszt két capture és három scan mellett ugyanazt
a publikus template-et használja 7 és 8 között: két candidate és fixed 0.
A teljes Linux-lánc ezek mellett tényleges Chromiumból indul, SDK-capture nélkül.

A régi capture/refresher, redakciós, proxy-, engine-, browser- és scheduler-
regressziók is a teljes csomag részei maradtak. A szándékosan átcímkézett régi
capture kontrollját az E2E külön azonosítja: evidence-e továbbra is 7-es,
replayje blokkolt, hálózati mellékhatása nulla. Nem számít a három valódi
8-as capture egyikének. A CLI exit 1 az ilyen megőrzött blocked/inconclusive
kontroll miatt egy későbbi sikeres job után is helyes lehet; a teszt a jobot és
az összesített coverage-t külön ellenőrzi.

Futtatókörnyezet: saját, ideiglenes Ubuntu 24.04 ARM64 VM, 2 CPU / 4 GiB,
Linux 6.8.0-117-generic, Python 3.12.3, bubblewrap 0.9.0,
Playwright 1.58.0 / Chromium **145.0.7632.0**. Hostkönyvtár-mount és
SSH-agent forwarding nem volt; az AppArmor user-namespace beállítása kizárólag
ebben a később törölt VM-ben változott. A 296 átadott source/skill/template/
workflow fájl host- és guestoldali SHA-256-ja mind egyezett.

Nuclei **3.11.1**, MIT, upstream commit
`a8c88feb4a1c8e961b7902534ce3af97e9d524a4`; Linux ARM64 binary SHA-256:
`f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477`.
Új külső komponens vagy Strix/HexStrike-kód nem került be; a meglévő pinned
engine maradt. A GitHub-workflow új mérési artifact változót kapott,
GitHub-build/publish nem történt ebben a folytatásban.

Bizonyítékok:
[összesítés](measurements/browser-token-verification-summary.json),
[Linux stdout](measurements/browser-token-linux/browser-token-full.txt),
[Linux JUnit](measurements/browser-token-linux/browser-token-full.junit.xml),
[macOS stdout](measurements/browser-token-macos-tests.txt),
[macOS JUnit](measurements/browser-token-macos.junit.xml),
[részletes Chromium E2E-mérés](measurements/browser-token-linux/browser-token-e2e.json),
[megmaradt SDK-lánc aktuális mérése](measurements/browser-token-linux/post-refresh-e2e.json),
[strict mypy](measurements/browser-token-mypy.txt),
[Ruff](measurements/browser-token-ruff.txt),
[viewer build](measurements/browser-token-viewer-build.txt),
[Go](measurements/browser-token-go-tests.txt),
[runtime](measurements/browser-token-linux/runtime.json),
[dependency-verziók](measurements/browser-token-linux/pip-freeze.txt),
[engine/licenc receipt](measurements/browser-token-linux/nuclei-install.json),
[source-azonosság](measurements/browser-token-linux/source-verification.json),
[source/skill-ellenőrzés](measurements/browser-token-source-skills.json).

## Reprodukció

Az előzetesen jóváhagyott privát vault, browser-rule és refresh-provider pontos
sémája, tokenbindingjei, a bootstrap GET-anchor és a fix multipart-sentinel:
[angol fejlesztői/futtatási útmutató](../RedJohn/docs/browser-post-body-tokens.md).
A privát fájlokat saját, 0700-as könyvtárban, 0600-as móddal kell létrehozni;
nem tartoznak a repositoryba vagy a worker mountjaihoz.

```bash
# Explicit előkészítés, ha a már ellenőrzött engine/browser még nincs telepítve:
.venv/bin/python RedJohn/scripts/install-nuclei-pinned.py
.venv/bin/python RedJohn/scripts/create-nuclei-fixture-lock.py
.venv/bin/python -m playwright install chromium

# Indítás és későbbi újraindítás ugyanazzal a konfigurációval/outputtal:
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/approved-browser.json \
  --output redjohn_runs/approved-browser --max-jobs 1

# Teljes regressziós csomag:
PYTHONPATH=RedJohn .venv/bin/python -m pytest RedJohn/tests -q

# Linuxon: a hiányzó namespace/engine capability kötelező hibát okoz:
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_BROWSER_TOKEN_MEASUREMENTS=/tmp/redjohn-browser-token.json \
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_browser_token_pipeline.py -q -s
```

A további lefuttatott ellenőrzések megismétlése Bash/Zsh alatt:

```bash
(cd RedJohn && ../.venv/bin/mypy \
  redjohn/assessment/{auth_replay,request_body,session_refresh,capture,models,policy,browser_proxy,adapters,store,runtime,scheduler,registry,native_session,contracts,browser,browser_capture,browser_workflow,body_tokens,browser_tls,egress,_egress_worker}.py \
  redjohn/tools/hunt/nuclei.py)

.venv/bin/ruff check RedJohn/redjohn/assessment \
  RedJohn/redjohn/tools/hunt/nuclei.py RedJohn/tests
.venv/bin/ruff format --check RedJohn/redjohn/assessment \
  RedJohn/redjohn/tools/hunt/nuclei.py RedJohn/tests

(cd RedJohn/redjohn/interface/viewer/frontend && \
  npm run build -- --outDir /tmp/redjohn-browser-viewer-build)
(cd RedJohn/redjohn/interface/tui && go test ./...)
```

A scanner futásához külön reviewzott engine/template-lock és kiválasztott
Nuclei-job kell. A startup capture-jobot hoz létre, nem választ tetszőleges
scannert vagy template-et. A mellékhatásos refresh külön explicit job marad.
A következő startup automatikusan egyezteti a sikeresen frissített revízióhoz
tartozó browser-capture-t; lezárt vagy bizonytalan régi jobot nem küld újra.

## Határok és hibaszemantika

A mock/unit ellenőrzés és a valódi Chromium/HTTPS/Nuclei futás külön bizonyíték.
Az új teljes Linux E2E nem használja a host HTTPX capture SDK-t: az alkalmazás
JavaScriptje állítja elő mindhárom POST-formátumot. A korábbi SDK/GET tesztek
aktívak maradtak. Minden új hálózati teszt saját, ártalmatlan fixture-t használ;
ez nem nyilvános cél vizsgálata vagy az eredeti, hiányzó RCE-fixture igazolása.
A marker találata candidate; a javított kontroll csak az adott ellenőrzésben
negatív. A TLS/401/403/429/redirect/truncation/hiányzó képesség nem negatív.

- Nincs általános login/MFA/CAPTCHA/OAuth-discovery vagy ismeretlen gombokra
  kattintás. A browser természetes, szabály szerint engedett alkalmazásforgalmát
  fogjuk el. Persistent `storage_state` átírása helyett a proxy a friss,
  originhez kötött credentialt injektálja.
- Nincs heuristikus tokenkeresés vagy általános stringcsere. JSON-nál csak
  kiválasztott string érték, form/multipart esetén kiválasztott szövegmező
  módosítható. Upload, numerikus JSON-mező, raw HTTP/XML és nested multipart
  tokenátírás nem támogatott. A provider saját refresh-tokenjének rotációja
  továbbra is külön, hiányzó integráció.
- Legfeljebb 16 binding/kérés, 4096 byte/token és 16 KiB összes forrásérték;
  JSON parser max. 64 mélység/4096 node. A POST body max. 64 KiB,
  capture response max. 80 KiB wire; a teljes browser-flow határideje és
  request-/connection-/vault-kerete kódban korlátozott.
- A multipart-public-sentinel kizárólag validált privát multipart bodyhoz,
  pontos markerhez és reviewzott template-hez engedett. Ez nem dinamikus
  template-futtatás, wildcard Content-Type vagy uploadátírás.
- A privát vaultcsere és SQLite-commit két tartós művelet. Crash/lost-response
  esetén uncertain állapot és kézi egyeztetés szükséges, nincs vak resend.
  Más session/actor/policy vagy régi capture átcímkézése blokkolt.
- A távoli worker kernelhatára Linuxot/bubblewrapot igényel. A macOS
  loopback-fixture teszt nem állít Linux-kernel-enforcementet.
- A mért RSS mintavételezett processfaösszeg, közös lapokat többször számolhat;
  nem abszolút maximum és nem kemény cgroup RAM-limit bizonyítéka.
  A teljes master prompt valamennyi opcionális adaptere és release-követelménye
  ettől még nem kész.

## Megőrzés és átadás

Mind a **220 kiinduló Python-forrás-/tesztfájl megmaradt**. A korábbi 39 aktív
teszt-/supportfájlból **38 hash-e változatlan**; egy meglévő capability-lista
assertion kizárólag az új `browser_post_capture` elemmel bővült. A bővítés
visszacserélésével byte-ra az eredeti baseline-hash áll elő: más korábbi
assertion vagy tesztfüggvény nem változott. A 4 új tesztfájl összesen 40 esetet
adott a korábbi 439-hez. Aktív teszteset nem törlődött.

A Git HEAD, index és master prompt hash-e változatlan; az origin továbbra is
`https://github.com/akosdrx/redjohn.git`. Nem volt reset, clean, stage, commit
vagy publish. A korábbról örökölt nagy Git-átstrukturálást megőriztük.
A mypy projektkonfiguráció hash-e is változatlan; az ellenőrzések javításával
szűntek meg a hibák, nem az ellenőrzés kikapcsolásával.
[Megőrzési bizonyíték](measurements/browser-token-preservation.json).

A takarítás **491 generált/cache/tesztadat-fájlt, 83 756 485 logikai byte-ot**
mozgatott külön privát macOS Trash-könyvtárba, visszaállíthatóan. Production
vagy aktív tesztforrás nem törlődött. A saját `redjohn-e2e` VM-et, profilját és
külön adatalemezét eltávolítottuk; mindhárom hiányát ellenőriztük. A managed
engine/dependency-k, a meglévő viewer static bundle, a két korábbi elfogadott
demo-run és minden átadott mérés megmaradt.
[Pontos takarítási lista](measurements/browser-token-cleanup.json).

A skillek angolok maradtak, a két érintett assessment contract az új kontrollált
browser/body-token képességet is leírja, miközben az általános login/MFA út
továbbra is külön hiányzó képesség. Mind a 47 tartalomhash helyes, az eredeti
forrásprovenance megmaradt. Firecrawl nem került be, külső platform nem váltotta
fel a RedJohnt.

[A jelen folytatás fájljai és SHA-256-jai](redjohn-browser-token-changed-files.json),
[összesített fájlindex](redjohn-changed-files.md),
[összesített manifest](redjohn-changed-files.json).
