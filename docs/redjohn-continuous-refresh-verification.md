# RedJohn: refresh után folyamatos Chromium-capture és Nuclei-replay

Történeti baseline. Az automatikus 401/lejárat-felismerés és a tartósan
korlátozott helyreállítás új igazolása az
[auth-recovery jegyzőkönyv](redjohn-auth-recovery-verification.md).

Ellenőrzés: 2026-10-17, `/Users/akosdrx/Documents/rjkali`.
Az alábbi eredmények a ténylegesen módosított és hash szerint ellenőrzött
forrásra vonatkoznak. A korábbi browser-token és POST/refresh jegyzőkönyvek
történeti baseline-ok; a régi számaikat nem írtuk át.

## Implementált működés

- Az explicit `continuous_replay` konfiguráció pontos actor/tenant/POST URL/
  media type/template-ID kötést ad. Csak a meglévő lockban reviewzott,
  megfelelő profilú `authenticated-replay` template választható.
- A sikeres refresh ugyanabban az SQLite-tranzakcióban kap tartós folytatási
  eseményt, mint amelyben a szülőjob lezárul. A futó scheduler a friss revízió
  alapján nem idempotens Chromium-capture-t sorol be; újraindítás nem szükséges.
- A tényleges új capture után a kijelölt Nuclei-replay automatikusan indul.
  Minden kiválasztott kéréshez aktuális session, pontos szülő-identity,
  observed POST, megfelelő body-hash/Content-Type/reference, teljes 2xx
  sent-evidence, élő privát szabály és újraolvasott vault-jóváhagyás kell.
- A gyermekjobok beküldése és az esemény nyugtázása atomi. Queue-hiba után az
  esemény megmarad, a sikeres módosító szülő nem válik retryvá. Régi jobot,
  capture-t, template-verziót és bizonyítékot nem címkéz át az új sessionre.
- A `max_jobs` minden végrehajtott lépést számol. A végső slot után is
  tartósan sorba kerülhet a gyermek; a limit miatt nem indul plusz worker.
- A scheduler nem-browser feladat előtt lezárja az idle browser-workert és
  felszabadítja a lease-ét. A teljes lánc `max_workers=1` mellett is működik.
  Propagált lezárási hiba esetén `browser_idle_cleanup_failed` blokkolás
  előzi meg a scanner indítását.
- Hiányzó várt POST esetén `continuous_replay_capture_missing` jelzi a
  blokkolást. Bizonytalan refresh vagy nem igazolt/hiányos POST nem ad replayt.
  A CLI a folytatási hibákat külön riportolja és nem nulla exitet ad.
- A korábbi startup-capture és kézi scanner-job mód konfigurációs
  kompatibilitása megmaradt. A teljes automatikus lánchoz az új explicit mapping
  szükséges; nem választunk automatikusan új template-eket.

## Valódi E2E és mért eredmény

Az új `test_continuous_refresh_pipeline.py` egyetlen futó `AssessmentRuntime`
és scheduler mellett, azonos controller PID-del hajtja végre a 7 → 8 refresh-t,
az új browser-capture-t és három Nuclei-replayt. A refresh után nincs kézi
gyermekjob-beküldés, új CLI vagy új runtime. A worker Chromium folyamatának
lezárása és szükség szerinti újbóli indítása az erőforrás-életciklus része;
nem állítunk azonos Chromium OS-folyamatot minden fázisra.

Saját, nem loopback HTTPS-fixture (`192.168.5.1`), szigorú upstream TLS és
valódi Linux namespace-attesztáció védi a browser/scanner útvonalat. Verziók:
Playwright **1.58.0**, Chromium **145.0.7632.0**, Nuclei **3.11.1**,
bubblewrap **0.9.0**, Ubuntu/Linux ARM64, Python **3.12.3**.
A Nuclei bináris SHA-256:
`f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477`.
MIT, upstream commit `a8c88feb4a1c8e961b7902534ce3af97e9d524a4`;
a három saját ártalmatlan template külön content-pinned bundle.

| Mérési pont | Tényleges eredmény |
|---|---|
| Munkafolyamat időtartama | **7,025025 s** |
| Refresh utáni egy batch | **5 job**: refresh + capture + 3 replay |
| Teljes E2E végrehajtott job | **12** |
| HTTPS-kérés / tartós request charge | **18 / 18** |
| Forgalom | 2 GET + 6 Chromium POST-capture + 9 Nuclei POST + 1 refresh POST |
| Bodyformátum | JSON, URL-encoded form, multipart bináris uploaddal |
| Session és body-tokenek | Valódi **7 → 8**, mindhárom formátumban friss érték |
| Pozitív kontroll | **6 candidate**, külön capture és replay mindkét revízióban |
| Javított kontroll | **3 ténylegesen végrehajtott ellenőrzés, 0 új finding** |
| Ismételt batch / későbbi újranyitás | **0 duplikált kérés** |
| Scope-on kívüli credential-trap | **0 kérés** |
| Modellhívás | **0** |
| Beállított workerlimit / mintavételezett aktív worker-lease maximum | **1 / 1** |
| Browser–scanner lease átfedés | **0 mintában**; 92 browser- és 186 scanner-minta |
| Mintavételezett processfa-RSS maximum | **1 065 590 784 byte = 1016,23 MiB** |
| Memóriamérés | 280 minta, 25 ms célköz, legnagyobb tényleges köz **37,07 ms**, max. 17 folyamat |

A RSS a tesztcontroller és tényleges leszármazottai összege; megosztott lapokat
többször számolhat, és a mintavétel nem abszolút maximum vagy hard OS-limit.
A worker-lease egy logikai erőforrásfoglalás, nem egyetlen Chromium OS-processz.
A systemd service memóriaadata más mérési határ, ezért nem használjuk a teljes
workerfogyasztás helyettesítésére. A régi 17-CLI workload eltérő munkát mért;
nincs százalékos gyorsulási vagy memóriajavulási állítás.

Az első capture-re szánt egyetlen slot után három scanner-jobot független
SQLite-handle is lát: a sorba állított munka tartós. A tényleges refresh utáni
öt lépés egyetlen `run_batch(max_jobs=5)` hívásban fut végig. A privát v2
vaultban az új byteok/hash-ek/refek szerepelnek, a multipart boundary változása
mellett ugyanaz a reviewzott bundle marad érvényes. A titkok nem szerepelnek a
publikus mérési JSON-ban vagy az evidence/workspace fájlokban.

Mindkét browser-job aggregate coverage-e **partial** maradt: egy
scope-on kívüli háttérkapcsolatot a proxy blokkolt (`browser_scope_denied`).
Ez a hiány megmarad a riportban. Az egyes kiválasztott POST-ok teljes 2xx
transportbizonyítéka külön ellenőrzött; csak ezek replayje folytatódott.
Nem nevezzük a teljes böngészős felderítést completednek.

Nyers bizonyíték: [teljes E2E-mérés](measurements/continuous-refresh-linux/continuous-refresh-e2e.json),
[külön egyworker-es futás](measurements/continuous-refresh-linux/continuous-focused-e2e.json),
[runtime](measurements/continuous-refresh-linux/runtime.json),
[valódi engine-receipt](measurements/continuous-refresh-linux/nuclei-install.json).

## Tesztmátrix és mockhatár

| Ellenőrzés | Végleges eredmény |
|---|---|
| Teljes Linux Python-csomag | **541 passed / 1 skipped**, 542 eset, **149,96 s**, 0 failure/error |
| Teljes macOS Python-csomag | **535 passed / 7 skipped**, 542 eset, **107,44 s**, 0 failure/error |
| Új tesztesetek | **63**, a korábbi 479 eset megmaradt |
| Strict mypy, változatlan projektkonfiguráció | **22 forrásfájl hibamentes** |
| Ruff + formatter | **84 fájl**, sikeres |
| Python AST / angol natív contract-hash | **235 fájl / 47 assessment skill**, sikeres |
| Viewer build | **2260 modul, 2,63 s**, saját temp-output; meglévő bundle megmaradt |
| Go TUI | `go test ./...` sikeres, **4 package tesztfájl nélkül**, fordítási ellenőrzés |

Az új 38 workflow-kontraktusteszt szintetikus inventory/evidence/vault adatot
használ. A 20 outbox-teszt valódi SQLite-tranzakciókat és governor-lease-eket,
de fake workereket használ. A négy CLI-status teszt mockolt futás eredményét
ellenőrzi. Ezek nem live integrációs állítások. Az egy új teljes E2E valódi
Chromiumot, HTTPS-t, refresh providert és Nuclei binárist használ.
A régi valós browser/POST/body-token/refresh/restart E2E-k is újrafutottak.

Linuxon kizárólag a repositoryn kívüli eredeti felhasználói skillpack
forráshash-tesztje maradt ki, mert a forrást nem másoltuk a VM-be. A fordított
47 natív contract hash-e ott is helyes; az eredeti source-ellenőrzés macOS-en
lefutott. A hét macOS-kihagyás három Linux-kernel-izolációs és négy remote E2E
teszt; ugyanazok Linuxon ténylegesen lefutottak.

A teljes Linux stdoutban a mock installer teszt szándékosan 35 byte-os
Darwin-fixture adatokat is kiír. Ez nem a használt engine: a valódi telepítés
külön receiptje és az E2E engine-hash-e a fenti Linux binárist igazolja.

Eredmények: [Linux JUnit](measurements/continuous-refresh-linux/continuous-refresh-full.junit.xml),
[Linux stdout](measurements/continuous-refresh-linux/continuous-refresh-full.txt),
[macOS JUnit](measurements/continuous-refresh-macos.junit.xml),
[macOS stdout](measurements/continuous-refresh-macos-tests.txt),
[mypy](measurements/continuous-refresh-mypy.txt),
[Ruff](measurements/continuous-refresh-ruff.txt),
[Viewer build](measurements/continuous-refresh-viewer-build.txt),
[Go](measurements/continuous-refresh-go-tests.txt),
[összesített gépi eredmény](measurements/continuous-refresh-verification-summary.json).

## Indítás és reprodukció

Konfigurációs fragmentek, privát szabályok, seed és recovery:
[continuous workflow](../RedJohn/docs/continuous-refresh-replay.md).
A már reviewzott konfigurációból, repositorygyökérben:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/assessment.json \
  --output /absolute/private/assessment-output --max-jobs 16
```

A ténylegesen használt teszt- és buildparancsok lényegi részei:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest RedJohn/tests -q \
  --basetemp=/tmp/redjohn-continuous-macos-tests \
  --junitxml=docs/measurements/continuous-refresh-macos.junit.xml

# Linux, előkészített namespace/Chromium/pinned-Nuclei környezetben:
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_CONTINUOUS_REFRESH_MEASUREMENTS=/tmp/continuous-refresh-e2e.json \
PYTHONPATH=RedJohn .venv/bin/python -m pytest RedJohn/tests -q -s

REDJOHN_REQUIRE_REMOTE_E2E=1 PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_continuous_refresh_pipeline.py -q -s

.venv/bin/ruff check RedJohn/redjohn/assessment \
  RedJohn/redjohn/tools/hunt/nuclei.py RedJohn/tests
.venv/bin/ruff format --check RedJohn/redjohn/assessment \
  RedJohn/redjohn/tools/hunt/nuclei.py RedJohn/tests

(cd RedJohn && ../.venv/bin/mypy \
  redjohn/assessment/{auth_replay,request_body,session_refresh,capture,models,policy,browser_proxy,adapters,store,runtime,scheduler,registry,native_session,contracts,browser,browser_capture,browser_workflow,body_tokens,browser_tls,egress,_egress_worker}.py \
  redjohn/tools/hunt/nuclei.py)
(cd RedJohn/redjohn/interface/tui && go test ./...)
(cd RedJohn/redjohn/interface/viewer/frontend && \
  npm run build -- --outDir /tmp/redjohn-continuous-viewer-build)
```

A Linux-futás dedikált helyi, mount és SSH-agent-forward nélküli VM-ben,
saját systemd service-ből indult; a hoston futó forrással mind a **300**
engedélyezetten átmásolt fájl SHA-256-ja egyezett.
[Forrásmanifest](measurements/continuous-refresh-linux-source-files.json),
[ellenőrzés](measurements/continuous-refresh-linux-source-verification.json).
A GitHub workflow kapott mérési változót; GitHub Actions-futtatást nem állítunk.

## Megőrzés, takarítás és nyitott képességek

Mind a **231** kiinduló Python forrás/teszt/script megmaradt; kizárólag hét
implementációs Python-fájl változott. Mind a **43** eredeti aktív teszt- és
segédfájl byte szerint azonos; négy új aktív tesztfájl került melléjük.
A master prompt, Git HEAD és index változatlan. RedJohn név, meglévő checkout,
integrációk és az `akosdrx/redjohn` origin megmaradt; nem történt reset/clean,
commit vagy push. A skillek továbbra is angolok, az új workflow-leírások is
angolul kerültek a natív contractokba, friss tartalomhash-sel.
[Megőrzési bizonyíték](measurements/continuous-refresh-preservation.json).

Csak saját generált tesztadatok, cache-ek és temp build/archívum fájlok kerültek
visszaállítható privát Trash-ba; a managed függőségek és korábbi elfogadott
runok megmaradtak. A saját ellenőrző VM külön törlési igazolást kapott.
[Takarítás](measurements/continuous-refresh-cleanup.json).
Módosított fájlok: [aktuális manifest](redjohn-continuous-changed-files.json),
[összesített lista](redjohn-changed-files.md).

Blokkolt/hiányzó képesség külön marad a negatív kontrolltól: Linux-kernelhatár
nélkül remote futás nem indul; hiányzó/lejárt privát approval vagy nem reviewzott
template nem ad replayt; bizonytalan mutáló kimenetel kézi reconciliationt kíván.
Teljes login/MFA/password-reset, a provider saját refresh-tokenjének rotációja,
heurisztikus body-token-keresés, XML/raw/nested multipart és az eredeti RCE
fixture továbbra sincs igazolva/implementálva. Az eredeti RCE státusza
`not_reproduced_missing_fixture`; a marker candidate nem RCE-bizonyíték.
Az összes specialist adapter, hosszú soak, Kali release és teljes master
elfogadás nem válik ettől késznek. A Viewer nagy chunk figyelmeztetése megmaradt.
