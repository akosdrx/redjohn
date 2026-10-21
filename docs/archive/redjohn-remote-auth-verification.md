# RedJohn — távoli HTTPS-egress és autentikált Nuclei-replay igazolása

Történeti GET/HEAD remote/auth baseline. A lenti számok és snapshot változatlanok;
a későbbi POST/body/session-refresh bővítés [külön jegyzőkönyvben](redjohn-post-refresh-verification.md) szerepel.

Ellenőrzés: **2026-10-17**. A Linuxon futó valódi Chromium → observed inventory →
tartós scheduler → autentikált Nuclei → explicit javított kontroll lánc sikeres.
A RedJohn név, a meglévő Nuclei-integráció és a felhasználói módosítások megmaradtak.
A teljes master prompt elfogadása továbbra is részleges; az alábbi bizonyíték a
pontosan leírt read-only HTTP(S) subsetre vonatkozik.

## Tényleges környezet és mérési határ

| Elem | Ellenőrzött érték |
|---|---|
| Futtatás | `redjohn-e2e` saját Ubuntu Linux ARM64 VM |
| Kernel/platform | Linux `6.8.0-117-generic`, aarch64, glibc 2.39 |
| Python | 3.12.3 |
| Playwright / Chromium | 1.58.0 / 145.0.7632.0 |
| Nuclei | valódi 3.11.1, Linux ARM64 executable |
| Engine SHA-256 | `f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477` |
| Bundle SHA-256 | `be5818f06aae0dea08c6891aba662c93988a335373b53c28273ebf21d6b17cbe` |
| Cél | a teszt saját HTTPS-szervere: `https://192.168.5.1:43715` |

A cél valódi, **nem loopback** lokális interfészcímen figyelt, saját ideiglenes
CA-val és eldobható credentiallel. Nem történt idegen publikus cél pentestje.
Az új futás Linux-környezet; a korábbi macOS loopback-adatokat történeti baseline-
ként kell kezelni. A két platform Chromium-buildje és Nuclei-hash-e eltérhet.

## Valódi E2E eredmények

Elsődleges bizonyíték a végső teljes Linux-suite-ból:
[nyers mérési JSON](measurements/remote-auth-linux/remote-auth-e2e.json).
Ez a tényleges stage-eket, céloldali kéréseket, actorokat, státuszokat, namespace-
attesztációkat, tartós request budgetet és erőforrássnapshotokat is tartalmazza.

| Mérés | Eredmény |
|---|---|
| Teljes mért lánc a végső Linux-suite-ban | **4,178810 s** |
| Tényleges céloldali HTTPS-kérés | **6** |
| Tartós SQLite request-terhelés | **6**, a valódi kérésekkel egyezően |
| Kezdeti marker | **1 candidate**, nem confirmed sérülékenység |
| Javított, autentikált kontroll | **0 új finding**, teljes 200-válasz, `no_finding_observed=true` |
| Újranyitás utáni duplikált hálózati kérés | **0** |
| Hibás identity/expiry/capture kontrollok | **8 eset, 0 céloldali I/O** |
| Controller / külön scanner-CLI PID | **6886 / 9271** |
| Mintázott process-tree RSS maximum | **802 283 520 B = 765,12 MiB** |
| Belső LLM-hívás / input-output token | **0 / 0** |

A memóriaérték az egyes controller/CLI stage-ekben megfigyelt összegzett process-
tree RSS maximuma; osztott lapokat többször számolhat. Nem PSS, nem folyamatos
csúcsmérés és nem általános hard RAM-limit. Az admission a process-tree RSS és a
saját cgroup `memory.current - inactive_file` maximumát használja; a nyers current/
inactive-file adatok megmaradnak a JSON-ban. Hiányzó `memory.stat` esetén nincs
feltételezett levonás, a rendszer gyökér-cgroupja pedig nem saját jobmérés.

Külön korábbi ismételt mérés: [önálló E2E JSON](measurements/remote-authenticated-live.json),
1 passed / 5,84 s pytest, 4,284528 s lánc, 740,74 MiB mintázott RSS-maximum,
controller/CLI 6558/6699. Ez külön futás; a végső suite adatait nem kevertük vele.

### A hat céloldali kérés és a kontrollok

| Stage | Céloldali kérés | Következtetés |
|---|---:|---|
| Autentikált Chromium SPA/inventory | 2, mindkettő `alice` | `/` és `/private` ténylegesen megfigyelt; a surface `observed` |
| Named actor Nuclei, külön CLI-processz | 1, `alice`, 200 | reviewed marker matched; 1 candidate |
| Anonymous kontroll | 1, 401 | `blocked/authentication_expired`; nem negatív scan |
| SQLite újranyitás / azonos job | 0 | ugyanaz az idempotenciakulcs nem indult újra |
| Explicit új retestrevision, javított szerver | 1, `alice`, 200 | marker nincs, teljes kontroll; nincs új finding |
| Eltérő session/tenant/actor | 0 összesen | identity/request mismatch miatt blokkolt |
| Lejárt credential | 0 | `auth_replay_expired` |
| Manipulált capture-identity, `sent=false`, hiányzó `sent`, eltérő capture-policy | 0 összesen | capture mismatch miatt blokkolt |
| Redirect kontroll | 1, `alice`, 302 | `inconclusive/response_status_unverified`; a credential-trap nem kapott kérést |

A browser stage **succeeded/partial** maradt: Chromium Google-háttérkapcsolati
próbái out-of-scope elutasítást kaptak. A proxy öt scope-elutasítást rögzített;
ez nem öt céloldali kérés és nem öt budgetterhelés. A saját két HTTPS-kérés
sikeres volt, TLS-failure és wire-limit drop nélkül. A partial státuszt nem
alakítottuk completed állapottá a szebb összesítés kedvéért. WebSocket, service
worker, általános módosító workflow és response-body capture eleve külön korlát.

## Mi kényszeríti ki a határokat?

- Linux user/network/mount/PID namespace, kizárólag `lo` interfész,
  effective-capability `0` és `NoNewPrivs`; tényleges `/proc` és `SO_PEERCRED`
  attesztáció a worker indulása előtt.
- Privát Unix relay kizárólag a kiválasztott controller-proxyhoz. A nem attesztált
  host-peer elutasított; a workernek nincs közvetlen IPv4/IPv6/UDP/raw-socket útja.
- Pontos HTTPS-origin és IP/CIDR allowlist, a DNS-válaszok ellenőrzése és numerikus
  connectpin az eredeti hostname/SNI megtartásával. Szigorú upstream CA-/hostname-
  validáció; nincs globális TLS-kikapcsolás vagy rendszer-truststore módosítás.
- Kérésenkénti policy/read-only/request-budget és közös tartós rate/cooldown
  admission. Az opcionális motorok sorosan indulnak a meglévő schedulerből.
- Host-only credential binding az observed URL/metódus/request-ref és pontos
  actor/tenant/session-/policyrevision/expiry alapján. A secret nem jobopció,
  scanner-argv vagy template; a target által visszatükrözött ismert érték raw
  evidence előtt is redaktálódik. Nincs anonymous fallback vagy redirect-replay.

A [namespace tesztfájl](../tests/test_assessment_egress.py) külön futása
**6 passed / 0,39 s** volt ([stdout](measurements/remote-auth-linux/namespace-final-tests.txt),
[JUnit](measurements/remote-auth-linux/namespace-final.junit.xml)):
**3 tényleges Linux kernel/processz kontroll és 3 mockolt
platform/dependency/kontraktus unit-teszt**. Ezek nem „6 valódi integráció”. A három
Linux eset a közvetlen hálózati bypassokat és az attesztált proxyt, a boundary-close
saját workerének leállítását, valamint egy worker cancelje mellett a másik worker
megőrzését és a `finally` cleanupot ellenőrzi. Ez külön komponensbizonyíték a fenti
teljes browser–inventory–Nuclei lánctól.

## Indítás és reprodukció

A parancsok a repository gyökeréből, előkészített **Linux** Python-környezetből
futnak. Opcionális eszköz telepítése explicit lépés; a teszt és a scheduler nem
telepít automatikusan motort vagy upstream template-készletet.

```bash
.venv/bin/python -m pip install pytest==9.1.1 pytest-asyncio==1.4.0 \
  PyYAML==6.0.3 httpx==0.28.1 cryptography==48.0.1 playwright==1.58.0 \
  openai-agents==0.19.4 openai==2.54.0 pydantic-settings==2.16.0 \
  rich==15.0.0 requests==2.34.2 Jinja2==3.1.6
.venv/bin/python -m playwright install --with-deps chromium
.venv/bin/python scripts/install-nuclei-pinned.py
.venv/bin/python scripts/create-nuclei-fixture-lock.py

PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_assessment_egress.py -q -s

REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_REMOTE_E2E_MEASUREMENTS=/tmp/redjohn-remote-auth-e2e.json \
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_remote_authenticated_pipeline.py -q -s

PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_nuclei_auth_live.py \
  tests/test_assessment_auth_replay.py -q -s
```

A `bubblewrap` és `iproute2`, valamint a Linux unprivileged namespace-támogatás
előfeltétel. `REDJOHN_REQUIRE_REMOTE_E2E=1` hiányzó Linux/bwrap/Chromium/Nuclei esetén
failt ad, nem skipped capabilityt. Dedikált systemd scope választja el a mérés
cgroupját más build/download munkáktól; a scope önmagában nem jelent hard RAM-limitet.

A végső teljes Linux-suite tényleges indítása a VM-ben:

```bash
sudo systemd-run --unit=redjohn-final-tests --wait --pipe --collect \
  --property=User=akosdrx --property=Group=akosdrx \
  --property=WorkingDirectory=/home/akosdrx.guest/redjohn-e2e \
  /usr/bin/env PYTHONPATH=. REDJOHN_REQUIRE_REMOTE_E2E=1 \
  REDJOHN_REMOTE_E2E_MEASUREMENTS=artifacts/remote-auth-e2e.json \
  .venv/bin/python -m pytest tests -q -s \
  --junitxml=artifacts/redjohn-tests.junit.xml
```

A konfigurált tartós futás parancsa továbbra is:

```bash
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /private/approved-redjohn-config.json \
  --output redjohn_runs/approved-remote --max-jobs 16
```

A remote policy `egress_mode="enforced"`, pontos HTTPS `allowed_origins` és
`allowed_ips`; a `tls.upstream_ca_file` opcionális saját CA. Nucleihoz külön
engine-/bundle-lock, named actorhoz explicit `auth_vault_file` kell. A vault aktuális
tulajdonú `0600` regular file; nem Git-adat vagy riport. Az imported seed önmagában
nem autentikált capture. A programozott browser discoveryhez a host matching
`actor_states`-ot is átad; a CLI nem ad általános login-/credential-refresh wizardot.
A részletes séma, konfiguráció és hibakódok: [remote/auth](remote-egress-auth.md),
[runbook](redjohn-runbook.md), [Nuclei-integráció](nuclei-integration.md).

## Angol skillek és további tesztek

Mind a **47 assessment kontraktus angol**, az eredeti 12 angol core skill és a
külső felhasználói csomag megmaradt. A forrás-SHA, fordításbemenet-SHA és aktuális
angol tartalom-SHA külön mező. A natív registry/provenance tesztek: **10 passed**,
47/47 angol tartalomhash egyezik, magyar ékezetet tartalmazó skillfájl: 0.
[Gépi validáció](measurements/english-skill-validation.json).

A generikus Codex `quick_validate.py` mind a 47 skillnél a RedJohn `version/status`
frontmatter-mezőit utasítja el. Ez sémakülönbség, nem sikeres Codex-validator futás;
a termékmezőket megtartottuk, nem migráltuk a runtime-kontraktust egy másik schema
kedvéért. A natív validáció és a tényleges capability-eligibility a mérvadó.

| Végső ellenőrzés | Eredmény | Bizonyíték és határ |
|---|---|---|
| Teljes Linux Python-suite | **276 passed, 1 skipped, 66,02 s** | [stdout](measurements/remote-auth-linux/redjohn-tests.txt), [JUnit](measurements/remote-auth-linux/redjohn-tests.junit.xml); minden Chromium-, valódi engine-, remote- és kernelteszt lefutott |
| Teljes macOS Python-suite | **273 passed, 4 skipped, 68,72 s** | [stdout](measurements/remote-auth-macos-tests.txt), [JUnit](measurements/remote-auth-macos.junit.xml); a négy Linux-képességteszt explicit skip |
| Go TUI | **4 package sikeres ellenőrzése, nincs Go-tesztfájl** | A `go test ./...` build/import ellenőrzés, nem négy unit-teszt |
| Viewer build | **2260 modul, 2,71 s** | Sikeres production build; chunkméret-warning megmaradt |
| Célzott strict mypy | **10 source fájl sikeres** | Projektkönyvtárból futtatott célzott típusellenőrzés; nem teljes repository-mypy állítás |

A Linux egyetlen skipje a `test_user_supplied_sources_match_recorded_hashes`:
a külső, repositoryn kívüli felhasználói forráscsomagot nem másoltuk a VM-be.
Ugyanez macOS-en sikeres, így az eredeti 35 forrás-SHA ellenőrzése megtörtént.
Ez nem engine-, Chromium- vagy remote-integrációs hiány. A macOS négy skipje a
három valódi Linux namespace/processzteszt és a teljes remote-chain teszt;
hiányzó platformot jelentenek, nem negatív sérülékenységvizsgálatot.

A mock engine, mock installer/download és platformmock unit-tesztek külön
kategóriák; egyik sem helyettesíti az itt rögzített valódi engine-/Chromium-/
namespace-mérést. A Go-tesztek hiánya és a viewer warning nem lett tesztsikerré
vagy eltitkolt hibává átnevezve.

## Megmaradt korlátok és átadás

- Remote browser/scanner támogatás Linuxhoz kötött. macOS/Windows remote jobhoz
  nincs namespace-fallback; a capability blocked, nem negatív vizsgálat.
- Általános POST/body/JSON/XML/multipart auth-replay, OAST, raw/workflow/headless
  Nuclei template és több specialist adapter továbbra sincs ebben a subsetben.
- Automatikus session refresh, teljes legacy agent/shell policy-migráció,
  hostglobális több-adatbázisos governor, hard RAM/cgroup-limit, release/Kali
  csomagteszt és teljes master-prompt elfogadás külön nyitott tételek.
- A saját marker nem valós CVE/RCE-bizonyítás. Az eredeti RCE hiányzó kontrollja
  továbbra is `not_reproduced_missing_fixture`.
- A helyes GitHub repository **`akosdrx/redjohn`**. A workflow előkészítve, de a
  hozzá szükséges GitHub-auth hiányzik: nincs erre a repositoryra CI-build állítás.
  A korábban téves repositoryban létrejött branch és workflow-runs törölve lettek;
  ez nem állítás a GitHub elérhetetlenné vált Git-objektumainak fizikai törléséről.

A takarítás **548 generált/cache/debug fájlt, 149 359 839 bájtot** mozgatott
visszaállíthatóan a Kukába, 103 repositorybeli célpontból. Ez nem felszabadított
lemezterület-mérés. Aktív tesztet és funkcionális forráskódot nem töröltünk;
biztosan elavult funkcionális kódot nem azonosítottunk. A saját teszt-VM, annak
profilja és generált adatlemeze leállítás után törölve lett; host könyvtárat és
SSH-agentet nem osztottunk meg vele. Az elfogadott futások és mérések megmaradtak.
[Tényleges takarítási lista](measurements/remote-auth-cleanup.json).

[Aktuális módosított fájlok és SHA-256](redjohn-remote-auth-changed-files.json),
[összesített implementációs fájllista](redjohn-changed-files.md),
[273 átadott Linux-forrás egyezősége és runtime-verziók](measurements/remote-auth-linux/source-and-runtime-verification.json).
A Git HEAD és az index megmaradt; a master prompt tartalma változatlan.
