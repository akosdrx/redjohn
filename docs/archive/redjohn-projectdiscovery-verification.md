# RedJohn: httpx, Katana és VulnX ellenőrzés

2026-10-18, a meglévő `akosdrx/redjohn` checkouton. A RedJohn neve,
módosításai, régi eszközei, Nuclei-integrációja és MCP-támogatása megmaradt.
Ez a master prompt újabb részfeladatának implementációja; nem a teljes master
prompt vagy egy éles pentest lezárása.

## Implementáció és indítás

Az új `httpx_probe`, `katana_discover` és `vulnx_intelligence` a meglévő
SQLite-scheduler jobjai. Indításuk explicit konfigurációhoz és kiválasztott
jobhoz kötött. A health/planner nem indít opcionális folyamatokat. A munkák
sorosak; a scanner előtt az idle Chromium lezárul. A policy-, profil-, IP/DNS-,
kéréskeret-, cooldown-, timeout-, cancellation- és outputkorlátokat kód hajtja
végre. Távoli worker csak attesztált Linux namespace-ből futhat.

Fő fájlok:

| Fájl | Változás |
|---|---|
| `redjohn/assessment/discovery_tools.py` | Valódi httpx és standard Katana; typed argv, readonly GET, proxy-megfigyeléssel egyeztetett inventory, technológiai fejlécek, URI-hűség |
| `redjohn/assessment/vulnx.py` | Egyetlen CVE-ID intelligence adapter; külön provider-scope és CA-bizalmi kör, hostoldali API-key, tartós TTL-cache, explicit retest |
| `redjohn/assessment/pinned_tools.py` | Digest/verzióellenőrzés, bounded supervisor, privát HOME, minimális környezet, processzcsoport/namespace cleanup |
| `assessment/{runtime,registry,scheduler,cli}.py` | Opt-in konfiguráció, capability/jobverziók, fair tervezés, tartós végrehajtás, egyértelmű blocked/unsupported státuszok |
| `assessment/browser_proxy.py` | Korlátozott szolgáltatói gateway, canonical HTTPS alapján ellenőrzött upstream TLS, üres query megőrzése, külön számlált blokkolt proxy-próba |
| `tools/hunt/bounded_worker.py` | Szűk Go/kliens-CA környezetséma; a korábbi Nuclei/ffuf útvonal megőrizve |
| `scripts/install-projectdiscovery-pinned.py`, `projectdiscovery-pins.json` | Explicit hivatalos letöltés, archive/checksum/license SHA-k, meglévő telepítés felülírásának tiltása |
| `tests/test_projectdiscovery_{contract,live}.py` | 51 kontraktus és 41 integrációs/gate teszteset |

A teljes, SHA-s fájllista: [módosításjegyzék](redjohn-projectdiscovery-changed-files.json).
A konfiguráció, minden korlát és upstream forráshivatkozás az
[angol runbookban](projectdiscovery-adapters.md) található.

```sh
# Repository root; a már meglévő, ellenőrzött telepítést nem kell újratelepíteni.
.venv/bin/python scripts/install-projectdiscovery-pinned.py httpx
.venv/bin/python scripts/install-projectdiscovery-pinned.py katana
.venv/bin/python scripts/install-projectdiscovery-pinned.py vulnx
PYTHONPATH=. .venv/bin/python -m redjohn.assessment health

# A példában a scope/IP/path/SHA helykitöltőket előbb operátori értékekre kell cserélni.
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/path/to/operator-config.json \
  --output /absolute/path/to/assessment --max-jobs 16
```

Példa: [assessment-projectdiscovery.json](../examples/assessment-projectdiscovery.json).
Az alapértelmezett seed-capability lista nem bővült automatikus toolindítással.
A VulnX csak előre engedélyezett nyilvános CVE-azonosítókat kap, privát assetlistát nem.

## Verzió, licenc és valódi motor

| Tool | Verzió | Ellenőrzött commit | CLI-licenc |
|---|---|---|---|
| ProjectDiscovery httpx, nem a Python-kliens | 1.12.0 | `4b6a9a9d476f94a4f3a630f37051f5671ecfb1f8` | MIT |
| Katana, standard mód | 1.8.0 | `35267ac5c8ff1db9694a319d0eb466ed97b0969f` | MIT |
| VulnX | 2.0.2 | `76410ddde266b7103673813e14a79dbad13b4beb` | MIT |

A licencek SHA-ja és a négy platform archive-pinje a pins JSON-ban szerepel.
Ténylegesen macOS ARM64 és Linux ARM64 binárisok futottak. Az AMD64 pinek nem
jelentenek AMD64 E2E-t. Opcionális fingerprint-adatbázisok és cloud-adatok
feltételei különállók; nincs upstream PoC/template-forrás átvéve vagy futtatva.
Strix/HexStrike-forrás és Firecrawl nem került be. Második CVEMap motor sincs.

A valódi Linux binárisok mérete: httpx **51 970 210 B**, Katana **65 208 482 B**,
VulnX **28 967 096 B**, a meglévő Nuclei **131 858 594 B**.
A [Linux](measurements/projectdiscovery/linux/binary-integrity.json) és
[macOS](measurements/projectdiscovery/macos/binary-integrity.json) SHA-bizonylatok
a tényleges telepített fájlokat ellenőrzik; mellettük a hivatalos installer-receiptek.

## Lefuttatott ellenőrzések

| Ellenőrzés | Eredmény |
|---|---|
| Teljes macOS Python-regresszió | **778 passed, 18 skipped**, 247,09 s |
| Teljes Linux Python-regresszió | **796 passed, 0 skipped**, 342,11 s |
| Új kontraktusteszt-modul | **51 passed**, mindkét platformon; nincs külső CLI-futtatás |
| Új live/gate modul | Linux **41 passed**; macOS **38 passed, 3 kernelhez kötött skip** |
| Strict mypy | **0 hiba, 191 forrásmodul**, macOS és Linux; beállításgyengítés nélkül |
| Ruff, 12 érintett Python-fájl formátuma | Rendben; teljes source/scripts/tests lint rendben |
| Viewer production build | **2261 modul, 2,60 s**; a buildelt assetek SHA szerint azonosak a meglévőkkel |
| TypeScript no-emit + unused ellenőrzés | Rendben |
| Go TUI | 4 csomag fordítható, `go test ./...` és `go vet ./...` rendben; nincs külön Go-unit tesztfájl |

A 18 macOS-skip **mindegyikének azonos tesztje sikeresen lefutott Linuxon**:
[tesztösszesítő és pontos skip-okok](measurements/projectdiscovery/test-summary.json).
A Linux környezet saját, mount és SSH-agent nélküli Ubuntu 24.04 ARM64 VM,
kernel `6.8.0-117-generic`, 2 CPU / 4 GiB RAM. GitHub CI konfigurálva van,
de GitHubon futtatott buildet, Kali-csomagot és hosszú soak-tesztet nem állítunk.

A teljes regresszió unit/mock teszteket is tartalmaz. Különösen a logban látható
**35 bájtos, Darwinra állított mock Nuclei installer-receipt nem valódi motor**.
A valódi motorok igazolása a külön integrációs modul, a managed bináris SHA-ja,
a tényleges HTTPS-kérés és a marker/fixed kontroll. A kontrollált VulnX API
valódi CLI-t és HTTPS-t használ, de szintetikus adatforrás; a publikus API-próba
ettől külön teszteset és külön mérési fájl.

## Valódi E2E és mérések

Minden lánc: Chromium → httpx → Katana → VulnX fixture → meglévő Nuclei →
javított kontroll. A store és runtime minden szakasz között újranyílik.
Mindhárom esetben **10 HTTPS-kérés, 0 ismételt kérés resume után, 0 modellhívás**.
A Nuclei marker **1 candidate**, a javított kontroll **0 candidate**. Ez nem az
eredeti, hiányzó RCE-fixture reprodukciója és nem confirmed impact.

| Környezet | Teljes lánc | Legnagyobb mintavételezett process-tree RSS |
|---|---:|---:|
| macOS loopback HTTPS | **10,315 s** | **475,48 MiB** |
| Linux loopback HTTPS | **9,580 s** | **560,36 MiB** |
| Linux nem-loopback HTTPS, namespace | **10,463 s** | **805,13 MiB** |

Ezek tényleges governor-minták; nem folyamatos csúcsmérés, nem egyetlen scanner
RAM-ja és nem OS hard limit. Az összegzett RSS közös lapokat többször számolhat.
Új adapter előtti mérési baseline nem volt (`baseline_unavailable`), gyorsulási
százalék nincs állítva. A rövid fixture-próbák nem terhelési benchmarkok.

A távoli láncban a browser **partial** maradt a tiltott Chromium háttérkérések
miatt (`browser_scope_denied`), miközben readiness/oldalbetöltés teljesült.
A három új adapter és a két Nuclei-job **completed**. Az engedélylistát nem
bővítettük a részleges browser-státusz eltüntetésére.

Külön bizonyítékok:

* [Valódi publikus VulnX API](measurements/projectdiscovery/linux/vulnx-public.json):
  **1 HTTPS-kérés, 1,053 s**, CVE-2024-3094, API-key nélkül. A privát cél-CA
  mellett a provider a külön default/system CA-kat használta. Namespace- és
  TLS-bizonyíték szerepel a fájlban. Érintettség **unknown**, dinamikus finding 0.
* [Valódi DNS + HTTPS 443](measurements/projectdiscovery/linux/dns-https.json):
  saját DNS-név → saját VM-interfész; httpx és Katana egyaránt completed.
  A teszt nem módosít rendszerfájlt; a saját VM-ben előre beállított alias volt.
* Külön CLI-folyamatok, QoS-változás és resume: 3 tartós job,
  **0 átfedő job-időintervallum** macOS-en és Linuxon. Nincs új forgalom resume-ra.
* Valódi worker cancel/timeout mindhárom motornál: reaped processz,
  megőrzött részleges evidence-ref, felszabadított lease és eltávolított job-workspace.
* TLS-hiba, 429/cooldown, request-budget, response-limit, gzip, rossz
  binary-SHA, hibás CVE-ID, auth/API-hiba, cookie-redakció és page-budget kontrollok.
  A stdout/stderr-overflow az örökölt supervisor-regresszió szintetikus/mock
  folyamatával ellenőrzött határ, nem túlcsordulásig hajtott publikus scan.
* A régi POST/JSON/form/multipart, session refresh és automatikus capture/replay
  E2E-k a teljes csomag részeként ismét lefutottak. Méréseik a Linux könyvtárban.

## Külön jelzett korlátok

| Képesség | Valós állapot |
|---|---|
| macOS-ről kernelesen védett távoli worker | `blocked_linux_network_namespace_required`; Linuxon igazolt |
| httpx 1.12.0 encoded slash a pathban, illetve záró üres `?` | A motor átírná; `unsupported`, **0 továbbított kérés**. Katana a tesztelt encoded pathot változatlanul végrehajtotta |
| Katana teljes JS/SPA-lefedettség | Standard regex nem teljes: `/api/js-only` feltárva, az el nem indított `/js-only` nem. Headless feladat a meglévő Playwrighté |
| Katana Burp-detektor | Fix `http://burpsuite/` próba blokkolva DNS/kérésküldés előtt, külön számláló; nincs scope-kivétel |
| Tömörített / túl nagy válasz | `inconclusive` vagy explicit unsupported/limit hiba; nem negatív teszt |
| Új httpx/Katana auth/POST replay | Nem támogatott; a meglévő hitelesített browser/Nuclei útvonal megmaradt |
| Valódi provider API-key jogosultsága | Saját kulcs nem volt megadva; kulcsinjektálás valós CLI + kontrollált HTTPS-fixture-ben tesztelve, publikus provider anonim módja külön igazolt |
| VulnX CVE-egyezés | Intelligence; validált asset-verzió és érintett tartomány nélkül **unknown**, nem sérülékenységi bizonyíték |
| Hard RAM-limit / hostglobális több-DB governor / eredeti RCE | Nincs új OS hard limit; az eredeti RCE `not_reproduced_missing_fixture`; ezek nem negatív eredmények |

## Megőrzés és takarítás

**58 korábbi aktív tesztfájl és 47 assessment `SKILL.md` byte szerint megmaradt.**
A korábbi Nuclei/ffuf motorok SHA-ja a megőrzött receiptnek megfelel; a master
prompt, a Git HEAD/index és a felhasználó MCP-konfigurációjának hash-e megmaradt.
A korábbi Git-átrendezés nem ennek a feladatnak a törlése. Meglévő forrásfájlt
nem töröltünk; a változtatások célzott bekötések és új modulok.

A saját teszt-VM ellenőrzés után törölve lett; a tesztek után nem maradt
browser/scanner/bwrap worker. Csak saját generált tesztadat, cache, debug- és
referencia-munkakönyvtár kerül a Kukába. A managed motorok, az aktív tesztek,
felhasználói források és az alábbi ellenőrzési bizonyítékok megmaradnak:

* [Megőrzési bizonyíték](measurements/projectdiscovery/preservation.json)
* [Takarítás](measurements/projectdiscovery/cleanup.json)
* [Forráshash-ek](measurements/projectdiscovery/source-hashes.json)
* [macOS JUnit](measurements/projectdiscovery/macos/tests.junit.xml),
  [Linux JUnit](measurements/projectdiscovery/linux/tests.junit.xml)
* [macOS mérések](measurements/projectdiscovery/macos/derived.json),
  [Linux mérések](measurements/projectdiscovery/linux/derived.json)

Reprodukció telepített motorokkal:

```sh
PYTHONPATH=. REDJOHN_REQUIRE_PD_E2E=1 .venv/bin/python -m pytest \
  tests/test_projectdiscovery_contract.py \
  tests/test_projectdiscovery_live.py -q -s

# Linux: user namespace/bubblewrap/iproute2/Chromium és a meglévő Nuclei lock szükséges.
# A DNS-fixture alias csak a saját tesztinterfészre oldódhat fel.
PYTHONPATH=. REDJOHN_REQUIRE_PD_E2E=1 REDJOHN_REQUIRE_REMOTE_E2E=1 \
  REDJOHN_DNS_FIXTURE_NAME=redjohn-owned-fixture.test \
  .venv/bin/python -m pytest tests -q -s
```
