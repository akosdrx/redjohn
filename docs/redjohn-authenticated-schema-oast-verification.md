# RedJohn: autentikált TInjA / Schemathesis / Interactsh POST és refresh

2026-10-18. A korábbi GET-profilok célzott bővítése, a RedJohn név,
meglévő felhasználói módosítások és aktív integrációk megőrzésével.

## Működő lánc és pontos határ

Valódi Chromium POST-capture → privát v2 vault-jóváhagyás → kijelölt tartós
adapterjob → valódi pinned TInjA/Schemathesis vagy hivatalos Interactsh receiver →
korlátozott bizonyíték/riport. A három bodyformátum: JSON, URL-encoded form,
multipart; a fájlfeltöltés byte-jai változatlanok maradnak.

A host nyilvános GET/query inputot ad a workernek; a privát body nem kerül az
argumentumokba, kérésfájlokba vagy generált sémába. A host egy felülvizsgált mezőt helyettesít
az eredeti privát bodyban, majd tényleges autentikált HTTPS POST-ot küld. Ez
RedJohn transport bridge, nem upstream JSONL-ból következtetett vagy korlátlan
natív bodytámogatás. A Schemathesis kiválasztott integer-input vetületet generál;
a valódi válaszkonformitást az upstream motor ellenőrzi. A TInjA véges katalógusa,
a két explicit SKIP belső Schemathesis-probe és az OAST protokollverzió változatlan.

Egyértelmű, teljes 401 vagy pontos privát credential-lejárat → tartós,
kerethez kötött, azonos actorú refresh → új session-revízió → valódi friss
Chromium-capture → új kiválasztott adapterjob. Ugyanabban a schedulerben is
végigfut; a régi sikertelen POST nem kap új címkét és nem indul újra.

Az OAST poll már elküldött allocationt követ; sessionváltás után sem kézbesít
újra a célra és nem igényli a régi cél-credentialt. A receiverengedély és a
privát kulcs/állapot továbbra is külön ellenőrzött. A bizonytalan dispatch vagy
draining poll továbbra is inconclusive, nem automatikus retry vagy negatív.

## Végső ellenőrzések

| Ellenőrzés | macOS ARM64 | Ubuntu ARM64 |
|---|---:|---:|
| Teljes csomag | 1030 pass / 46 skip, 598.40 s | 1076 pass / 0 skip, 785.24 s |
| Új valódi E2E | 47 pass / 21 kernel-skip | 68 pass / 0 skip |
| Új szintetikus input/recovery kontraktus | 38 pass | 38 pass |
| Strict mypy | 197 modul, 0 hiba | 197 modul, 0 hiba |
| Teljes teszt-workload mintavett RSS-csúcs | 815.64 MiB | 1191.80 MiB |
| Új valódi case-adatbázisok | 47 | 68 |

A 46 macOS-skip mind sikeres Linux-esethez párosítható.
A végső forráslista 326 fájl, 271 Python-forrással (197 modul, 67 teszt/support,
7 script); mindkét futás előtt/után nulla forráseltérés. A nyers JUnit, parancs,
szűrt env, engine SHA-k és 11 valós managed engine adatai a platformmappákban vannak.
A teljes csomag unit/mock teszteket is tartalmaz; a mock installer-output nem
binárisbizonyíték. A fenti új E2E-számok tényleges hálózati/engine I/O-t jelentenek;
a két TTL- és három hop-header eset csak késleltetést/fejlécet injektál, nem válaszokat.

Ruff sikeres; 15 érintett Python-fájl formátumellenőrzése sikeres. Viewer: 2261
modul / 2.77 s, strict-unused TypeScript sikeres, négy static asset byte-azonos.
Go test/vet sikeres, a négy csomagban nincs Go unit teszt. GitHub CI-futás nem történt.

Mindkét platformon nulla fennmaradt jobowner és nulla átfedő jobidőszak az új
case-adatbázisokban. A RSS külső processzfa-összegzés, 100 ms alvással és ps-overheaddel;
megosztott lapok többször számolhatók. A teljes pytest/controller/Chromium/scanner/owned
receiver workloadot méri, nem kizárólagos engine-heapet vagy OS hard limitet.
A Linux-körben mypy nem futott a tesztek mellett; a saját VM fájlcache-e előtte ürült.


A kontraktusfájl szintetikus body-/állapot-/recovery-ellenőrzés. A két új live
fájl tényleges Chromiumot, scannerfolyamatokat, HTTPS refresh providert és
hivatalos titkosító Interactsh receivert futtat. A külön CLI-esetek négy külön
processzt indítanak ugyanarra a tartós adatbázisra. A csonka 401, a 403 és a 429
nem indít frissítést és nem válik negatív sérülékenységi tesztté.

Az egyes történeti 401 jobok blokkoltak maradnak; az adott CLI ezért 1-gyel is
kiléphet akkor, amikor az új revíziójú adapterjob sikeres. A mérés ezt külön mutatja.
A callback és a scannerjelzés candidate; egyik sem automatikus confirmed RCE.


## Mért jobfázisok és reprodukció

Csak a kezdeti pozitív/javított POST-mátrix sikeres jobfázisai, p50 / nearest-rank
p95. A recovery, csonka válasz, startup-latencia és hop-header kontroll nincs a
mintában. Az OAST parent és poll külön fázis; ez nem a teljes callback-várakozás.

| Jobfázis | macOS | Linux |
|---|---:|---:|
| `tinja_validate` | 1.076 / 2.670 s, n=6 | 1.038 / 3.052 s, n=12 |
| `schemathesis_validate` | 3.327 / 3.529 s, n=6 | 1.872 / 2.290 s, n=12 |
| `oast_correlate` | 0.242 / 0.348 s, n=6 | 0.162 / 0.210 s, n=12 |
| `oast_poll` | 0.120 / 0.128 s, n=9 | 0.089 / 0.115 s, n=18 |

[Esetszintű mérések és módszer](measurements/authenticated-schema-oast/performance-summary.json),
[tesztösszesítő és skiplista](measurements/authenticated-schema-oast/test-summary.json),
[Linux-lab határa](measurements/authenticated-schema-oast/linux/lab-boundary.json).
A case-adatbázisokból képzett read-only kivonatban külön van a queue-wait és a
job-duration. A teljes E2E-idő és a cél-POST-ok száma a case-rekordokban látható;
a regisztráció/poll infrastruktúra-kérései nincsenek cél-POST-nak feltüntetve.

A teljes kör pontos pytest argv-ja és szűrt env-je:
[macOS](measurements/authenticated-schema-oast/macos/command.json),
[Linux](measurements/authenticated-schema-oast/linux/command.json);
mindkettő a repository gyökeréből, `PYTHONPATH=RedJohn` környezettel indult.
A célzott új tesztparancs az angol runbookban szerepel.

| Egyéb ellenőrzés | Munkakönyvtár | Parancs |
|---|---|---|
| Strict mypy | `RedJohn` | `../.venv/bin/python -m mypy redjohn --no-incremental` |
| Ruff | repógyökér | `.venv/bin/ruff check RedJohn/redjohn RedJohn/scripts RedJohn/tests` |
| Viewer build | `RedJohn/redjohn/interface/viewer/frontend` | `npm run build -- --outDir /tmp/redjohn-auth-schema-viewer/dist --emptyOutDir` |
| TypeScript | ugyanott | `npx tsc --noEmit --incremental false --noUnusedLocals --noUnusedParameters` |
| Go | `RedJohn/redjohn/interface/tui` | `go test ./...`, `go vet ./...` |

## Indítás és átadás

Az [angol runbook](../RedJohn/docs/authenticated-schema-oast.md) tartalmazza a
konfigurációs mezőket, a bodyk és tokenek privát kezelését, a telepítési és
reprodukciós parancsokat. A repository gyökeréből:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/approved.json \
  --output /absolute/private/engagement --max-jobs 32 --wait-ready-seconds 65
```

A 64 meglévő teszt/support fájl byte-azonos; három új aktív tesztfájl marad.
A 47 angol skillből öt célzott kontraktus és a manifest frissült; a 35 eredeti
felhasználói skill SHA-ja külön ellenőrzött. A master prompt, HEAD, origin,
Git-index, privát MCP-konfiguráció és a 11 korábbi managed engine változatlan.
Baseline fájl nem hiányzik. [Megőrzési bizonyíték](measurements/authenticated-schema-oast/preservation.json).

[Módosított fájlok](redjohn-authenticated-schema-oast-changed-files.md),
[kumulatív átadás](redjohn-changed-files.md),
[takarítási jegyzék](measurements/authenticated-schema-oast/cleanup.json).


## Blokkolt, unsupported és nem igazolt képességek

- macOS-en a távoli browser/scanner worker Linux kernelhatár nélkül blokkolt.
  A helyi HTTPS-lab és a Linux nem-loopback HTTPS külön bizonyíték.
- TInjA/OAST: egy kijelölt string/text mező; Schemathesis: egy top-level JSON
  integer vagy integer form/multipart text. XML, objektum/array-érték módosítása,
  ismételt kijelölt mező, file-part mutation és általános stateful/GraphQL/CRUD
  unsupported. A többi byte, query és upload megmarad.
- A megőrzött v2 bodykontraktus a puszta JSON/form MIME-ot és a pontos
  `; charset=utf-8` toldatot fogadja el. Más írásmód, például a browser-default
  `;charset=UTF-8`, unsupported; nincs csendes normalizálás vagy negatív eredmény.
- A profil-fingerprint frissült; régi profilhoz kötött várakozó job/allocation
  nincs átírva vagy újraküldve. Ezek explicit egyeztetést igényelnek. A v1/v2
  privát vault sémája kompatibilis. A refresh sessionenként történik; minden
  scannerpróbához új egyszerhasználatos nonce szerzése unsupported.
- Általános login/logout/MFA/password-reset és a provider saját refresh-tokenjének
  rotációja nincs bevezetve. Nincs anonim fallback vagy cél-/hatáskör-bővítés.
- Publikus OAST DNS-delegáció, internetes/IPv6 callback-elérhetőség és további
  protokollok nem igazoltak. A fixture kontrollált HTTP Host útvonalon ér el
  valódi hivatalos receivert. Nuclei–OAST binding továbbra is unsupported.
- A RAM-governor kooperatív; nem univerzális hard limit. Hosszú soak, Kali/AMD64
  kiadás, GitHub CI-futás és a teljes kereskedelmi csomagolás nincs itt igazolva.
- Az eredeti RCE-fixture hiányzik: `not_reproduced_missing_fixture`.

## A végső kör előtti diagnosztika

Az első teljes Linux-kör 1073 pass / 2 fail / 1 skip lett (770.69 s).
Az authentication-session optional mapping bővítése eltért a megőrzött régi
kontraktustól; a régi mapping visszaállt, az új adapterek saját skilljei megtartják
a bővítést. A régi teszt nem változott. A repón kívüli eredeti 35 skill hiányzó
Linux-referenciája pótolva, a célzott kompatibilitási/proveniencia kör 6/6 sikeres.

Egy régi Chromium–Nuclei restart egyszer `PolicyDenied`-del állt meg. Öt teljes
E2E-ismétlés és 32 extra, zérójobos valódi CLI-restart nem reprodukálta. A mentett
workspace másolatának hálózat/worker nélküli megnyitása is zérójobos lett.
Az ok nem bizonyított; nem állítom külön javítottnak vagy negatív teszteredménynek.
Az első teljes kör megmarad diagnosztikaként. A végső teljes körök debug hook,
időfagyasztás vagy startup-stress plugin nélkül futottak, a régi tesztek változatlanok.

## Későbbi MIME/restart vizsgálat

Az itt rögzített eredmények történeti mérések. A következő folytatás feloldotta
a szabályos UTF-8 MIME-írásmódok korlátját, reprodukálta az üres restart 2-es
kilépését kontrollált policy-lejárattal, és külön Schemathesis auth-admission
versenyhelyzetet javított. A korábbi napló nem tárolta a konkrét PolicyDenied-okot;
az új diagnózis ezt a bizonyítási korlátot is megőrzi. Lásd az
[új jegyzőkönyvet](redjohn-mime-restart-verification.md).
