# RedJohn MIME/charset és restart ellenőrzés

2026-10-18. Az új fejlesztés a meglévő RedJohn kódra épül. A név, branding,
saját eszközök, általános MCP-támogatás és a működő integrációk megmaradtak.

## Implementáció

Az új `assessment/media_type.py` korlátozott MIME-parsert ad. A privát vault
gyökérverziója továbbra is 2; az egyes POST-approvalok opcionális
`body_contract_version: 2` jelölése engedi az új értelmezést. A régi approvalok
és a régi szigorú tesztek változatlanul működnek. A browser tényleges
Content-Type fejléce és a body byte-jai megmaradnak; nincs hitelesített kérés
csendes átírása.

Támogatott a kis-/nagybetűs és idézett UTF-8 charset, a Chromium valódi
`application/x-www-form-urlencoded;charset=UTF-8` fejléce és az idézett
multipart boundary. A body-token refresh, a friss browser-capture, a kiválasztott
TInjA/Schemathesis/OAST mező és a privát Nuclei binding ugyanazt a kontraktust
viszi tovább a tartós schedulerben. A publikus Nuclei-template továbbra is a
meglévő kanonikus host-placeholdert használja; a host az eredeti privát fejlécet
és bodyt állítja vissza.

Két külön restart/auth jelenség lett megkülönböztetve:

1. A CLI a policy-visszautasításnál csak általános `policy_denied` hibát mutatott.
   Most biztonságos, engedélyezett konstans `reason` mezőt is ad, például
   `campaign_deadline_exceeded`. A lejárt engedély továbbra is 2-es kilépés és
   nulla új hálózati kérés; a deadline nem hosszabbodik meg automatikusan.
2. A Schemathesis teljes 401 után az aszinkron worker-leállítás előtt még új
   kérést adhatott fel. A szinkron admission-kerítés ezt a budget/socket előtt
   megtiltja. Az addig megfigyelt teljes válaszok és a konzervatív auth-recovery
   feltételei megmaradnak; a hiányos válasz nem lesz negatív eredmény.

## Valódi ellenőrzések

| Ellenőrzés | macOS ARM64 | Ubuntu ARM64 |
|---|---:|---:|
| Teljes csomag | 1087 pass / 66 skip, 741.31 s | 1153 pass / 0 skip, 1011.59 s |
| Új valódi integráció/E2E | 28 pass / 20 kernel-skip | 48 pass / 0 skip |
| Új szintetikus MIME/CLI kontraktus | 29 pass | 29 pass |
| Teljes teszt-workload mintavett RSS-csúcs | 833.75 MiB | 1220.17 MiB |
| Új valódi eset-adatbázisok | 28 | 48 |

A táblázat a pytest összesítőidejét mutatja; a JUnit és a külső sampler külön
mérésiablakának ideje is megmarad a JSON-adatokban.

A 66 macOS-skip mind sikeres Linux-teszthez párosítva. Mindkét
platformon nulla fennmaradt jobowner és nulla átfedő jobidőszak az új esetekben.
A 330 fájlos forráslista mindkét teljes kör előtt és után byte-azonos.
A falióra mínusz monoton futásidő eltérése macOS-en
0.001205 s, Linuxon
0.000002 s.

A RSS külső processzfa-összegzés 100 ms alvással és ps-overheaddel. A teljes
pytest/controller/Chromium/scanner/owned-receiver workloadot méri; a megosztott
lapokat többször számolhatja, nem OS hard limit vagy engine-heap mérés. A Linux
kör előtt pinned install és célzott E2E futott; nem cold-cache benchmark.
A két platform futásának idősávja részben átfedett ugyanazon fizikai hoston;
ezek workload-mérések, nem izolált platformsebesség-benchmarkok.

[Teljes tesztösszesítő és pontos skiplista](measurements/mime-restart/test-summary.json),
[esetenkénti mérések és p50/p95](measurements/mime-restart/performance-summary.json),
[Linux-lab határa](measurements/mime-restart/linux/lab-boundary.json).


A teljes csomag szintetikus/mock teszteket is tartalmaz. Az új MIME-kontraktus
26 esete és a CLI allowlist 3 esete külön szintetikus ellenőrzés. Az installer-unit
tesztek mintakimenete nem natív binárisbizonyíték; a tényleges engine-ek verzióját
és SHA-ját a platformok `binary-integrity.json` fájlja rögzíti. Az új 48
integrációs/E2E eset tényleges Chromiumot, TLS-t, privát host replayt, pinned
scannerfolyamatot vagy hivatalos Interactsh receivert használ. A saját HTTPS
alkalmazás MIME-értelmezése a production parsertől független Python email
parserrel történik. A fixture osztálycsere nem helyettesít engine-választ vagy
hálózati I/O-t.

A clock-step eset egyetlen valódi CLI-child Python falióráját lépteti 600
másodperccel előre. Ez explicit időinjekció; a host órája, Chromium, Nuclei,
TLS és HTTP-válaszok valósak. A lejárt child előtt és után a négy kész job,
attempt, policy-deadline és a cél kérésszáma változatlan. Utána a normál órájú
teljes régi E2E folytatódik, refresh-sel és friss replayjel.

## A korábbi eltérés diagnózisa

A korábbi hibás teljes Linux-futás JUnit kezdete és a host befejezése között
3349,762 s telt el, míg a monoton sampler 771,574 s-ot mért. A különbség
2578,188 s, körülbelül 43 perc. A feladatra szűrt rendszeresemények összesen
2592 s hostalvást mutatnak ugyanebben az időablakban. A nyers power log,
alkalmazásnevek és más tevékenység nem került a bizonyítékok közé.

Az eredeti teszt policy-határideje 300 s. A kontrollált +600 s child-időlépés
a változatlan korábbi kódon reprodukálta a pontos tünetet: négy sikeres lépés
után az `unchanged_restart_no_browser_or_post` 0 helyett 2-vel tér vissza,
a stack a `NativeFixtureSession.__init__` → `check_scope_url` deadline-ellenőrzésre
mutat. Az új E2E a pontos reason mezőt és a nulla mellékhatást is ellenőrzi.

Ez a határidő-mechanizmust reprodukáltan bizonyítja, és erősen alátámasztja az
eredeti eset magyarázatát. A történeti futás konkrét kivételokát annak régi,
általános naplójából nem lehet visszaállítani; ezt a bizonyítási korlátot nem
helyettesíti a következő sikeres futás. A szünet nélküli külön diagnosztika
100 extra valódi üres CLI-restartot és 30 friss első öt lépéses láncot futtatott
hiba nélkül. A 30 prefix nem 30 teljes refresh E2E.

A régi tesztsorrend prefixe külön hibát hozott elő: 344 pass után egy
Schemathesis refresh esetben 6 admissionre csak 5 teljes válasz jutott. A
konzervatív recovery emiatt inconclusive lett. A célzott, valódi új regresszió
a javítás előtt 7 késői admissiont mért a teljes 401 után, a javítás után 0-t.
Ez külön versenyhelyzet, nem azonos a korábbi általános CLI PolicyDenied-del.

[Időbizonyíték](measurements/mime-restart/diagnostics/historical-timing.json),
[piros regressziós hurkok](measurements/mime-restart/diagnostics/red-capable-loops.json),
[ismétlési/probe összesítő](measurements/mime-restart/diagnostics/restart-probes.json).

## Megőrzés és indítás

A 67 meglévő teszt/support fájl byte-azonos; három új aktív tesztfájl marad.
A 47 angol skill és a 35 eredeti felhasználói forrás ellenőrzött, változatlan.
A master prompt, HEAD, origin, Git-index, privát MCP-konfiguráció és mind a 11
korábbi managed engine változatlan; baseline fájl nem hiányzik.
[Megőrzési bizonyíték](measurements/mime-restart/preservation.json),
[módosított fájlok](redjohn-mime-restart-changed-files.md),
[kumulatív átadás](redjohn-changed-files.md),
[takarítás](measurements/mime-restart/cleanup.json).

Strict mypy: 198 production modul, 0 hiba; Ruff és formátum: 14/14 érintett
Python-fájl sikeres. A frontend/Go források nem változtak ebben a folytatásban;
a korábbi build/test/vet mérések történeti bizonyítékok, itt nem futottak újra.


Az [angol használati leírás](mime-replay-and-restart.md) tartalmazza
a verziómezőket és a parancsokat. A repository gyökeréből:

```sh
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/approved.json \
  --output /absolute/private/engagement --max-jobs 32 --wait-ready-seconds 65

PYTHONPATH=. .venv/bin/python -m pytest tests -q -s
.venv/bin/mypy redjohn
```

A platformonkénti `command.json` tartalmazza a tényleges teljes tesztparancsot,
szűrt env-et és a kötelező engine/kernel feltételeket. A mérések saját kontrollált
HTTP(S)-labra vonatkoznak. Új külső kódrészlet, toolverzió, Strix/HexStrike
komponens vagy Firecrawl nem került be.

## Megmaradó korlátok

- A szöveges body UTF-8 marad. ISO-8859-1/UTF-16, XML/vendor JSON, ismételt
  kijelölt mező és file-part mutation unsupported; ezek nem negatív scanek.
- macOS-en a távoli worker Linux kernelhatára hiányzik. A loopback HTTPS
  lab és a Linux nem-loopback egress külön ellenőrzés.
- A hiányos/túl nagy válasz, TLS-hiba, 403/challenge és ismeretlen hatás nem
  jogosít auth refreshre vagy tiszta negatív eredményre. Minden POST/session
  és kampánybudget érvényes marad.
- Általános login/MFA/egyszerhasználatos nonce workflow, publikus OAST DNS/IPv6
  elérhetőség és Nuclei–OAST binding nincs ebben a folytatásban igazolva.
- A régi, eredeti RCE-fixture hiányzik: `not_reproduced_missing_fixture`.
  RAM hard limit, hosszú soak, Kali/AMD64 csomag és GitHub CI itt nem igazolt.
