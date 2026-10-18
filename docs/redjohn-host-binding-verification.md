# RedJohn közös host-binding ellenőrzés

2026-10-18. A master prompt teljes feladata továbbra is aktív; ez a közös
CLI/TUI/agent runtime bekötésének implementált és ellenőrzött szakasza.
[Teljes hátralék](redjohn-completion-status.md),
[angol működési és indítási leírás](../RedJohn/docs/host-bound-assessment.md).

A közös konfigurációs factory ugyanazt a tartós SQLite queue-t és adaptereket
használja a dedikált assessment CLI és a root/child SDK-context számára.
A korlátos host-pump egyesével kér jobokat. Nem indít új queue-t vagy minden
opcionális motort. A runner automatikus MCP-warmupja kikerült; a felhasználó
konfigurációja és az általános, kiválasztáskor kapcsolódó MCP működés megmaradt.

Az inventory-only indulás DNS és HTTP nélkül rögzíti az explicit web/API
célokat; a jobok valódi scope/IP/egress vizsgálata megmaradt. A natív
Nuclei-session is a store által egyszer kanonizált policyt és határidőt kapja.
A privát snapshot v2 UID-/caller-/run-directory-kötött HMAC, `0600` fájl,
atomikus csere és fsync mellett marad tartós. A puszta SHA átírása nem jóváhagyás.

A host a policy-váltást, teljes cancel-t és határidőt külön stop-okkal kezeli.
A mutáló jobok retry-jelzője az API-ban származtatott vagy elutasított, a
scheduler a hibás persisted refresh/capture jobot is leállítja. A riportmetrikák
közösek a dedikált CLI-vel; lezárt control service stabil blokkolt választ ad.

A korai hibák takarítása közben talált resume-regresszió külön javítást kapott:
hibás/unreadable topology nem írható felül, és el nem indult roothoz nem készül
hamis resumable graph. A szabályos SDK-resume megőrzi a session historyt ugyanabban
az adatbázisban, mint az assessment queue. Hibás host-start biztonságosan
lezárható; opcionális komponens close-hibája mellett a többi cleanup is lefut.

## Célzott és valódi ellenőrzések

| Platform | Célzott csomag | Idő |
|---|---:|---:|
| macOS ARM64 / Python 3.13.16 | 104 sikeres, 0 hibás, 0 skip | 19.61 s |
| Ubuntu ARM64 / Python 3.12.3 | 104 sikeres, 0 hibás, 0 skip | 18.36 s |

[macOS JUnit](measurements/host-binding/regressions/host-binding-final-targeted.junit.xml),
[Linux JUnit](measurements/host-binding/regressions/targeted-linux-final.junit.xml).
A 104 esetből 43 új: 5 valódi SDK/HTTPS/Chromium/Nuclei/processz-lock integráció,
38 SQLite/private-file/SDK-kontraktus vagy hibainjektálás. A többi 61 eset
meglévő scheduler/session-refresh/MCP regresszió.

A tényleges öt új integráció az alábbiakat igazolja:

| Eset | Tényleges eredmény |
|---|---|
| SDK-tool → host → Chromium → inventory → Nuclei | Három tartós job: egy browser, kezdeti Nuclei és explicit fixed-retest. A kezdeti markerre 1 candidate, a javított kontrollra 0; újranyitás és azonos job beküldése nem ad új target-kérést. |
| Host jobkeret | Egy valódi HTTPS megfigyelés után a következő beküldés blokkolt, új target-kérés nélkül. |
| Folyamatban lévő HTTPS cancel | Egy admission, majd `cancelled / partial`; stop-ok `engagement_cancelled`. |
| Folyamatban lévő HTTPS határidő | Egy admission, majd `cancelled / partial`; stop-ok `deadline_exhausted`. A bizonytalan kimenetel nem negatív vizsgálat. |
| Másik processz által tartott scheduler-lock | Várakozás 0 target-kéréssel és 0 worker-foglalással; lock elengedése után ugyanaz a controller automatikusan végrehajt 1 HTTPS megfigyelést. |

Mind az öt lezárásnál üres az aktív resource-állapot. Az SDK/browser/Nuclei
esetben összesen 6 tartós request-admission történt, a másik négyben 1–1.
Az admission és a tényleges szerverválasz külön fogalom: cancel/deadline alatt
a fixture még nem adott teljes választ. A mérés és a tartós jobok kivonata:
[adatok](measurements/host-binding/targeted-live-macos.json).
Model-call/input-token/output-token: e teszteknél 0; modellprovider nincs meghívva.

A teljes kör külön valódi Nuclei-kontrollja mindkét platformon 3.11.1 motort
futtatott, pozitív/javított 1/0 eredménnyel. A valós binary SHA-256 macOS-en
`f427ae885dcd60be25cf27c34a416ef18a803b29e153d5568057d7b6012a454d`, Linuxon
`f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477`:
[macOS](measurements/host-binding/macos/nuclei.json),
[Linux](measurements/host-binding/linux/nuclei.json).
A mock installer teszt naplójának 35 bájtos fixture-binárisa ettől külön
szintetikus ellenőrzés, nem a valós scanner telepítési bizonyítéka.

A root runner tesztjeiben a modell-loop és a sandbox indulása tesztdublőr.
A runner, coordinator, SDK session, approval és control service valódi.
Ezek context-megosztást, jogosultságot, byte-megőrző hibás resume-t, szabályos
history-resume-t és cleanupot igazolnak; nem teljes CLI/TUI vagy live provider E2E-t.
A marker/fixed fixture nem az eredeti, hiányzó RCE-fixture reprodukciója.

## Hibák előtte és utána

A megőrzött JUnitok a valódi hibát kiváltó futásokat külön tartják:

- [metadata-only import előtte](measurements/host-binding/regressions/metadata-import-before.junit.xml);
- [nem ASCII MAC, hiányzó kulcs, más run és FD-szivárgás előtte](measurements/host-binding/regressions/approval-faults-before.junit.xml),
  [javítás után](measurements/host-binding/regressions/approval-faults-after.junit.xml);
- [hibás resume megőrzése előtte](measurements/host-binding/regressions/resume-preservation-before.junit.xml),
  [javítás után](measurements/host-binding/regressions/resume-preservation-fixed.junit.xml);
- [host-start hiba előtte](measurements/host-binding/regressions/host-start-fault-before.junit.xml),
  [komponens close-hiba előtte](measurements/host-binding/regressions/component-close-before.junit.xml),
  [javítás után](measurements/host-binding/regressions/host-start-close-fixed.junit.xml);
- [natív deadline-eltérés előtte](measurements/host-binding/regressions/native-deadline-before.junit.xml);
- [határidő stop-ok előtte](measurements/host-binding/regressions/deadline-reason-before.junit.xml).

Az FD-hiba három sikertelen aláírás után 14 → 17 saját FD-t adott. A fix
aláírás előtt nem nyit kimeneti descriptort; a külön ellenőrzés FD-számnövekedés
és hátrahagyott ideiglenes fájl nélkül zárul. Ez privát fájl-/IO-hibainjektálás,
nem scanner-integráció.

## Teljes regresszió és forrásrögzítés

A javított teljes macOS/Linux kör terminális és sikeres:

| Platform | Sikeres | Hibás | Skip | pytest idő | Külső idő | Külső processzfa-RSS csúcs |
|---|---:|---:|---:|---:|---:|---:|
| macOS ARM64 | 1154 | 0 | 71 | 823.96 s | 825.99 s | 898859008 B / 857.22 MiB |
| Ubuntu ARM64 | 1225 | 0 | 0 | 1042.76 s | 1044.18 s | 1297227776 B / 1237.13 MiB |

[macOS JUnit](measurements/host-binding/macos/tests.junit.xml),
[Linux JUnit](measurements/host-binding/linux/tests.junit.xml),
[összesítő](measurements/host-binding/verification-summary.json).
A strict mypy mindkét platformon 204 production modult ellenőrzött hibamentesen;
a módosított kód Ruff ellenőrzése is sikeres. A 71 macOS-skipből 66 Linux
namespace/egress, 5 Linux cgroup képesség hiánya; Linuxon valamennyi lefutott.
Az 1225 eset unit-, kontraktus- és valódi integrációs/E2E-tesztet egyaránt jelent.

A mintavevő 6139 / 9815 külső mintát és legfeljebb 15 / 18 processzt látott,
hiányzó minta nélkül. A végén mindkét ledger üres, elveszett owner nincs:
[macOS](measurements/host-binding/macos/resources-after.json),
[Linux](measurements/host-binding/linux/resources-after.json).
A forráshash és forráslista futás előtt/után változatlan. Az RSS-mérés nem
hard OS-limit; a részben átfedő futások nem izolált gyorsulási benchmarkok.
A JUnit aggregált ideje 823.929 / 1042.728 s, a táblázat a pytest saját
összesítőjének idejét mutatja.

A 412 rögzített
bemenet 295 Python-forrást, a két prompt-sablont, runtime-adatokat, Viewer-fájlokat,
az eredeti és natív skilleket, konfigurációkat és a tényleges mintavevőt tartalmazza.
[Manifest](measurements/host-binding/source-hashes.json), SHA-256:
`bb5ed5f58756dedc64f67a71ae8a668cb84d3a7c9e0764aa34a26d847879b8e6`.

A resume-hiba felfedezésekor a korábbi köröket a saját, azonosított pytest
processzüknek küldött SIGINT-tel megszakítottam. macOS: 369 befejezett esetből
348 sikeres, 21 skip, 249.47 s külső idő. Linux: 372 befejezett esetből
371 sikeres, 1 interrupt alatti hiba, 282.64 s. Ezek nem teljes regressziók.
A forráshash és a forráslista nem változott a futásuk alatt. A részleges
[macOS](measurements/host-binding/macos-before-resume-fix/memory.json) és
[Linux](measurements/host-binding/linux-before-resume-fix/memory.json) eredmény,
JUnit, napló és megszakítási ok megmaradt. A macOS-en látható unfenced browser
foglalás karanténban maradt; nem állítom automatikus OS-fence nélküli visszanyerésnek.
A későbbi mintában Playwright-processz nem maradt. A részleges teszt-ledger nem
kerül újra használatba; az új kör új ledgerrel fut.

## Megőrzés, indítás és nyitott hatókör

A 76 korábbi aktív Python teszt/support forrás és 11 host-engine hash szerint
változatlan. A HEAD, origin, index és privát MCP-konfiguráció is egyezik:
[megőrzés](measurements/host-binding/preservation-before.json).
A teljes ellenőrzés utáni [hashvizsgálat](measurements/host-binding/preservation-after.json)
ugyanezt igazolja; a kiinduló meglévő fájlok közül sem hiányzik egy sem.
A módosított Python-források listája:
[fájllista](measurements/host-binding/changed-python-files.json).
Emellett a `scope.jinja`, az angol host-binding leírás, ez az ellenőrzési leírás
és a teljes státuszjegyzék változik. A Gitben korábban meglévő átstrukturálás
nem e szakasz törlése.

A lezárt saját pytest-fixture könyvtárak, átmeneti archívum és a már aktív
tesztbe átvezetett prototípusok közül 28 host- és 8 guest-elem helyreállíthatóan
a Kukába került. Aktív tesztforrás nem törlődött. A baseline, a tényleges
mérések, a következő cache-migráció saját korpusza és a még használt Linux VM
megmaradt: [takarítási jegyzék](measurements/host-binding/generated-cleanup.json).

Indítás a repository gyökeréből, az operator által jóváhagyott célra:

```sh
PYTHONPATH=RedJohn .venv/bin/redjohn --target https://owned.example \
  --assessment-config /absolute/path/approved-assessment.json
PYTHONPATH=RedJohn .venv/bin/redjohn --non-interactive \
  --target https://owned.example \
  --assessment-config /absolute/path/approved-assessment.json
PYTHONPATH=RedJohn .venv/bin/redjohn --resume RUN_NAME
```

A help valóban lefutott és tartalmazza az új argumentumot. Ezek működési parancsok;
a példabeli domain nem tesztelt vagy automatikusan engedélyezett publikus cél.
Tényleges célzott ellenőrzés:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_host_assessment_contract.py \
  RedJohn/tests/test_host_assessment_live.py \
  RedJohn/tests/test_host_binding_contract.py \
  RedJohn/tests/test_host_binding_failures.py \
  RedJohn/tests/test_host_job_contract.py \
  RedJohn/tests/test_host_lifecycle_live.py \
  RedJohn/tests/test_runner_assessment_contract.py \
  RedJohn/tests/test_assessment_scheduler.py \
  RedJohn/tests/test_assessment_session_refresh.py \
  RedJohn/tests/test_mcp_configuration.py -q -p no:cacheprovider
```

A teljes kör tényleges mintavevője új kimeneti könyvtárral reprodukálható:

```sh
PYTHONPATH=RedJohn .venv/bin/python \
  docs/measurements/host-binding/full-suite-sampler.py.txt \
  /tmp/redjohn-host-verification-results /tmp/redjohn-host-verification-pytest \
  docs/measurements/host-binding/source-hashes.json
```

A root/child service-binding nem helyezi automatikusan az összes régi Shell/MCP
operációt a közös policy/resource határba. A readonly mount nem általános
titok-olvasási kizárás. Inline SDK OS-limit csak már precontained Linux processzben
érvényes; a dedikált assessment CLI pre-exec containmentje ettől külön garancia.
A teljes provider fault matrix, UI E2E, régi cache-ek, inventory/workflow,
korreláció és további adapterek továbbra is nyitottak.

A régi CVE-cache mérése külön, offline saját SQLite-korpuszon valóban átlépte
a közös assessment cache-keretét: 383 megmaradt lejárt elem, 50212341 B JSON
a 33554432 B kerettel szemben. Ez még javítandó örökölt út, nem lezárt cache-
migráció vagy a mostani scanner-E2E negatív eredménye:
[mérés](measurements/host-binding/legacy-cache-before.json).

A helyi `gh` továbbra is az `itsolutionshu` fiókot használja; ezzel az
`akosdrx/redjohn` nem elérhető. GitHub CI és push nem történt:
[hozzáférés-ellenőrzés](measurements/host-binding/github-access.json).
Az eredeti RCE-fixture hiánya, publikus OAST és cloud/Kubernetes live-hozzáférés
külön korlát marad. A Kali/AMD64 és kiadási elfogadás sincs késznek jelölve.
