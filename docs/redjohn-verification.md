# Tényleges teszt- és mérési jegyzőkönyv — 2026-10-17

Történeti HTTP/loopback HTTPS baseline. A későbbi Linux remote-egress és
exact-request auth-replay működését a [remote/auth dokumentum](../RedJohn/docs/remote-egress-auth.md)
írja le; az aktuális sikeres lánc [külön mérési jegyzőkönyvet](redjohn-remote-auth-verification.md)
kapott, a browser partial coverage-ének megtartásával.
A korábbi „távoli blocked” állítások az akkori implementációra vonatkoznak.

## Frissített HTTPS/Nuclei állapot

A korábbi két helyi hiány megoldva: valódi Chromium HTTPS-böngészés és
checksum-/verziórögzített Nuclei v3.11.1 a tartós schedulerben. A külön
CLI-processzek között megőrzött inventory, sor, evidence, engine/template
verzió és idempotenciakulcs tényleges E2E-vel ellenőrzött. Az origin/group/account
rate-limit és a 429 cooldown szintén SQLite-ban marad újraindítás után.

A jelenlegi mérés, parancsok, bizonyítékok és még blokkolt képességek:
[HTTPS/Nuclei végleges jegyzőkönyv](redjohn-https-nuclei-verification.md).
A távoli production egress és a hiányzó specialist adapterek továbbra sem kész
képességek; a saját marker-fixture nem bizonyít CVE-t vagy RCE-t.

## Korábbi HTTP-only baseline — a HTTPS/Nuclei bővítés előtt

Az alábbi eredmények a korábbi változat archivált mérései. A bennük szereplő
Nuclei-/HTTPS-hiányok nem a fent hivatkozott új implementáció állapotát írják le.

Az új core vertikális szelet működik helyi HTTP lab-fixture-ön. A teljes master
prompt elfogadása továbbra is részleges: a valódi Nuclei, production egress,
HTTPS browser és több specialist adapter még hiányzik. A következők tényleges
futtatások, nem tervezett vagy háttérben ígért munkák.

## Teljes tesztkészlet

```bash
.venv/bin/python -m pytest RedJohn/tests -q \
  --junitxml=/tmp/redjohn-final-tests.xml
```

**148 passed, 1 skipped, 0 failure/error, 30.44 s.** A kihagyott teszt:
`test_live_existing_nuclei_local_marker`, oka:
`blocked_missing_dependency: existing Nuclei binary unavailable; no second engine installed`.
Egy skip sem jelent sikeres negatív scannert.

Bizonyíték: [JUnit](measurements/tests.junit.xml), [konzolkimenet](measurements/tests.txt),
[gépi összesítés](measurements/verification-summary.json).

| Tesztcsoport | Esetek | Bizonyítási szint |
|---|---:|---|
| Meglévő model-picker | 7 | Megőrzött korábbi tesztek |
| Scheduler/policy/control/SQLite | 22 | Valódi SQLite, hibaágaknál név szerint fake worker; nem scanner |
| Resource/cache/recovery | 25 | Unit/fault; process-tree RSS tényleges OS-lekérdezés |
| Technology/advisory/correlation/performance | 14 | Fixture/provider-double; nem live intelligence |
| Skillregistry/loader | 9 | Valódi 47 skill/manifest; readiness nem detektálási bizonyíték |
| Browser | 5 | Limitkontraktus + valódi Chromium, SPA, actor, crash, redirect, cancel, requestbudget |
| Összekötött pipeline | 8 | Valódi Chromium/HTTP/SQLite; guard és cancellation esetek külön; missing-browser valódi izolált subprocess |
| Nuclei-kontraktus/supervisor | 37 | Mock engine/SDK fixture és tényleges supervisor-subprocess faultok; nem valódi Nuclei |
| Native fixture session | 7 | Tényleges Python/processgroup, fake scanner; nem valódi Nuclei |
| Safe reproducer | 14 | Helyi HTTP-fejléc és javított kontroll; sem marker, sem syntax nem RCE-proof |
| Live Nuclei | 1 | **Skipped/blocked_missing_dependency** |

Ellenőrzött hibák: lejárt lease, fencing, cancellation cleanup közben,
koordinátorütközés és batch után élő browser megakadályozása, scanner timeout,
truncated/malformed JSON, outputkvóta, túlméretes evidence, disk/storage fault,
429/Retry-After másodperc/dátum, 403 elkülönítés, hiányzó/lejárt/sessionrevision-
hibás actorállapot, provider-kiesés, cache TTL/refresh verseny/invalidation,
offscope redirect, valódi Chromium crash és hiányzó Chromium-bundle.

A végső Ruff-ellenőrzés sikeres az új assessment/hunt/skill-loader és tesztfájlokon;
40 fájl formázásellenőrzése sikeres. `pip check`: **No broken requirements found**.
`compileall` és `bash -n RedJohn/scripts/install-kali.sh` sikeres.
A browser/hunt/native/reproducer modulokon külön célzott mypy sikeres; teljes
legacy repository typechecket vagy CI/Kali release-buildet nem állítunk.

## Soros, zavaró párhuzamos benchmark nélküli browser-mérés

```bash
REDJOHN_BROWSER_SOAK_CYCLES=20 .venv/bin/python -m pytest \
  RedJohn/tests/test_assessment_browser.py -q -s
```

**5 passed, 12.55 s.** Playwright **1.58.0**, valódi headless Chromium
**145.0.7632.6**. Az ismételt SPA-rész:

- 20 ciklus, két váltott, izolált actor; **100 tényleges HTTP-kérés**, **0 LLM-hívás**.
- Ciklus p50 **0.299475 s**, nearest-rank p95 **0.338508 s**.
- Context/page létrehozás–lezárás: **20/20**, **20/20**.
- Folyamatok száma minden mintában **6**; indítás előtt **2**, lezárás után **2**.
- Mintavételezett összegzett process-tree RSS maximum:
  **438 910 976 B = 418.58 MiB**. Első minta 411 516 928 B, utolsó 437 043 200 B.

Módszer: controller + gyermekfolyamatok RSS-ének összege; megosztott lapot
többször számolhat. Ez nem heap, nem cgroup-mérés és nem folyamatos OS-peak.
Az RSS emelkedése és rövid visszaesései alapján hosszú távú leakmentesség
nem állítható. Ez rövid reprodukálható workload, nem órás soak.

[Nyers mérések](measurements/chromium-20-cycles.json),
[tesztkimenet](measurements/chromium-tests.txt),
[részletes browser/fault leírás](../RedJohn/docs/redjohn-browser-verification.md).

## Teljes helyi core pipeline

```bash
.venv/bin/python -m redjohn.assessment demo --cycles 5 \
  --output redjohn_runs/handoff-2026-10-17
```

Tényleges idő **3.894833 s**, **22 HTTP-kérés**, **23 tartós input/surface**,
0 modellhívás/inputtoken/outputtoken és 0 modellköltség. A controller mérési
mintáiban RSS maximum **312 033 280 B = 297.58 MiB**. A ciklus p50
**0.692531 s**, p95 **0.748179 s**; a batchenkénti Chromium-indítás és
lezárás benne van, így ez nem a fenti shared-service workload időmérése.

Öt discovery-job `succeeded/partial`: a JS által kezdeményezett JSON/XML POST
metadata látható, küldése tiltott; nincs teljes bodyteszt/SPA-lefedettség állítva.
Két header-job `succeeded/completed`, két korábbi **candidate**, javított retestben
0 új candidate. Nincs automatikus globális „fixed” vagy confirmed impact.
Egy Nuclei-job `failed/blocked`, `tool_missing`. Két deduplikált submit nem küld
új kérést; retest explicit új revisionnel fut. A végén 0 page/context/proxy/
resource lease, és nincs késznek mondott hiányzó scanner.

[Mérési JSON](measurements/core-pipeline-5-cycles.json).
Teljes privát SQLite/report: `redjohn_runs/handoff-2026-10-17/`.

A konfigurált CLI-t két külön processzben is ellenőriztük ugyanazon DB-vel:
első indítás **1.167946 s / 5 új HTTP-kérés**, második indítás
**0.109379 s / 0 új kérés**. A tartós alap-deadline változatlan maradt.
Mindkét exit1 a külön jelzett Nuclei-hiány miatt történt, nem sikeres scannert
jelzett. [CLI restart-mérés](measurements/configured-cli-resume.json).

Külön 20-batch korláttesztben 60 origin-kérés után 15 discovery-job
succeeded/partial, 5 blocked, a header-jobok cooldownba kerültek. Ez a közös
keret tényleges működésének bizonyítéka, **nem 20 sikeres teljes vizsgálat**.
[Külön korlátteszt](measurements/origin-limit-20-batches.json) — az ottani korábbi
belső 403-os admission diagnosztikát azóta külön resource-kód váltotta fel.

## Cache és natív process-fault

Reprodukálható cache-parancs:

```bash
.venv/bin/python -m redjohn.assessment.cache_benchmark --cycles 20 \
  --lookups-per-cycle 2000 \
  --output redjohn_runs/cache-benchmark.json
```

Legutóbbi tényleges külön mérés: **40 000 hit**, **264 576 B** tárolt payload
524 288 B quota mellett, 0 in-flight, **1.535804 s**, 0 HTTP/LLM. Cache-trim
felszabadította a payloadot; RSS nem csökkent azonnal. Ez nem browser/full-platform
soak és nem régi/új gyorsulás. [Adatok](../RedJohn/docs/measurements/cache-workload-2026-10-17.json).

Valódi supervisor/fake-scanner processgroup cancel: **1.090996 s**, 0 maradó
aktív foglalás/marker/tempkönyvtár. [Adatok](../RedJohn/docs/nuclei-native-measurements.json).
Ez process cleanupot igazol; valódi Nuclei-motort nem.

## Pontosan mi nem igazolt

- Régi összehasonlítható workload: `baseline_unavailable`; nincs ígért gyorsulás.
- Eredeti RCE: `not_reproduced_missing_fixture`; nincs valódi RCE-detektálási állítás.
- False-positive/false-negative arány: `not_measured_no_vulnerability_oracle_fixture`.
- Nuclei engine/templates, új VulnX/specialisták, Caido live, cloud/Kubernetes:
  dependency/adapter/credential szerint külön hiányok; [capability-mátrix](redjohn-capabilities.md).
- HTTPS browser és távoli production/network: unsupported/blocked a tényleges
  egress-infrastruktúra elkészültéig. OS hard RAM-limit és teljes régi agentpolicy
  migráció még hiányzik. A régi működő integrációk kódja megmaradt.
- CI, Kali/Linux packaging és hosszú soak nem futott; ez macOS ARM64 helyi ellenőrzés.
