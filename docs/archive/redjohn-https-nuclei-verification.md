# RedJohn: valódi HTTPS browser–inventory–Nuclei E2E

Történeti loopback-jegyzőkönyv a távoli Linux-egress és exact-request auth-replay
hozzáadása előtt. A lenti tesztadatok az akkori forrássnapshothoz és workloadhoz
tartoznak; az új lánc külön mérendő. [Jelenlegi remote/auth út](remote-egress-auth.md).
[A sikeres Linux remote/auth mérés](redjohn-remote-auth-verification.md) külön workload.

Ellenőrizve: 2026-10-17, macOS ARM64, Python 3.13.16. A RedJohn neve,
projektstruktúrája és meglévő integrációi megmaradtak. A master prompt SHA256-a
változatlan; az induláskor rögzített 327 forrásfájlból egy sem tűnt el, 298
változatlan. A Git HEAD és a korábban már fennálló tracked státuszok darabszámai
is változatlanok. Nem történt reset, clean, checkout, commit vagy push.

## Elkészült működés

- **Playwright 1.58.0 / valódi Chromium 145.0.7632.6 HTTPS:** CONNECT után
  kérésenként ellenőrzött HTTP/1.1, szigorú upstream CA- és hostname-validálás.
  Kizárólag a saját ideiglenes proxykulcs SPKI-kivételét kapja Chromium;
  általános TLS-kikapcsolás vagy rendszer-truststore módosítás nincs.
- **Valódi Nuclei 3.11.1**, hivatalos MIT engine, külön engine- és saját
  fixture-template lock. Bináris SHA256:
  `f427ae885dcd60be25cf27c34a416ef18a803b29e153d5568057d7b6012a454d`.
  A meglévő hunt-útvonal erősödött; nem került be második scanner-implementáció.
  [Pontos forrás/licenc/checksum](nuclei-engine-provenance.json).
- **Tartós scheduler:** megfigyelt browser surface → SQLite queue → külön
  CLI-processzben végrehajtott scanner → bounded evidence → jelölt finding.
  Az engine-verzió és template-digest a jobkulcs része; eltérő lock blokkol.
  Azonos kulcs nem indít új hálózati kérést, újrateszt csak új retest revisionnel.
- **Tartós limit:** a browser, HTTP és scanner azonos SQLite origin/group/account
  ablakot és 429/503 cooldown-t használ. Három scope terhelése atomikus;
  a várakozást új runtime/adatbáziskapcsolat sem törli. Az engagement request
  budget külön tartós számláló. Az opcionális toolok sorban, admission után futnak.
- **Eredményhatár:** üres scanner-stdout vagy exit 0 önmagában nem negatív.
  Negatívhoz minden reviewzott kérés teljes, rögzített 2xx-válasza kell.
  TLS-hiba, 401/403/429/5xx, csonka válasz és quotaütközés nem negatív lelet.

A közös read-only guard tiltja a módosító metódusokat és az ismert
állapotváltoztató route-okat, többszörösen kódolt path/query esetén is.
Ez helyi labvédelmi réteg: URL-nevekből nem állapítható meg minden alkalmazás
szemantikája. A távoli profilokat ettől még nem nyitja fel a kód.

## Lefuttatott ellenőrzések

Repository-gyökérből:

```bash
.venv/bin/python -m pytest tests -q \
  --junitxml=docs/measurements/https-nuclei-tests.junit.xml
```

**230 passed, 0 failed, 0 error, 0 skipped — 62,70 s.**
[JUnit](measurements/https-nuclei-tests.junit.xml),
[konzolkimenet](measurements/https-nuclei-tests.txt),
[gépi összesítés és megőrzési ellenőrzés](measurements/https-nuclei-verification-summary.json).
Az utolsó, szemantikát nem módosító típusjelölés-/formázásjavítás után a
scheduler/policy + persistent limiter + TLS fixture + valódi, négyprocesszes E2E
csoport ismét lefutott: **40 passed / 9,65 s**.
[Kimenet](measurements/https-nuclei-final-targeted-tests.txt).

| Csoport | Eset | Mit bizonyít |
|---|---:|---|
| `test_nuclei_live.py` | 7 | Valódi pinned engine, HTTP/HTTPS marker és fixed control, hibás CA/SAN, tényleges 401/403/429 |
| `test_assessment_https_e2e.py` | 1 | Valódi Chromium + Nuclei, SQLite inventory, négy külön CLI-processz, dedup és explicit retest |
| `test_assessment_https_pipeline_failures.py` | 17 | Valódi engine-nel TLS-/429-/budget-hibaágak; külön tiszta policy-kódolási esetek |
| Browser HTTP/HTTPS/proxy | 17 | Valódi Chromium, secure actor-cookie, idegen SPKI elutasítás, raw TCP/TLS framing, idle connection |
| `test_tls_fixture.py` | 6 | Valódi TLS-kézfogás, CA-/hostname-negatív kontrollok, privát fájlok cleanupja |
| Persistent rate limiter | 11 | Valódi SQLite újranyitás, 429 megőrzése, két kapcsolat versenye 1 kéréses keretért |
| Nuclei proxy cleanup fault | 3 | **Transport-double**, valódi listener/TLS-fájl cleanup-kivétel és foglalt binding esetén; nem engine-futás |
| Installer | 6 | **Mock download**, integritás-/overwrite-/race-fault; nem valódi scan vagy telepítés |
| Hunt/native session | 53 | Kontraktus, fake scanner és valódi supervisor/processgroup; nem valódi Nuclei-lelet |

A további scheduler, cache/resource, intelligence-fixture, skill, reproducer és
megőrzött model-picker tesztek a teljes 230-es eredmény részei.
Ruff: sikeres; format check: **53 fájl**; célzott strict mypy:
**8 source fájl, `--follow-imports=silent`**; `pip check`: nincs törött dependency.
Ez Python assessment-integrációs ellenőrzés, nem frontend/Go vagy release-minősítés.

A statikus ellenőrzések tényleges parancsai, a `` mappából:

```bash
.venv/bin/python -m ruff check redjohn/assessment redjohn/tools/hunt tests \
  scripts/install-nuclei-pinned.py scripts/create-nuclei-fixture-lock.py
.venv/bin/python -m ruff format --check redjohn/assessment redjohn/tools/hunt tests \
  scripts/install-nuclei-pinned.py scripts/create-nuclei-fixture-lock.py
.venv/bin/python -m mypy redjohn/assessment/browser.py \
  redjohn/assessment/browser_proxy.py redjohn/assessment/browser_tls.py \
  redjohn/assessment/persistent_rate_limit.py redjohn/assessment/policy.py \
  redjohn/assessment/native_session.py redjohn/tools/hunt/nuclei.py \
  redjohn/tools/hunt/bounded_worker.py --follow-imports=silent
.venv/bin/python -m pip check
```

## Elkülönítetten mért valódi E2E

A teljes tesztkészlet után, más teszt- vagy benchmarkfutással nem párhuzamosan:

```bash
.venv/bin/python -m redjohn.assessment https-demo \
  --output ../redjohn_runs/https-e2e-final
```

Eredmény: **6,138721 s**, négy külön PID, minden exit code 0, minden stderr 0 bájt.

| CLI-processz | Idő (s) | Mintázott process-tree RSS maximum | Legtöbb processz |
|---|---:|---:|---:|
| Chromium HTTPS discovery | 2,021142 | 551 272 448 B / 525,73 MiB | 6 |
| Nuclei a megfigyelt `/api/items` surface-en | 1,552285 | 234 307 584 B | 3 |
| Tartós folytatás / azonos job dedup | 1,020611 | 105 889 792 B | 1 |
| Nuclei explicit fixed-control retest | 1,509683 | 235 077 632 B | 3 |

Összesen **6 valódi upstream HTTPS GET = 6 tartós request charge**:
`/` 1, `/api/me` 1, `/api/search` 1, `/api/items` 3. Újraindítás miatti duplikáció
**0**. Kezdetben **1 candidate**; javított kontrollon **0 új finding**, teljes
200-válasz alapján. A történeti jelölt megmarad; automatikus finding-lezárás nincs.
LLM-hívás és input/output token **0**. A végén aktív resource lease és foglalás 0.

A memória `/bin/ps` alapú, névlegesen 50 ms-onkénti külső mintavétel, a lekérdezés
idejével növekvő intervallummal. A megosztott lapokat többször számolhatja;
mintázott maximum, nem folyamatos heap-/OS-peak. Az E2E konfigurált kerete 2 GiB.
Nem régi/új teljesítmény-összehasonlítás és nem hosszú soak.

[Nyers mérés](measurements/https-e2e-final.json),
[teljes CLI-kimenet](measurements/https-e2e-final-cli.txt),
[JSON riport](../redjohn_runs/https-e2e-final/assessment-report.json),
[HTML riport](../redjohn_runs/https-e2e-final/assessment-report.html).

A szerveroldali secure alice/bob cookie- és upstream TLS-negatív kontrollok
[külön browser-jegyzőkönyvben](redjohn-browser-https-verification.md)
találhatók. A self-signed, rossz CA és hibás hostname kontrolloknál 0 upstream
HTTP-kérés jutott át. 429 után és új runtime-ban sem ment át új scanner-kérés;
a tartós kéréskeret 1 esetén a második job szintén 0 upstream kérést eredményezett.

## Indítás és még hiányzó képességek

A gépen a pinned engine és fixture lock **már elő van készítve**. Másik gépen
csak explicit előkészítés után, a [runbook](redjohn-runbook.md) parancsaival indul.
A normál launch és health nem telepít vagy indít opcionális toolokat.

A jelenlegi HTTPS/scanner határ **literal-loopback, isolated-lab, HTTP/1.1**.
Távoli production/network profile: `blocked_egress_enforcement_unavailable`;
a host-konfiguráció `enforced` szava nem oldja fel. Nincs kernel/network-namespace
enforcement erre a macOS natív workerre. Nincs általános authenticated Nuclei
body-replay, WebSocket/service-worker coverage, reviewzott teljes community
template-csomag, új live cloud/Kubernetes/specialist adapter vagy production
OS-szintű hard RAM-limit. Ezek képességhiányok, nem negatív teszteredmények.

A fixture saját ártalmatlan markerét **valódi engine** vizsgálja. Ez a láncot és
a kontrollt igazolja, nem valódi CVE-/RCE-detektálást. Az eredeti RCE továbbra is
`not_reproduced_missing_fixture`. A teljes master prompt elfogadása részleges.

Módosított/új fájlok és tartalomhashek:
[összesített fájllista](redjohn-changed-files.json),
[ennek a folytatásnak a fájllistája](redjohn-https-nuclei-changed-files.json).
