# RedJohn közös resource-runtime ellenőrzés

2026-10-18. Ez a master prompt még aktív teljes feladatának egy implementált
szakasza. [Teljes hátralévő hatókör](redjohn-completion-status.md),
[angol indítási és konfigurációs leírás](../RedJohn/docs/shared-resources-and-os-memory.md).

Az új kód privát SQLite-ledgerrel koordinálja az aktív assessment-foglalásokat
egymástól független kampányadatbázisok között. A dedikált Linux CLI-controllert
exec előtt kernelcgroupba helyezi, tényleges memory/swap/pids limitekkel.
Processzt birtokló vagy besorolatlan foglalás csak a hozzá kötött processzfa
igazolt megszüntetése után használható újra. A saját, kizárólag a controller
threadjeit/socketjeit használó HTTP/refresh/OAST adaptereknél a capability és az
adapter közösen rögzíti az `owner_process_only` élettartamot; itt a controller
igazolt halála elegendő. A bizonytalan megfigyelés és a lejárt heartbeat nem
indokol törlést. A régi foglalások nem kapnak automatikusan ilyen besorolást.

Kérés előtti, idempotens kapacitáshiány tartós `retry_wait` állapotot és bounded
folytatást kaphat ugyanabban a controllerben. A már admissiont kapott vagy
nem idempotens munka nem ismétlődik automatikusan. A kernel-OOM külön
`resource_exhausted` hiba, inconclusive evidence-szel; nem üres negatív scan.

A célzott új Linux-csomag 20/20 sikeres, 13.75 s. Ezek közül 11 tényleges
processz-/böngésző-/kernel-/CLI-integráció, 9 szintetikus vagy capability-kontraktus.
A két csoportot a tesztfájlok külön jelölik. macOS-en az új 15 ellenőrzés sikeres,
5 kernel-eset explicit capability-skip; a Linux-kör ezeket valóban lefuttatta.

Az első teljes macOS/Linux regresszió hibásan zárult:

| Platform | Sikeres | Hibás | Kihagyott | pytest futásidő |
|---|---:|---:|---:|---:|
| macOS ARM64 | 1079 | 23 | 71 | 688.57 s |
| Ubuntu ARM64 | 1146 | 26 | 1 | 900.99 s |

A strict mypy mindkét platformon 201 production modulon hibamentes. A macOS
[teljes napló](measurements/resource-runtime/macos/tests.txt) és
[JUnit](measurements/resource-runtime/macos/tests.junit.xml) a hibás futás
bizonyítéka; a Linux [teljes napló](measurements/resource-runtime/linux-before-fix/tests.txt)
és [JUnit](measurements/resource-runtime/linux-before-fix/tests.junit.xml) szintén
megmaradt.

A közös ledgerben egy már kilépett CLI worker-foglalása maradt OS-fence nélkül.
Ez későbbi browser/specialista feladatok admissionjét blokkolta. Friss közös
ledgerrel az eredeti OAST-crash teszt, majd a valódi Chromium–Arjun/sqlmap/Dalfox
lánc 1 sikeres / 1 hibás eredményt adott, 17.69 s alatt. A külön új regressziós
E2E a javítás előtt 17.47 s alatt ugyanígy elbukott, utána 17.69 s alatt sikeres:
[előtte](measurements/resource-runtime/regressions/oast-owner-before.junit.xml),
[utána](measurements/resource-runtime/regressions/oast-owner-after.junit.xml).
A javítás az explicit controller-élettartamot rögzíti; a régi/ismeretlen vagy
processzt birtokló foglalások karanténszabálya megmarad. Kapacitásfelszabadítás
nem változtatja ismertté a bizonytalan poll kimenetelét, és nem enged új POST-ot.

A Linux tesztbemenetekbe bekerült a 4 meglévő Viewer statikus fájl és a 35 eredeti
skill-forrás. A javított célzott kör Linuxon 33/33 sikeres, 57.83 s; macOS-en
27 sikeres / 5 Linux-kernelhez kötött kihagyás, 55.60 s. Ebben az új resource-
csomag már 29 eset: 14 tényleges processz-/browser-/kernel-/CLI-integráció és
15 szintetikus vagy capability-kontraktus. A fennmaradó 3 macOS / 4 Linux eset
a korábbi OAST, specialisták, Web View és Linuxon az eredeti skill-provenance
ellenőrzése. [Linux JUnit](measurements/resource-runtime/targeted-linux-fixed/junit.xml),
[macOS JUnit](measurements/resource-runtime/targeted-macos-fixed/junit.xml).

A javított kód teljes regressziója mindkét platformon új, a teljes csomagon
belül közös ledgerrel sikeres:

| Platform | Sikeres | Hibás | Kihagyott | pytest futásidő | Külső processzfa-RSS csúcs |
|---|---:|---:|---:|---:|---:|
| macOS ARM64 / Python 3.13.16 | 1111 | 0 | 71 | 771.82 s | 858013696 B / 818.27 MiB |
| Ubuntu ARM64 / Python 3.12.3 | 1182 | 0 | 0 | 1013.52 s | 1272213504 B / 1213.28 MiB |

[macOS JUnit](measurements/resource-runtime/macos-fixed/tests.junit.xml),
[Linux JUnit](measurements/resource-runtime/linux-fixed/tests.junit.xml),
[macOS memória](measurements/resource-runtime/macos-fixed/memory.json),
[Linux memória](measurements/resource-runtime/linux-fixed/memory.json).
A külső teljes idő 773.30 / 1014.62 s, a minták száma 5828 / 9505,
a megfigyelt legnagyobb processzdarabszám 14 / 18. Egyik platformon sem volt
hiányzó processzfa-minta, hash- vagy forráslista-eltérés. A végén a ledger mindkét
platformon üres, elveszett owner nincs:
[macOS](measurements/resource-runtime/macos-fixed/resources-after.json),
[Linux](measurements/resource-runtime/linux-fixed/resources-after.json).

A 71 macOS-skipből 66 Linux network namespace/egress, 5 delegált Linux cgroup
hiánya miatt szükséges; a Linux-kör mindegyiket lefuttatta. Az 1182 összesített
eset unit-, kontraktus- és valódi integrációs/E2E-teszteket tartalmaz, nem 1182
valódi scanner-E2E-t. A 201 production modul strict mypy ellenőrzése mindkét
platformon sikeres.

Az első hibás futás és ledger megmaradt. A korábbi 1153-as teljes mérés nem
az új kódra végrehajtott regresszió. A különálló
[böngészős mérőprogram](../RedJohn/benchmarks/README.md) nem része a fenti pytest
input-snapshotnak: külön Ruff/mypy és tényleges workload ellenőrzi.

A kezdeti, ütemezés nélküli 100 ciklusos HTTP demo 91.47 s alatt 30 sikeres és
70 origin-admission miatt blokkolt browser-jobot, 120 valódi HTTP-kérést adott.
A cleanup-ellenőrzések sikeresek, de ez nem 100 befejezett crawl és nem pozitív
soak-elfogadás. A [mérési adat](measurements/resource-runtime/browser-pressure-macos.json)
a blokkolást és a bizonyíték hiányát megtartja. Az új HTTPS mérőprogram a meglévő
policy/scheduler használatával, két valódi actor cookie-val, alapértelmezésben
5 másodperces kezdési időközzel tartja tiszteletben az origin-kvótát. A 100
ciklusos, 10 warmup ciklust kizáró mérések mindkét platformon lefutottak:

| Platform | Sikeres browser-job | HTTP-kérés | Teljes idő | Mintavett processzfa-RSS csúcs | p50 / p95 jobidő |
|---|---:|---:|---:|---:|---:|
| macOS | 100/100 | 400 | 496.69 s | 499302400 B / 476.17 MiB | 0.930 / 1.227 s |
| Linux | 100/100 | 400 | 496.39 s | 597155840 B / 569.49 MiB | 0.620 / 0.783 s |

[macOS nyers mérés](measurements/resource-runtime/browser-soak-macos.json),
[Linux nyers mérés](measurements/resource-runtime/browser-soak-linux.json).
A jobidő nem tartalmazza az 5 másodperces pacing várakozását. A forrás a két
actor tényleges cookie-ját a saját HTTPS szerverén megfigyelte. 100/100 page és
context lezárult, aktív proxykapcsolat, cleanup-hiba és host-foglalás nem maradt.
Input/output token és model-call: 0/0/0. A tartós jobok `succeeded / partial`
állapotúak, mert az automatikus mutáló POST-ok tiltása megmaradt; ez nem teljes
webes sebezhetőség-lefedettség vagy negatív scan:
[macOS jobállapot](measurements/resource-runtime/browser-soak-macos-durable.json),
[Linux jobállapot](measurements/resource-runtime/browser-soak-linux-durable.json).

A warmup utáni ciklusmintákban a fixture TCP-listenere végig 1, lezárás után 0.
Linuxon az idle FD-szám 12, lezárás előtt/után a teljes folyamat saját FD-száma
6/6; a mintavett idle processzdarabszám 1. macOS-en az idle FD-tartomány 19–22,
a teljes folyamat lezárás előtti/utáni FD-száma 12/13. A kezdeti/végső két
processz a Python és a sleep-guard `caffeinate`; ezt külön tényleges
[processzdiagnosztika](measurements/resource-runtime/browser-process-caffeinate.json)
azonosította, nem maradt Chromiumként értelmezzük. A megfigyelő rövid életű
`ps`/`lsof` processzei és pipe-jai a köztes mérést befolyásolhatják.

A warmup utáni első/utolsó tíz processzfa-RSS-minta mediánja között macOS-en
5.27 MiB, Linuxon 7.23 MiB emelkedés látszik. Ez megfigyelés, nem bizonyított
Python-heap leak vagy igazolt plateau; az okot hosszabb heap/SQLite-cache és
vegyes workload profilozással kell tisztázni. Nuclei/specialista-soak,
cache-/maximális body/log/queue terhelés nem történt ebben a mérésben.

A standalone mérőprogram Ruff és strict mypy ellenőrzése sikeres, a saját SHA-ja
`a626c29ff81215dbecab0fbf3f1e48461c3327638ceba12ac56e2b7a2a2b3041`.
A két futás a mérőprogramot és mind a 201 RedJohn package-forrást változatlannak
ellenőrizte. 791 / 972 külső minta készült, megfigyelői hiba nem volt.

A kapcsolódó felületellenőrzésben a TypeScript `--noEmit` sikeres, a Vite build
3.04 s alatt elkészült külön ideiglenes könyvtárba. Mind a 4 meglévő statikus
Viewer-fájl byte-ra egyezik az új builddel. A Go TUI 4 csomagja lefordult,
Go-tesztfájl nincs; ez nem TUI-interakciós E2E:
[buildadatok](measurements/resource-runtime/interface-builds.json).

A kezdeti forráslista 354 fájlt, ebből 283 Python-forrást rögzített. A javított
[manifest](measurements/resource-runtime/source-hashes-fixed.json) 396 bemenetet
tartalmaz: 285 Python-forrás, a 4 Viewer statikus fájl, a 35 eredeti skill és
a kapcsolódó konfigurációk/kontraktusok. SHA-256:
`11c1d5a74de5c09aec8a40368d6b8de0bd419a4dd749175a30f8ed1986e52c74`.
A teljes futások előtt és után hash- és forráslista-ellenőrzés történik.
A processzfa-RSS mintavétele külön mérés
a cgroup memory.peak számlálójától. A két platform futása ugyanazon fizikai hoston
részben átfed; az idő- és memóriaértékek workload-mérések, nem izolált platform-
vagy gyorsulási benchmarkok.

A régi interaktív runtime, az idle cache-ek teljes közös kezelése, a teljes
hostot átfogó OS-keret és a hosszú soak még nyitott. macOS-en a Linux kernel-
enforcement továbbra is blokkolt. Az eredeti RCE-fixture hiányzik; státusza
változatlanul `not_reproduced_missing_fixture`.

A 70 korábbi aktív test/support forrás, a 11 telepített host-engine, a Git
HEAD/origin/index és a privát MCP-konfiguráció megőrzését a
[hash-ellenőrzés](measurements/resource-runtime/preservation.json) rögzíti.
A lezárt futások 15 saját generált fixture/debug/staging elemét helyreállíthatóan
a Kukába mozgattam; aktív teszt vagy meglévő projektfájl nem került törlésre:
[takarítás](measurements/resource-runtime/generated-cleanup.json).

## Reprodukáló parancsok

A repository gyökeréből, a már telepített, lockolt motorokkal és Chromiummal:

```sh
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment resources
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment https-demo \
  --output /tmp/redjohn-https-check \
  --nuclei-lock RedJohn/.tools/nuclei/3.11.1/fixture-lock.json
PYTHONPATH=RedJohn .venv/bin/python RedJohn/benchmarks/browser_soak.py \
  --output /tmp/redjohn-browser-soak \
  --cycles 100 --warmup 10 --interval-seconds 5
```

A fixture-kimenetekhez friss könyvtárat használj. A teljes regresszió és külső
RSS-mintavétel változatlan, ténylegesen használt
[archivált forrása](measurements/resource-runtime/full-suite-sampler.py.txt)
azonos SHA-val szerepel mindkét platform `command.json` rekordjában:

```sh
task_verify_dir="$(mktemp -d /tmp/redjohn-verify.XXXXXX)"
PYTHONPATH=RedJohn .venv/bin/python \
  docs/measurements/resource-runtime/full-suite-sampler.py.txt \
  "$task_verify_dir/results" "$task_verify_dir/pytest" \
  docs/measurements/resource-runtime/source-hashes-fixed.json
```

Linuxon ehhez a saját delegált cgroup és a namespace-környezet is kell; a
tényleges környezetváltozók és pytest argumentumok a
[Linux command.json](measurements/resource-runtime/linux-fixed/command.json)
rekordban, a kernel-előkészítés az angol runbookban és a CI-workflowban szerepel.
A helper az eredeti skill-források jelenlétét/hashét is ellenőrzi; ezek
hiányát nem kezeli sikeres eredményként. Ez helyi reprodukció; GitHub CI-futás
ebben a szakaszban nem történt.
