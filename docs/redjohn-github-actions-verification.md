# RedJohn GitHub Actions ellenőrzés

> Történeti jegyzőkönyv a `39136007758` futásról. A Chromium/namespace-blokkolás
> később javítva: a [teljes x64/ARM64 újramérés](redjohn-github-actions-sandbox-verification.md)
> a `57141b25ed32169e24d0065b4bc21a0422e83fab` committal platformonként
> 1225 pass / 0 fail / 0 skip, a `39139076653` futás lezárt státusza success.

2026-10-18. A végső tényleges futás befejeződött, **failure** státusszal.
A CI áthelyezése implementált és kipróbált; a teljes Chromium–inventory–Nuclei
és több scanner E2E elfogadása a GitHub-hosted runner képességein blokkolt.
Ez nem sikeres teljes Linux-integrációs csomag és nem negatív sérülékenységvizsgálat.

- Repository és hitelesített connector-fiók: `akosdrx/redjohn`, illetve `akosdrx`; admin/push/pull hozzáférés ténylegesen ellenőrizve.
- [Workflow](https://github.com/akosdrx/redjohn/blob/e9c1adaf4d323599785dbdd65cd83d27ada775f3/.github/workflows/redjohn-ubuntu.yml)
- [Tényleges, lezárt futás](https://github.com/akosdrx/redjohn/actions/runs/39136007758)
- [Draft PR #1](https://github.com/akosdrx/redjohn/pull/1), nincs merge.
- Forrás/head commit: `e9c1adaf4d323599785dbdd65cd83d27ada775f3`.
- Ténylegesen checkoutolt PR merge commit: `0b7e1bbb03069eb7e59e6e3522b4cfe3afbcddf7`.
- Forrásfa: `70abdfcc9ed0d4783c9d592e701f8f1188e907f4`.

Mindkét artifactban a 607 eredeti forrásfájl SHA-256 értéke egyezik a publikált
head pillanatképével. Mindkét evidence-index 61 bizonyítékfájljának hash-e külön
ellenőrizve. A letöltött ZIP-ek hash-e is egyezik a GitHub artifact digestjével.
Az artifactok 14 napig maradnak GitHubon; a letöltött eredmények itt megmaradnak.
A tesztazonosság a checkoutolt bemenetekre vonatkozik; a frontend build saját
kimeneti asseteket készít, nem állítok minden buildkimenetre változatlanságot.

## Tényleges eredmények

A RedJohn pytest-gyűjtemény 1225 esete mindkét architektúrán szerepel a két
külön JUnitban. Nincs teszttörlés vagy módosított alkalmazás-assertion.

| Platform | Regresszió sikeres | Valódi integráció sikeres | Hibás/error | Kihagyott integráció | Regresszió külső idő | Integráció külső idő | RSS-csúcs regresszió / integráció |
|---|---:|---:|---:|---:|---:|---:|---:|
| Ubuntu 24.04 x64 | 905 | 20 | 0 | 300 | 59.85 s | 23.52 s | 365.16 / 352.90 MiB |
| Ubuntu 24.04 arm64 | 905 | 20 | 0 | 300 | 63.00 s | 25.47 s | 302.28 / 290.88 MiB |

Platformonként összesen **925 sikeres, 0 hibás, 300 kihagyott**.
A 905 regressziós esetből 167 `mock_contract`, 738 `unit_contract_or_mixed`;
a további 20 eset `real_integration`. A vegyes csoport helyi valódi komponenseket
is használhat, de nem számítom native scanner E2E-nek. A CI saját hét
kontraktustesztje mindkét platformon külön sikeres, nincs benne az 1225-ben.

Mindkét platformon sikeres: production Ruff, strict mypy 204 modullal, `pip check`,
TypeScript typecheck, valódi Vite build, Go vet, Go fordítás és a meglévő
Hatchling hookkal készített saját Python-wheel. A `go test -race -json ./...`
négy csomagot ellenőrzött, de az aktuális forrásban nincs `*_test.go`:
**0 Go tesztfüggvény**. Ez nem sikeres Go unit suite vagy interaktív TUI E2E.
A frontend package nem definiál külön JS tesztparancsot; a Viewer böngészős
ellenőrzése a képességkapu miatt kimaradt integrációk között van.

Az RSS külső `/proc` processzfa-összeg, 200 ms mintavételi szünettel és olvasási
többletidővel; a közös lapokat többször számolhatja. Nem hard memórialimit.
A kihagyott 300 eset miatt ez nem hasonlítható gyorsulási benchmarkként a korábbi,
Colimában mind az 1225 esetet lefuttató körhöz.

## Valódi integrációs bizonyíték

A 20 sikeres natív eset mindkét architektúrán:

- 14 valódi Nuclei/HTTPS/replay eset: marker/fixed kontroll, szigorú CA-/hostname-ellenőrzés, 401/403/429 szemantika, névhez kötött autentikáció, POST JSON/form/multipart, redaction/protokollszó regressziók.
- 3 valódi tartós scheduler/HTTPS lifecycle eset: cancel, deadline és másik processz coordinator-lockjának elengedése után újraindítás nélküli folytatás.
- 3 valódi kernel-eset: controller és leszármazott 64 MiB `memory.max` mellett OOM, valamint elárvult processz leállítása kapacitás-visszanyerés előtt.

Nuclei **3.11.1**, pozitív/javított kontroll **1/0** mindkét platformon.
A JSON, form és multipart formátumok mindegyike külön marker/fixed 1/0 kontrollt
adott valódi saját HTTPS-célon. A 401/403/429 és hibás TLS nem negatív finding.

| Architektúra | Valódi Nuclei bináris SHA-256 |
|---|---|
| x64 | `c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251` |
| ARM64 | `f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477` |

A kernelmérésben `memory.max=67108864`, `memory.swap.max=0`, `pids.max=512`.
Mindkét OOM-esetnél a memory peak 67108864 B, az OOM-kill számláló ténylegesen
nőtt; az owner-crash tesztben a lost owner 1-ről 0-ra ment az orphan leállítása
után. A végső saját CI-cgroup eltávolítva, túlélő processz nincs; valamennyi
rögzített parancsnál üres a sampler által látott túlélő-leszármazott lista.
Ez a saját tesztcsoportokra vonatkozik, nem általános host-memory garancia.

## Mi blokkolt

Mindkét GitHub-hosted VM-en `apparmor_restrict_unprivileged_userns=1` mellett
a valódi bwrap attestation hibája:

```text
blocked_namespace_attestation_failed:bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted
```

A `chromium_sandbox=True` indítás külön `TargetClosedError`; a namespace és a
sandboxolt Chromium képessége egyaránt hiányzik a kipróbált runnerképen.
A delegált cgroup működik. AppArmor/sysctl kikapcsolás, `--no-sandbox`, TLS-lazítás,
remote → local egress fallback és alkalmazás-memóriakeret-emelés nem történt.

A CI integrációs profilja a kapcsolódó browser-/namespace-csoportokat
képességkapuval kihagyja; a külön felülvizsgált, támogatott native loopback
Nuclei és kernel-only esetek tovább futnak. A 300 kihagyott eset tételesen a
JUnitban és a summaryban van. Nem állítom, hogy valamennyi kihagyott alteszt
önállóan is technikailag futtathatatlan: a kapu konzervatív csoportszintű feltétel.
A teljes Chromium–inventory–Nuclei, browser/session-refresh és a további
scanner-láncok ezen CI-körben **nem igazoltak**. A strict összesítő a 300 skip és
a hiányzó runnerképesség miatt bukik; nincs zöldre változtatott hiány.

## Változások, indítás, megőrzés

- `.github/workflows/redjohn-ubuntu.yml`: push/PR/manual mátrix, natív Ubuntu 24.04 x64 és ARM64; a régi `redjohn-remote-egress.yml` helyébe lép.
- `.github/requirements-ci.lock`: 104 rögzített Python dependency, a meglévő projektkövetelmények teljes szükséges closure-ja.
- `.github/scripts/ci.py`: commit-kötött parancsnapló, RSS, JUnit/Go összesítés, evidence-index és elutasító végső kapu.
- `.github/scripts/pytest_evidence.py`: két diszjunkt pytest-csoport, mock/vegyes/valódi címkék, explicit képesség-skip.
- `.github/scripts/capabilities.py`: valódi kernel-/Chromium-/cgroup-probe.
- `.github/scripts/linux-tests.sh`, `prepare-linux.sh`, `cleanup-linux.sh`: dedikált cgroupok, root eldobása exec előtt, igazolt saját cleanup.
- `.github/scripts/install-scanners.sh`: meglévő ellenőrzött pinelt installerek soros futtatása, verziók/receiptek.
- `.github/scripts/prepare-snapshot.py`: explicit publikálási fájllista és titokminta-vizsgálat Git-index módosítása nélkül.
- `.github/tests/test_ci.py`: hét CI-kontraktus, köztük skip/missing evidence/eltérő commit elutasítása.
- `.github/fixtures/skill-source/`: 35 eredeti, változatlan provenance-dokumentum és manifest; az angol runtime skillek változatlanok.
- `.gitignore`: az új CI artifact/state könyvtárak kizárása.
- `docs/redjohn-github-actions.md`, ez a jegyzőkönyv és `docs/measurements/github-actions/`: futtatási leírás és valódi bizonyíték.

A workflow teljesen pinelt Actions SHA-kat, pip/npm/Go/Chromium cache-t,
90 perces job-timeoutot és parancsonkénti időkorlátot használ. Mátrixonként legfeljebb két
job indul egyszerre; új commit nem szakít meg aktív futást. Az opcionális
scanner-installerek sorosak. A Python minor x64-en 3.13.16, ARM64-en 3.12.3,
a már ellenőrzött Schemathesis wheel lockoknak megfelelően; Node 22.14.0,
Go 1.25.1, Playwright 1.58.0.

A repository a feladat elején üres volt. A 607 fájlos, 6921891 B-os forráspillanatkép
átvizsgálása nem talált titokmintát; `.env`, helyi virtualenv, node_modules,
scanner-binárisok, adatbázisok, régi mérési adatok és más helyi projektek nem
kerültek fel. Ez explicit fájlválasztás és mintavizsgálat, nem univerzális
secret-detection garancia. A mainen csak a repository bootstrap/manual selector
van; a tényleges forrás és CI a draft PR-ban, külön ágon maradt.

Kézi indítás GitHub UI-ból: Actions → RedJohn Ubuntu validation → Run workflow,
ág: `codex/redjohn-ubuntu-actions`. Helyes `akosdrx` CLI-bejelentkezés mellett:

```sh
gh workflow run redjohn-ubuntu.yml --repo akosdrx/redjohn --ref codex/redjohn-ubuntu-actions
gh run watch RUN_ID --repo akosdrx/redjohn --exit-status
gh run download RUN_ID --repo akosdrx/redjohn --dir /tmp/redjohn-ci-results
```

A helyi `gh` továbbra is `itsolutionshu`; nem módosítottam. A publikálás és
Actions-követés a ténylegesen `akosdrx`-ként hitelesített GitHub connectorral
ment. Nincs szükség chatbe küldött tokenre.

A 83 meglévő aktív Python teszt/support fájl és valamennyi kiinduló RedJohn
alkalmazásforrás byte-azonos. Helyi HEAD/index/origin változatlan; helyi commit,
stage, reset, clean vagy push nem történt. A forrás GitHubon külön ágon készült,
force push és másik fejlesztési ág felülírása nélkül.

Colimában csak egy saját launcher-hibakereső teszt futott: 1 pass, 0.448 s külső
idő, 36945920 B processzfa-RSS-csúcs, nincs túlélő processz. Ez nem scanner E2E
és nem teljes Ubuntu-regresszió. A korábbi futás eredményei mentve/megőrizve;
a meglévő VM, runtime és projekt nem lett leállítva vagy törölve.

## Bizonyítékok

- [Gépi összesítő](measurements/github-actions/verification-summary.json)
- [x64 regressziós JUnit](measurements/github-actions/ubuntu-x64/regression.junit.xml), [integrációs JUnit](measurements/github-actions/ubuntu-x64/integration.junit.xml)
- [ARM64 regressziós JUnit](measurements/github-actions/ubuntu-arm64/regression.junit.xml), [integrációs JUnit](measurements/github-actions/ubuntu-arm64/integration.junit.xml)
- [x64 teljes jobnapló](measurements/github-actions/ubuntu-x64/github-job.log), [ARM64 teljes jobnapló](measurements/github-actions/ubuntu-arm64/github-job.log)
- [x64 végső kapu](measurements/github-actions/ubuntu-x64/summary.json), [ARM64 végső kapu](measurements/github-actions/ubuntu-arm64/summary.json)
- [Megőrzési ellenőrzés](measurements/github-actions/preservation.json)
- [Egyetlen célzott launcher-próba](measurements/github-actions/launcher-probe/python-regression.json)

A korábbi CI-hibák naplói külön megmaradtak. A summary-kontraktus, a saját
Python-wheel relatív útja, a közös cgroup-charge és a sudo által kiszűrt
PYTHONPATH hibája a CI-bekötésben javítva; nem a RedJohn tesztjeinek lazításával.
