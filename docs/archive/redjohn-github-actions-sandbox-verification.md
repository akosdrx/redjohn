# RedJohn: GitHub Actions Chromium- és namespace-javítás

2026-10-18. A teljes natív Ubuntu 24.04 x64/ARM64 mátrix ténylegesen
befejeződött, **success** eredménnyel. Platformonként **1225 sikeres,
0 hibás/error, 0 kihagyott** RedJohn-teszteset. Ebből **320 valódi integráció**.

- Hitelesített GitHub connector-fiók és repository: `akosdrx`, `akosdrx/redjohn`.
- [Lezárt sikeres futás](https://github.com/akosdrx/redjohn/actions/runs/39139076653).
- Tesztelt forrás és tényleges checkout SHA: `57141b25ed32169e24d0065b4bc21a0422e83fab`.
- Forrásfa: `840f2d9c7b954edb0ee1c8f3571ca321e06f9aae`.
- [Tesztelt workflow](https://github.com/akosdrx/redjohn/blob/57141b25ed32169e24d0065b4bc21a0422e83fab/.github/workflows/redjohn-ubuntu.yml).
- [Meglévő draft PR #1](https://github.com/akosdrx/redjohn/pull/1), nincs merge.
- Az ugyanahhoz a headhez automatikusan indult [PR-eseményű ismétlés](https://github.com/akosdrx/redjohn/actions/runs/39139081101) a jegyzőkönyv készítésekor még futott; ezt nem számítom befejezett/sikeres futásnak. A fenti teljes push-mátrix lezárt eredménye az elfogadási bizonyíték.

Ez a jegyzőkönyv és a letöltött bizonyítékok a futás után készültek helyben.
A GitHubon tesztelt commitot nem módosítják. A nyolc implementációs és működési
leíró fájl a tesztelt commit része; a futás eredményét a PR leírása is rögzíti.

## Ok és megoldás

Az alapértelmezett AppArmor-korlátozás a namespace-létrehozást végző folyamatot
az `unprivileged_userns` profilba helyezte. A rövid, valódi reprodukcióban a
bubblewrap `setpcap`/`net_admin`, a Chromium `sys_admin` elutasítást kapott.
A korábbi Actions-futás ugyanilyen bubblewrap `RTM_NEWADDR: Operation not
permitted` és Chromium `TargetClosedError` hibával zárult.

A javítás **név szerinti, executable attachment nélküli, enforcing** CI-profilt
hoz létre, egyedi run/attempt/arch névvel. A jogosult launcher belép a profilba,
majd `setpriv` segítségével eldobja a root UID/GID-t. A probe és a teljes
integrációs folyamatfa az eredeti runner UID-jával fut. A profil mindössze a
UID/GID-váltáshoz és namespace-építéshez szükséges hét capability AppArmor-
engedélyét tartalmazza; host Linux-jogosultságot nem ad: `CapEff`, `CapPrm`,
`CapAmb` mind nulla. Az exec örökli a profilt; nincs `ux`, `px`, profilváltási
engedély vagy unconfined/complain mód. A Pythonhoz, bubblewraphoz és Chromiumhoz
nem keletkezik általános executable-kivétel.

A `kernel.apparmor_restrict_unprivileged_userns=1` végig megmarad. Az
`apparmor_restrict_unprivileged_unconfined` 0-ról **1-re szigorodik**, így egy
közönséges `aa-exec` belépés nem adja meg a CI-profil namespace-jogosultságát.
A policy- és sysctl-írások, valamint a profilból kilépés külön tiltottak.
A CI-profil az engedélyezett tesztfolyamatfára vonatkozik, nem terméktelepítési
vagy többfelhasználós hostprofil. A működés alapja az Ubuntu dokumentált
[alkalmazásszintű userns-engedélyezése](https://documentation.ubuntu.com/security/security-features/privilege-restriction/apparmor/)
és a [nem jogosult profilváltás korlátozása](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007).

A RedJohn egress-kódja, privát mountjai, proxyjához kötött Unix-relayje,
`--cap-drop ALL`, `no_new_privs`, TLS-ellenőrzése, Chromium-sandboxa és meglévő
memóriakeretei változatlanok. Nincs `--no-sandbox`, setuid helper, host-network
fallback vagy megemelt alkalmazás-memóriakeret.

## Valódi védelmi kontrollok mindkét runneren

- Runner UID **1001**, enforcing profil; effektív, permitted és ambient host capability **0**.
- Privát user/mount/PID/network namespace, csak `lo` interfész, effektív worker capability **0**, `no_new_privileges=true`.
- Profil nélküli `unshare -Urn true`: tényleges elutasítás.
- Nem jogosult `aa-exec` + `unshare -Urn true`: tényleges elutasítás.
- A CI-profilból `unconfined` profilba kilépés: tényleges elutasítás.
- Új user/network namespace-ben létrehozott raw socket: tényleges elutasítás.
- `chrome://sandbox`: PID namespace **Yes**, network namespace **Yes**, seccomp-BPF **Yes**, TSYNC **Yes**. A tiltott sandboxkikapcsoló argumentumok hiányoznak.
- A végső saját cgroup eltávolítva, túlélő processz nincs. A profil eltávolítása előtt `active_profile_pids=[]`; mindkét globális korlátozás a futás végén is **1**. Aktív profilprocessz esetén a cleanup megtagadja a profil eltávolítását, és a kapu hibát jelez.

A hiányzó képességet vagy kötelező skipet elutasító összesítő változatlanul
szigorú, és most a policy cleanup-bizonyítékát is megköveteli.

## Teljes teszteredmény és tényleges mérések

| Platform | Regresszió | Valódi integráció | Hibás/error | Skip | Regresszió külső idő | Integráció külső idő | RSS-csúcs regresszió / integráció |
|---|---:|---:|---:|---:|---:|---:|---:|
| Ubuntu 24.04 x64, Python 3.13.16 | 905 | 320 | 0 | 0 | 59.24 s | 1012.81 s | 367.69 / 1341.08 MiB |
| Ubuntu 24.04 ARM64, Python 3.12.3 | 905 | 320 | 0 | 0 | 63.42 s | 1182.99 s | 294.41 / 1355.73 MiB |

A regressziós csoport platformonként **167 mock contract** és **738 unit/
contract/mixed** eset; ezek különböznek a 320 `real_integration` esettől.
Hét további CI-kontraktusteszt is sikeres platformonként, a fenti 1225-ön kívül.
Ugyanez a hét lokálisan 0.325 s alatt sikeres; a shellszkriptek szintaktikai
ellenőrzése sikeres. Hosszú helyi Linux/macOS-regresszió nem indult.

Mindkét platformon sikeres: Ruff, strict mypy **204 production modullal**, pip
check, TypeScript typecheck, Vite build, Go vet, `go test -race`, Go TUI build
és a meglévő packaging hookkal készített Python-wheel. A jelenlegi Go-forrásban
nincs `*_test.go`: **0 Go tesztfüggvény**, amit az összesítő külön rögzít.
Ez nem interaktív Go TUI E2E. Külön frontend JS unit suite nincs definiálva;
a Viewer **6 valódi Chromium-tesztje** mindkét platformon sikeres.

Az RSS külső `/proc` processzfa-összeg, 200 ms mintavételi szünettel. Közös
lapokat többször számolhat, nem PSS vagy kernel hardlimit. A teljes integráció
megfigyelt maximális processzszáma mindkét architektúrán **19**; nincs
megfigyelt túlélő leszármazott. A 4 GiB-os host-admission budget szoftveres
korlát, nem globális host-memory garancia. A külön opt-in Linux cgroup-boundary
valódi 64 MiB kernelkontrollját az OOM-esetek igazolják.

Chromium: x64 **145.0.7632.6**, ARM64 **145.0.7632.0**; Playwright **1.58.0**.
Mindkét kernel **6.17.0-1022-azure**, Ubuntu 24.04/glibc 2.39. A runner-image
verziója, minden dependency és minden installer-receipt az artifactokban van.

## Valódi integrációk

Mindkét platformon lefutott a Chromium–inventory–Nuclei HTTPS-lánc:
`inventory_source=observed`, pozitív jelölt **1**, javított kontroll új találat
**0**, restart utáni duplikált kérés **0**, model call **0**. A fixture marker
jelölt, nem megerősített valós sérülékenység. Az autentikált JSON/form/multipart
replay mindhárom formátuma külön **1/0** marker/fixed kontrollt adott.

Sikeres az automatikus browser POST-capture, body-token/session refresh,
újraindítás nélküli új capture/replay, tartós scheduler és restart/deadline/
cancel/crash recovery. A native modulok között 46 MIME-replay, 45 autentikált
schema/OAST, 23 recovery, 41 ProjectDiscovery, 25 specialist, 32 schema/OAST,
17 HTTPS failure-boundary és 6 kernel-memory eset van. A teljes, diszjunkt
modulonkénti lista az `independent-verification.json` fájlokban szerepel.

Mind a 11 ellenőrzött engine: **Nuclei 3.11.1, ffuf 2.1.0, httpx 1.12.0,
Katana 1.8.0, VulnX 2.0.2, Arjun 2.2.7, sqlmap 1.10.10, Dalfox 3.2.4,
TInjA 1.2.0, Schemathesis 4.31.1, Interactsh-server 1.4.1**. Kontrollált saját
helyi HTTP/HTTPS-célokat és saját OAST receivert használnak. A VulnX külön
publikus CVE-metaadat lekérése is ténylegesen sikeres; ez nem külső cél scan.

Nuclei bináris SHA-256:

- x64: `c49588140f357cbdddd5436dec11201953a4c5390faeec90777f9ee2cfd70251`
- ARM64: `f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477`

A kernel-OOM kontrollban mindkét platformon `memory.max=67108864`,
`memory.swap.max=0`, `pids.max=512`, és a memory peak **67108864 B**.
A controller esetben **2**, a descendant esetben **3** valódi OOM-kill történt.
Az orphan kontrollban lost owner **1 → 0**, `orphan_stopped=true`, végső
foglalás **0**. A scheduler kapacitás-visszaadása tényleges cleanupot követett.

## Módosított fájlok, indítás és megőrzés

| Fájl | Változás |
|---|---|
| `.github/workflows/redjohn-ubuntu.yml` | AppArmor eszközök, saját policy setup/probe/cleanup a meglévő natív mátrixban |
| `.github/policies/redjohn-ci.apparmor` | Új, nem executable-höz kapcsolt enforcing policy, szűk capability-listával |
| `.github/scripts/sandbox.py` | Policy-életciklus, globális tiltások ellenőrzése, valódi negatív kontrollok, biztonságos cleanup |
| `.github/scripts/linux-tests.sh` | Jogosult profilbelépés után eredeti UID/GID; ugyanaz a profil a probe és a teljes integráció alatt |
| `.github/scripts/capabilities.py` | Valódi profil/capability, escape/raw-socket, namespace, cgroup és Chromium sandbox ellenőrzés |
| `.github/scripts/ci.py` | Setup/cleanup-parancsok és policy cleanup kötelező bizonyíték |
| `.github/tests/test_ci.py` | A meglévő pozitív CI-fixture teljes policy cleanup-bizonyítéka; assertion nincs lazítva |
| `docs/redjohn-github-actions.md` | Angol működési és biztonsági leírás |
| `docs/redjohn-github-actions-sandbox-verification.md` | Ez a tényleges futási jegyzőkönyv |
| `docs/redjohn-github-actions-verification.md`, `docs/redjohn-completion-status.md` | A korábbi blokkolás történeti eredményként megjelölve, hivatkozás a javításra |
| `docs/measurements/github-actions-sandbox/` | JUnit, teljes build/tesztnaplók, verziók, mérések, hash- és megőrzési bizonyítékok |

Kézi indítás a GitHub Actions felületén, `codex/redjohn-ubuntu-actions` ággal.
Helyesen `akosdrx`-ként hitelesített CLI esetén:

```sh
gh workflow run redjohn-ubuntu.yml --repo akosdrx/redjohn --ref codex/redjohn-ubuntu-actions
gh run watch RUN_ID --repo akosdrx/redjohn --exit-status
gh run download RUN_ID --repo akosdrx/redjohn --dir /tmp/redjohn-ci-results
```

A helyi `gh` fiókját nem módosítottam. A GitHub-műveletek a hitelesített
`akosdrx` connectorral, az eredeti PR-ágra, expected-SHA védelemmel mentek.
Nincs helyi RedJohn-commit/stage/reset/clean/branchváltás, force push vagy másik aktív
fejlesztési ág felülírása. A RedJohn alkalmazásforrások, mind a **83** aktív
Python teszt/support fájl, a HEAD/index és a privát MCP-konfiguráció változatlan.
A publikálás nyolc célzott fájljának titokminta-ellenőrzése 0 találatot adott.
Helyi env, adatbázis, scannerbináris, cache vagy más projekt nem került fel.

Colimában csak rövid hiba- és képességreprodukciók futottak. A saját próbák
eredményei mentve; a VM eredeti 0/0 namespace/profilváltási sysctl-beállításai
a próbák után visszaállítva, a korábbi sandboxolt Chromium/namespace-indítás
ismét működik. A VM, eredeti runtime, projekt és régi teljes mérési eredmények
megmaradtak. Az Actions-mérések végig a külön rögzített **1/1** beállításokat
használják.

## Bizonyítékok és fennmaradó határok

- [Gépi összesítő](measurements/github-actions-sandbox/verification-summary.json), [megőrzés](measurements/github-actions-sandbox/preservation.json), [artifact-digestek](measurements/github-actions-sandbox/artifacts.json).
- [x64 JUnit](measurements/github-actions-sandbox/ubuntu-x64/integration.junit.xml), [ARM64 JUnit](measurements/github-actions-sandbox/ubuntu-arm64/integration.junit.xml).
- [x64 független ellenőrzés](measurements/github-actions-sandbox/ubuntu-x64/independent-verification.json), [ARM64 független ellenőrzés](measurements/github-actions-sandbox/ubuntu-arm64/independent-verification.json).
- [x64 teljes jobnapló](measurements/github-actions-sandbox/ubuntu-x64/github-job.log), [ARM64 teljes jobnapló](measurements/github-actions-sandbox/ubuntu-arm64/github-job.log).
- [x64 védelmi kontrollok](measurements/github-actions-sandbox/ubuntu-x64/capabilities.json), [ARM64 védelmi kontrollok](measurements/github-actions-sandbox/ubuntu-arm64/capabilities.json).

Az önálló [hash/JUnit ellenőrző](measurements/github-actions-sandbox/verify-artifacts.py) újra futtatható a kiválasztott artifact-könyvtárral; nem indít scannert vagy regressziót.

Mindkét platformon **609** bemeneti forráshash és **206** indexelt bizonyítékfájl
hash-e külön ellenőrizve. A letöltött ZIP-ek SHA-256 értékei egyeznek a GitHub
digestjeivel. Az artifactok 14 napig maradnak GitHubon; a letöltött bizonyítékok
helyben megmaradnak. A következtetések ehhez a konkrét SHA-hoz és runhoz kötöttek.

Ebben a teljes Ubuntu-gyűjteményben nincs blokkolt runnerképesség vagy skip.
A böngésző meglévő coverage-határai (például blokkolt WebSocket/service worker,
explicit POST-engedélyezés) megmaradtak. A saját HTTP(S) OAST receiver nem
bizonyít publikus DNS/SMTP/IPv6 OAST-lefedettséget. Éles LLM/OAuth/cloud/provider
hitelesítést ez a credential nélküli CI-kör nem igazol. A teljes master prompt
tágabb termék- és kiadási backlogja külön követelmény marad.
