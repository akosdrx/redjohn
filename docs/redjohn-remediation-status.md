# RedJohn javítási állapot — 2026-10-21

Ez a fájl a jelenlegi, commit-azonosított állapot. A korábbi dokumentumokban
szereplő commitok és futásszámok **történeti rekordok**; nem bizonyítják a mostani
forrás állapotát. Aktuális bizonyítékként csak az itt felsorolt, a megadott
commitból előálló eredmények használhatók.

## Kanonikus forrás

- Commit: `9d3de449301532e839d74708604865056232daaf`
- A commit a teljes ``, `.github/`, `docs/` és a szükséges gyökérfájlok
  kanonikus fáját tartalmazza.
- A worktree a commit után tiszta; a `.venv`, `node_modules`, `.tools`, cache-ek
  és runtime adatbázisok nincsenek verziókezelve.
- A javítási branch: `fix/redjohn-hardening-20261021`.

## Helyi ellenőrzések

Környezet: macOS arm64, Python 3.13.16, Node 24.21.0, Go 1.27.1.

| Ellenőrzés | Eredmény |
|---|---|
| `PYTHONPATH=. .venv/bin/python -m pytest tests -q` | **1931 passed, 138 skipped, 0 failed** (17:44) |
| `.github` CI-szerződés tesztek | **61 passed** |
| `npm test` | **14 passed, 0 failed** |
| `npm run build` | sikeres; a commitolt static bundle változatlan |
| `go vet ./...` | sikeres |
| `go test -race -count=1 ./...` | sikeres |
| wheel build | `redjohn_agent-1.7.0-py3-none-macosx_11_0_arm64.whl`, 17 MB, sha256 `3e25351de3439adaef6427b63e2c05e301aec66e3e8ab3177d939054005f416f` |
| `redjohn --version` | `RedJohn 1.7.0` |
| `redjohn assess health` | valódi Playwright Chromium útvonal; `live_verified=false`, mert health nem indít böngészőt |
| `redjohn assess demo --cycles 1` | sikeres; 6 HTTP kérés, 0 modelhívás, 1.12 s |

## Hosted Ubuntu CI — commit `9d3de44`

A teljes `RedJohn Ubuntu validation` futás
[39555197530](https://github.com/akosdrx/redjohn/actions/runs/39555197530)
**mindkét architektúrán success**:

| Platform | Regresszió | Valódi integráció | Frontend | Go |
|---|---:|---:|---:|---:|
| Ubuntu 24.04 x64 / Python 3.13.16 | 1615 passed, 0 failed/skip | 451 passed, 0 failed/skip | 14 passed | 21 passed |
| Ubuntu 24.04 ARM64 / Python 3.12.3 | 1615 passed, 0 failed/skip | 451 passed, 0 failed/skip | 14 passed | 21 passed |

A futás mixed soakja 2 ciklusos volt, nem hosszú soak:

- x64: 83.98 s, minden 16 soak-invariant `true`;
- ARM64: 73.68 s, minden 16 soak-invariant `true`;
- a summary `success=true`, blockers üres.

További commit-azonosított hosted futások:

- natív komponens smoke: [39555197563](https://github.com/akosdrx/redjohn/actions/runs/39555197563) — success;
- offline artifact E2E: [39555197528](https://github.com/akosdrx/redjohn/actions/runs/39555197528) — success;
- controller-memory x64/ARM64: [39559726136](https://github.com/akosdrx/redjohn/actions/runs/39559726136) — success; capability `available=true`, namespace/browser/cgroup elérhető, blockers üres.

## Javított területek

- **P0 forrásintegritás:** a Git-index és a worktree kanonikus `` fája
  szinkronban van; nincs lowercase `redjohn/` duplikáció.
- **P0 CI-bizonyíték:** a `ci.py preflight` és `snapshot` dirty vagy untracked
  forrás esetén non-zero exit; a workflow-k a snapshot előtt preflightot
  futtatnak.
- **P1 telepítés:** az installer a repository gyökér `.venv`-jét használja,
  telepíti a `[browser]` extrát és a Playwright Chromiumot.
- **P1 hunt:** a production runner átadja az `assessment_policy` és
  `resource_governor` kulcsokat; a hunt a service-policyra is fallbackel.
- **P1 browser cleanup:** a browser lease cleanup guardot kap; sikertelen
  Chromium close esetén quarantine marad, nem szabadul fel a kapacitás.
- **P1 viewer:** a `finished` csak akkor igaz, ha nincs több lap és nincs aktív
  job; a lapozott, részleges kampány `running` marad.
- **P1/P2 legacy:** local/non-web cél explicit `--unconfined-legacy` nélkül
  elutasításra kerül; webes cél továbbra is a host-bound policy alatt fut.
- **P2 installer hardening:** nincs alapértelmezett `--no-sandbox`; az npm
  csomagok pontos verziósak, `--ignore-scripts` mellett csak a két reviewed
  postinstall fut.
- **P2 health:** archive nem számít telepített binárisnak; a browser health a
  Playwright cache tényleges Chromium executable-jét ellenőrzi.
- **P2 teszt-besorolás:** a `real_integration` explicit teszt-szintű manifest
  (`.github/scripts/pytest-real-integration.json`), nem fájlszintű címke.
- **P2 retention:** a finding, audit, terminal session/capture/followup és
  unreferenced surface sorok konfigurálható kvótát kaptak; a job/attempt/evidence
  bizonyíték nem törlődik. A report kiírja a retention konfigurációt.
- **P2 vault atomicitás:** a capture/session refresh előbb `.commit-staged`
  fájlba ír, csak a sikeres fenced SQLite commit után aktiválja; hiba esetén a
  staged fájl törlődik, az aktív vault változatlan marad.
- **P3:** a CLI/TUI verzió `1.7.0`; a viewer IPv6 loopback URL-je
  `http://[::1]:port`, a help csak loopback hostokat kínál.

## Nem igazolt / nyitott

- **P2-3 AppArmor:** a szűkített profil kísérlet nem kompatibilis a jelenlegi
  `bwrap`/`unshare` namespace-attestationnel (cross-profile
  `/proc/<pid>/ns/net` hozzáférés). A profil a known-good széles változatra van
  visszaállítva; a globális write és a `sys_admin`/`net_admin` továbbra is jelen
  van. Ez **nyitott**, nem tekinthető javítottnak. Dedikált AppArmor redesign
  szükséges, külön Linux E2E-vel.
- Kali Linux x64/ARM64 telepítés és `assess health` a telepítő után.
- A 2 ciklusos CI soak nem hosszú 120 ciklusos / 1200 s-es soak.
- Élő modelles E2E; a dedikált secret továbbra sem elérhető.
- A `redjohn-live-model` workflow nem futott.

## Történeti dokumentumok

A `docs/redjohn-requirements.md`, `docs/redjohn-completion-status.md`,
`docs/redjohn-resource-closure.md`, `docs/redjohn-controller-memory.md` és a
többi mérési rekord korábbi commitokhoz tartozik. Ezekben a `3cc92d2`,
`fc1f70d`, `fd7c0d41`, `9f3a1a03`, `5cfd51d2`, `fefc3bf9`, `0b978b8` és hasonló
SHA-k **történeti** hivatkozások, nem a `9d3de44` állapotának bizonyítékai.
