# RedJohn: a 69 mypy-hiba javítása és teljes újraellenőrzés

Ellenőrizve: 2026-10-17. A jelenlegi, hash szerint egyező forráson végzett
macOS ARM64 és eldobható Ubuntu 24.04 ARM64 futások eredményei.

## Javítás

A teljes strict mypy eredménye **69 hibáról 0 hibára** változott, mindkét
platformon **186 forrásmodul** ellenőrzésével. A `pyproject.toml` változatlan;
nincs új mypy-kizárás vagy `type: ignore`. Linuxon a cache-t mellőző
`--no-incremental` futás is sikeres, **19,640 s** alatt.

A változás 15 Python-modult érint. A vegyes JSON-válaszok és metrikák konténerei
pontos konténertípust kaptak; TypedDict írja le a fixture-cookie/storage-state,
folyamatmérés és normalizált hibareferenciák mezőit. A hiányzó provider és a
cache-ből érkező objektum típusa használat előtt ellenőrzött. A TLS-fixture
dinamikus handler-leszármaztatását típusos GET-megfigyelő callback váltja fel.
A tanúsítvány KeyUsage flagjei érvényes bool értékek; a CA/hostname-ellenőrzés
és a workerhálózati szabályok megmaradtak. A lokális SDK-környezet szótárát
megfelelően típusozható másolattal adjuk át. Egy már megszűrt, szinkron lista
feldolgozásából kikerült a redundáns második típusellenőrzés.

Két hiba tényleges Viewer API-hibát is okozott:

- `/api/skills`: a nem létező `get_available_skills_for_prompt` helyett a
  működő natív `get_available_skills` adja a katalógust;
- `/api/config`: a `model_name` válaszmező értéke a valódi `settings.llm.model`.

A két új HTTP-regresszió a javítás előtt valóban elbukott, utána mindkettő
sikeres. Valódi helyi HTTP-szerverrel ellenőrzik az engedély nélküli 403-at,
a bootstrap/cookie jogosultságát és az engedélyezett 200-as JSON-választ.
A helyi account-előkészítés helyettesített, a statikus index saját fixture;
a HTTP-hívás, cookie és végpontkezelő tényleges. Nincs éles modell/API-hívás.
[Javítás előtti hiba](measurements/mypy-fix-viewer-before.txt).

A CI munkafolyamatába teljes strict mypy-lépés került, és a minimális teszt-
telepítés a valós futáshoz szükséges, verziózott meglévő függőségeket is kapja:
Caido SDK, LiteLLM, yarl, CVSS és Docker Python SDK. A GitHub Actions futást
nem indítottuk el; a tényleges ellenőrzés saját helyi Linux VM-ben történt.

## Lefuttatott ellenőrzések

| Ellenőrzés | Végleges eredmény |
|---|---|
| Teljes strict mypy macOS | **0 hiba, 186 modul**, Python 3.13.16 |
| Teljes strict mypy Linux, cache nélkül | **0 hiba, 186 modul, 19,640 s**, Python 3.12.3 |
| Teljes Python-csomag macOS | **650 passed / 14 skipped, 106,60 s**, 664 eset |
| Teljes Python-csomag Linux | **664 passed / 0 skipped, 178,77 s**, 664 eset |
| Célzott Viewer/TLS/intelligence/control regresszió | **49 passed, 4,02 s** |
| Ruff teljes forrás/scripts/tests | **sikeres** |
| Módosított Python-fájlok formázása | **16 fájl sikeres**, az új teszttel együtt |
| Frontend TypeScript + unused | **sikeres** |
| Viewer build | **2260 modul, 2,74 s**; meglévő 500 kB chunk-figyelmeztetés |
| Go TUI fordítás és vet | **4 package sikeres**; a csomagokban nincs Go-tesztfájl |

A macOS-en kihagyott három kernel-namespace és tizenegy remote browser/auth/
replay eset **mind ténylegesen lefutott Linuxon**. A 664 teszteset azonos mindkét
platformon; a korábbi 662 eset megmaradt, kettő új került melléjük. A teljes
csomag mock- és kontraktusteszteket is tartalmaz; az alábbi E2E-mérések ettől
elkülönített valódi integrációk.

Az első minimális Linux-környezetből hiányzó Caido SDK miatt négy MCP/CLI-teszt
elbukott, miközben a browser/Nuclei E2E-k már sikeresek voltak. A projektben
már deklarált SDK telepítése és a CI lista javítása után a **teljes** csomagot
újrafuttattuk. A fenti 664/0/0 a végleges, tiszta eredmény.
[Kezdeti környezeti hiba](measurements/mypy-fix-linux/initial-environment-failure.json).

## Valódi Chromium / HTTPS / Nuclei E2E

Playwright **1.58.0**, Chromium **145.0.7632.0**, Nuclei **3.11.1**, bubblewrap
**0.9.0**, Linux kernel **6.8.0-117**, Ubuntu 24.04 ARM64. Az engine SHA-256:
`f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477`.
MIT, upstream commit `a8c88feb4a1c8e961b7902534ce3af97e9d524a4`; az explicit
telepítő az archive/checksum/licenc pinjeit ellenőrizte. A host meglévő
Nuclei-telepítését nem módosítottuk.

Az automatikus session-helyreállítás hét esete saját nem-loopback HTTPS-fixture,
tényleges Chromium és engine, valamint kernel-attesztált worker namespace mellett:

| Eset | Workload idő | HTTPS-kérés | Refresh | Friss Nuclei marker-candidate |
|---|---:|---:|---:|---:|
| Browser GET 401 | 5,133 s | 9 | 1 | 3 |
| Browser POST-capture 401 | 5,113 s | 10 | 1 | 3 |
| Scanner 401 | 3,985 s | 13 | 1 | 3 |
| Lejárt scanner-binding | 3,476 s | 12 | 1 | 3 |
| Lejárt privát vault | 2,633 s | 8 | 1 | 3 |
| Ismételt 401 | 5,310 s | 3 | 1 | **nem futott: budget blokkolta** |
| Csonkolt 401-válasz | 2,696 s | 2 | 0 | **nem futott: inconclusive** |

Összesen **57 HTTPS-kérés, 6 refresh, 15 marker-candidate**, **28,346 s** összesített
workload-idő. Végig ugyanaz a controller/runtime marad; újraindítás és kézi
gyermekjob-beküldés nélkül folytatódik a refresh → új capture → kijelölt replay.
Az ismételt batch/újranyitás 0 duplikált kérést okozott. Legfeljebb egy worker-
lease volt aktív, és 0 mintában fedte egymást a browser és a scanner. A két
blokkolt/inconclusive eset nem negatív sérülékenységteszt. A marker-találatok
tesztbizonyítékok, nem igazolt CVE- vagy RCE-találatok; modellhívás 0.

A hét esetben a mintavételezett processfa összegzett RSS maximuma
**1 068 765 184 byte = 1019,25 MiB**, 1123 mintából. A célköz 25 ms, a legnagyobb
megfigyelt köz 89,893 ms. Megosztott lapok többször számolódhatnak; ez
mintavételezett mérés, nem abszolút csúcs vagy OS hard-limit.

További külön mérések ugyanebben a végleges teljes futásban:

| Lánc | Idő | HTTP(S)-kérés | Candidate / javított kontroll új finding |
|---|---:|---:|---:|
| HTTPS browser → inventory → scanner, külön CLI-k | 5,082 s | 6 | 1 / **0** |
| Távoli hitelesített GET/HEAD és restart | 3,876 s | 6 | 1 / **0** |
| JSON/form/multipart POST + session refresh, külön CLI-k | 15,406 s | 11 | 4 / **0** |
| Automatikus browser POST-capture és body-token rotáció | 23,444 s | 19 | 6 / **0** |
| Folyamatos refresh → új capture → replay, egy runtime | 6,306 s | 18 | 6 / **0** |

Minden sorban 0 restart-duplikáció és 0 modellhívás. A javított kontrolloknál
tényleges teljes válasz és hiányzó marker igazolja a lezárt negatív ellenőrzést.
A tesztekben szándékosan hiányzó lockkal/adaptérrel ellenőrzött capability-ágak
megmaradtak, elkülönülnek a fenti tényleges engine-futásoktól. A valódi helyi
MCP stdio-hívás/engedélylista/leállítás regressziója is sikeres lett.

## Megőrzés, környezet és bizonyítékok

Mind az **53 korábbi aktív teszt/segédfájl byte szerint változatlan**. A natív
CVE- és Nuclei-adapter, az általános MCP-kód, a skillek/manifest, a master prompt,
HEAD és index megmaradt. Az MCP-konfiguráció változatlan, a kivett alapértelmezések
nem jelentek meg újra. [Megőrzési ellenőrzés](measurements/mypy-fix-preservation.json).

A VM 2 CPU/4 GiB memóriával, host-mount és SSH-agent továbbítás nélkül futott.
A 318 kiválasztott forrásfájl minden hash-e egyezett előtte és utána. A 35 eredeti,
felhasználói skillforrást csak a provenance-teszt céljából tükröztük a VM-be;
ezek nem kerültek vissza a RedJohn angol skilljeinek helyére. A VM és adatai az
eredmények mentése után törölve. A saját ideiglenes állományok visszaállítható
takarítása külön rögzített; aktív tesztet nem töröltünk.

[Összesítő](measurements/mypy-fix-verification-summary.json),
[Linux JUnit](measurements/mypy-fix-linux/linux-tests.junit.xml),
[Linux stdout](measurements/mypy-fix-linux/linux-tests.txt),
[macOS JUnit](measurements/mypy-fix-macos.junit.xml),
[macOS stdout](measurements/mypy-fix-macos-tests.txt),
[valódi automatikus recovery E2E](measurements/mypy-fix-linux/automatic-session-e2e.json),
[engine-receipt](measurements/mypy-fix-linux/nuclei-install.json),
[Linux runtime](measurements/mypy-fix-linux/runtime.json),
[mypy baseline](measurements/mypy-fix-baseline.txt),
[mypy macOS](measurements/mypy-fix-macos-mypy.txt),
[mypy Linux cache nélkül](measurements/mypy-fix-linux/mypy-linux-cold.txt),
[forrásegyezés](measurements/mypy-fix-linux/source-verification-after.json),
[takarítás](measurements/mypy-fix-cleanup.json).

## Reprodukció

```sh
# A repository gyökeréből, a meglévő virtuális környezettel:
(.venv/bin/python -m mypy redjohn --no-incremental)
REDJOHN_TELEMETRY=0 OPENAI_AGENTS_DISABLE_TRACING=1 \
PYTHONPATH=. .venv/bin/python -m pytest tests -q
PYTHONPATH=. .venv/bin/python -m pytest tests/test_viewer_metadata_endpoints.py -q
.venv/bin/ruff check redjohn scripts tests --no-cache
(cd redjohn/interface/tui && go test ./... && go vet ./...)
(cd redjohn/interface/viewer/frontend && \
  node node_modules/typescript/bin/tsc --noEmit --noUnusedLocals --noUnusedParameters)
(cd redjohn/interface/viewer/frontend && \
  npm run build -- --outDir /tmp/redjohn-mypy-viewer-build --emptyOutDir)

# Linuxon, működő bubblewrap/user namespace, telepített Chromium és explicit lock mellett:
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_NUCLEI_LOCK=/absolute/path/to/reviewed/fixture-lock.json \
PYTHONPATH=. /path/to/venv/bin/python -m pytest tests -q -s
```

A Linux-függőségek és kernel-előkészítés a verziózott
[CI-munkafolyamatban](../.github/workflows/redjohn-remote-egress.yml) szerepelnek.
A külső eredeti skillforrás tesztjének teljes futásához az eredeti pack is szükséges
a tesztben rögzített helyen; a mostani Linux-ellenőrzéshez ezt biztosítottuk.
Az E2E-k kizárólag saját fixture-célokat használnak; a mypy-javítás nem növeli a
korábban még nem implementált specialist adapterek támogatottságát.

[Módosított fájlok és SHA-256](redjohn-mypy-fix-changed-files.json),
[reviewzható patch](measurements/mypy-fix.patch).
