# RedJohn MCP-alapértelmezések és halott kód takarítása

Ellenőrizve: 2026-10-17, macOS ARM64, Python 3.13.16. Ez a jegyzőkönyv a
mostani takarításra vonatkozik; a korábbi Linux/browser/Nuclei mérések történeti
eredményei külön dokumentumokban maradnak.

## Változás

A `cve-mcp` és `osint-mcp` alapértelmezett definíciói, a konfigurációíró/merge
segédfüggvények és a régi Desktop MCP-nevek migrációs listája megszűntek.
A CLI, a TUI és a Kali telepítő nem generál vagy módosít MCP-konfigurációt.
Nincs üres kompatibilitási függvény vagy új indításkori migráció a helyükön.

A helyi `~/.redjohn/mcp-servers.json` két pontosan egyező, korábban generált
bejegyzését egyszeri, kifejezetten engedélyezett takarítás távolította el.
A fájl tartalma most `[]`. A módosítás előtt hash-ellenőrzés és privát mentés
készült; más bejegyzést nem töröltünk. Az alkalmazás ettől kezdve csak olvas.

Az általános MCP-támogatás megmaradt: stdio/HTTP, egyedi konfigurációs útvonal,
include/exclude kiválasztás, engedélylista, registry, supervision és leállítás.
A felhasználó által explicit konfigurált szerver nevét nem tiltjuk, akkor sem,
ha történetesen egy korábbi alapértelmezéssel egyezik.
[Konfigurálás](../RedJohn/docs/mcp-configuration.md).

A RedJohn saját `lookup_cve` forrása byte szerint változatlan. A `hunt`
engedélyezése és végrehajtása AST szerint változatlan; csak a hivatkozás nélküli
parancsmegjelenítő segéd szűnt meg. Az assessment/browser/Nuclei/session/scheduler
források, a skillek és mind az 52 korábbi aktív teszt/segédfájl változatlanok.
Új aktív regressziós tesztfájl: `RedJohn/tests/test_mcp_configuration.py`.

## További igazoltan elárvult részek

A teljes 242 Python-fájlra kiterjedő AST-hivatkozáskeresés és Ruff-ellenőrzés
után egyenként ellenőriztük a találatokat. A három MCP-generáló függvény mellett
hét hivatkozás nélküli segédet távolítottunk el:

- `build_tui_stats_text`: a régi Python TUI statisztikai megjelenítője;
- `project_root`: a sidecar használaton kívüli útvonal-segédje;
- `resolve_lexer`: nem használt riport-lexer kiválasztás és importjai;
- `build_sarif_document`: hívó nélküli alias; a használt SARIF-író megmaradt;
- `hunt_command`: hívó nélküli shell-szövegformázás; az argv-végrehajtás megmaradt;
- `is_debug_enabled`: hivatkozás nélküli wrapper;
- `init_logging`: a használt scan/console naplózás melletti, nem hívott régi út.

Eltávolítottunk 14, már nem létező fájlokra/könyvtárakra vonatkozó Ruff-kivételt
és a régi MCP-loader fölöslegessé vált kivételét. A Go TUI-ból egy már nem
létező Python-megjelenítőre mutató elavult megjegyzés került ki.

A statikus keresés találatai között volt három, telepített SDK-ősosztályból
hívott override és három Pydantic-validator. Ezek működő kódok, megmaradtak.
A backend-/tool-regisztrációs bővítési pontok, a dinamikus exportok és a proxy
életciklusa is megmaradtak. Az audit nem állítja, hogy minden lehetséges
futásidejű elérhetetlenséget matematikailag kizárt.
[Gépi audit](measurements/mcp-cleanup-dead-code-audit.json).

A frontend szigorított unused-ellenőrzése két további maradványt azonosított:
az `AgentGraph` nem használt `useState` importját és az `IssueSidebar` sehol
nem átadott vagy olvasott `slackThreadUrl` propját. Ezek megszűntek. A teljes
frontend TypeScript-ellenőrzése `noUnusedLocals`/`noUnusedParameters` kapcsolóval
sikeres. A 41 Go-fájl privát, felső szintű függvényeinek AST-hivatkozáskeresése
nem talált új elárvult jelöltet; a `go vet` is sikeres.

## Lefuttatott ellenőrzések

| Ellenőrzés | Eredmény |
|---|---|
| Új célzott regresszió | **17 passed, 1,43 s** |
| Teljes aktív Python-csomag | **648 passed, 14 skipped, 104,64 s**, 662 eset |
| Valódi helyi MCP stdio E2E | **sikeres, 0,479 s** a teljes futásban |
| Ruff, teljes forrás/scripts/tests | **sikeres** |
| Módosított Python-fájlok formátuma | **11 fájl sikeres**, az új teszttel együtt |
| Strict mypy, módosított modulok | **10 modul sikeres**, `--follow-imports=silent` |
| Strict mypy, teljes projekt | **69 korábbi hiba 15 fájlban**, 186 ellenőrzött modul; előtte és utána ugyanazok a hibák, új hiba nincs |
| Teljes formatter | **12 korábbi formázási eltérés**; a módosítás előtti másolat is ugyanennyi eltérést ad |
| Frontend TypeScript + unused | **sikeres**, `--noEmit --noUnusedLocals --noUnusedParameters` |
| Viewer build | **2260 modul, 2,43 s**, sikeres; meglévő 500 kB chunk-figyelmeztetés |
| Go TUI | **4 package sikeresen fordult**; a jelenlegi csomagokban nincs Go-tesztfájl |
| Go vet / privát függvények | **sikeres / 41 fájl, új elárvult jelölt nélkül** |
| Kali telepítő | `bash -n` sikeres; a telepítőt nem futtattuk |
| CLI | Valódi `rj --help` és `rj assess health` sikeres; MCP-konfiguráció változatlan |

A helyi MCP E2E egy tényleges külön FastMCP-folyamatot indít, a valódi RedJohn
registry/catalog/`call_mcp` útvonalon egy engedélyezett hívást végez, elutasít
egy nem engedélyezett toolnevet, majd ellenőrzi a gyermekfolyamat megszűnését.
A konfiguráció byte szerint változatlan. Ez saját helyi protokoll-fixture;
nem a kivett harmadik fél szervereinek integrációs tesztje. Nincs modellhívás,
csomagtelepítés vagy külső hálózat ebben az E2E-ben.

A CLI-startup regresszió a scan/modell végrehajtását helyettesíti. A TUI-teszt
a valódi runtime konstruktort használja, ablak vagy sidecar indítása nélkül.
A riport-smoke tényleges Markdown/JSON/CSV/SARIF fájlokat ír a pytest ideiglenes
könyvtárába. Ezeket nem számoljuk külső scanner- vagy modellintegrációnak.

A 14 kihagyás Linux kernel namespace-t igényel: három egress-boundary eset és
tizenegy távoli browser/auth/replay E2E. Most macOS-en nem futottak le; ezek
hiányzó platformképességek, nem negatív biztonsági eredmények. A korábbi Linux
eredmények nem helyettesítik a mostani futást. A helyi Chromium/Nuclei esetek a
teljes csomag részeként újrafutottak.

[Teljes JUnit](measurements/mcp-cleanup-full.junit.xml),
[stdout](measurements/mcp-cleanup-full-tests.txt),
[helyi MCP E2E](measurements/mcp-cleanup-protocol-e2e.json),
[összesítő](measurements/mcp-cleanup-verification-summary.json),
[megőrzés](measurements/mcp-cleanup-preservation.json),
[mypy előtte](measurements/mcp-cleanup-mypy-baseline.txt),
[mypy utána](measurements/mcp-cleanup-mypy-current.txt),
[módosított modulok mypy](measurements/mcp-cleanup-mypy-changed.txt).

## Reprodukció a repository gyökeréből

```sh
PYTHONPATH=RedJohn .venv/bin/python -m pytest RedJohn/tests/test_mcp_configuration.py -q
PYTHONPATH=RedJohn .venv/bin/python -m pytest RedJohn/tests -q
.venv/bin/ruff check RedJohn/redjohn RedJohn/scripts RedJohn/tests --no-cache
bash -n RedJohn/scripts/install-kali.sh
PYTHONPATH=RedJohn .venv/bin/rj --help
PYTHONPATH=RedJohn .venv/bin/rj assess health

(cd RedJohn && ../.venv/bin/mypy --follow-imports=silent \
  redjohn/tools/mcp/loader.py redjohn/tools/mcp/__init__.py \
  redjohn/interface/main.py redjohn/interface/tui/runtime.py \
  redjohn/interface/tui/sidecar.py redjohn/interface/utils.py \
  redjohn/report/writer.py redjohn/report/sarif.py \
  redjohn/tools/hunt/tool.py redjohn/telemetry/logging.py)

# A teljes strict ellenőrzés jelenleg a fenti 69 korábbi hibával lép ki:
(cd RedJohn && ../.venv/bin/mypy redjohn)
(cd RedJohn/redjohn/interface/tui && go test ./...)
(cd RedJohn/redjohn/interface/tui && go vet ./...)
(cd RedJohn/redjohn/interface/viewer/frontend && \
  node node_modules/typescript/bin/tsc --noEmit --incremental false \
  --noUnusedLocals --noUnusedParameters)
(cd RedJohn/redjohn/interface/viewer/frontend && \
  npm run build -- --outDir /tmp/redjohn-mcp-cleanup-viewer --emptyOutDir)
```

[Módosított fájlok és hash-ek](redjohn-mcp-cleanup-changed-files.json),
[reviewzható patch](measurements/mcp-cleanup.patch),
[generált tesztadatok takarítása](measurements/mcp-cleanup-generated-cleanup.json).
Az örökölt Git-átstrukturálás nem ennek a feladatnak a törlési listája.
HEAD, index és master prompt változatlan.
