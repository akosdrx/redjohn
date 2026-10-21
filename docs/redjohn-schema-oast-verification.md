# RedJohn: TInjA / Schemathesis / Interactsh ellenőrzés

Historical GET-stage snapshot (source manifest recorded below). The current authenticated
POST/session extension is documented in [the follow-up verification](redjohn-authenticated-schema-oast-verification.md).

2026-10-18. A meglévő RedJohn repository célzott bővítése. A név, branding,
saját módosítások, aktív tesztek és a korábbi integrációk megmaradnak.
Ez a dokumentum az itt megvalósított profilokat igazolja, nem a teljes
master prompt minden képességének elfogadását.

## Implementált lánc

- Valódi Chromium-capture → megfigyelt inventory-input → kijelölt tartós
  `tinja_validate` / `schemathesis_validate` job. Valódi pinned CLI-processzek;
  SSTI- és schema-kontraktusjelzések candidate státuszban maradnak.
  Az alias-only workerek közvetlen CONNECT-tunnelje még scope-on belüli célra
  sem kerülhet admissionhöz vagy credential-injektáláshoz.
- TInjA 1.2.0: egy anonim GET/query input, host által ellenőrzött véges
  payloadkatalógus; valódi sandboxolt Jinja és escaped kontroll.
- Schemathesis 4.31.1: hashhez kötött helyi OpenAPI-részhalmaz, egy GET-művelet,
  korlátozott pozitív integer-generálás és valódi response-conformance ellenőrzés.
  Két, a kijelölt műveleten kívüli belső probe explicit SKIP; nem teszteredmény.
- Interactsh 1.4.1: saját hostoldali protokollkliens, valódi hivatalos receiverrel
  ellenőrizve. HTTPS regisztráció/poll/deregister, RSA-OAEP + AES-CTR események,
  egy kijelölt callback URL, privát kulcstároló, tartós late-poll outbox.
  A termék nem indít automatikusan upstream Interactsh CLI-t vagy receivert.
- Normál runtime/CLI újraindítás után nincs új célkézbesítés. A véges
  `run_until_idle` / `--wait-ready-seconds` az újraindítás nélkül később
  esedékes jobokat is futtatja, a `max-jobs` és deadline megtartásával.
- Valódi poll utáni azonnali processzhalál, tényleges lease-lejárat és új CLI:
  `unknown_execution_outcome`, inconclusive, nulla új célkérés. Nincs vak retry
  vagy elveszett callbackből képzett hamis negatív. Részbizonyíték-ref megmarad.

## Végső tesztek és mérések

| Ellenőrzés | macOS ARM64 | Ubuntu ARM64 |
|---|---:|---:|
| Teljes Python csomag | 945 pass / 25 skip, 400.03 s | 970 pass / 0 skip, 527.89 s |
| Új live esetek | 28 pass / 4 kernel-skip | 32 pass / 0 skip |
| Új kontraktus/kripto esetek | 74 pass | 74 pass |
| Strict mypy | 196 modul, 0 hiba | 196 modul, 0 hiba |
| Teljes teszt-workload mintavett RSS-csúcs | 771.28 MiB | 1121.00 MiB |

A 25 macOS skip mindegyike ugyanazon a forráson sikeres Linux-esethez
párosítható; részletek a `measurements/schema-oast/test-summary.json` fájlban.
A végső forráslista 322 fájl, benne 267 Python-forrás (196 modul, 64 teszt/support,
7 script). Mindkét futás előtt/után nulla forráseltérés. A mérési körök alatt
típusellenőrző nem futott a tesztek VM-cgroupjában; a saját Linux VM fájlcache-e
az ellenőrzési kör előtt ürült, ez nem termékbeli resource-fallback.

Ruff sikeres, 15 érintett Python-fájl formátumellenőrzése sikeres. A Viewer build
2261 modullal 2.33 s alatt elkészült, strict TypeScript sikeres, négy asset byte-azonos.
A meglévő Vite chunkméret-jelzés megmaradt. Go test/vet sikeres, a négy csomagban
nincs Go unit teszt. GitHub Actions-futás nem történt; a CI dependency lock nem
AMD64 live-bizonyíték.

A RSS-külső mintavétel a teljes pytest/controller/browser/scanner/owned-receiver
processzfát méri, 100 ms alvással és további ps-overheaddel. Megosztott lapok
többször számolhatók; ez nem kizárólagos engine-heap vagy OS hard RAM-limit.
A platformonkénti `memory.json` rögzíti a mintaszámot, időt és módszert.


A `test_schema_oast_contract.py` típus-, konfiguráció-, parser-, outbox-,
szintetikus kriptográfiai és lazy-start kontroll. Ezek nem live engine-tesztek.
A `test_schema_oast_live.py` valódi CLI-ket, Chromiumot és a pinned hivatalos
Interactsht használja. A receiverben tényleges HTTP-esemény keletkezik és
titkosítódik; nincs mock receiver/protokollválasz vagy hamis scanner-output.
A crash-teszt csak a valódi poll-válasz után hajt végre azonnali processz-exitet.

Az OAST-fixture kontrollált HTTP Host fejléc útján éri el a saját receivert.
Ez valódi HTTP-receiver-integráció, nem publikus DNS-delegáció vagy internetes
visszaérhetőség bizonyítéka. A callback önmagában nem RCE és nem igazolja a küldő
személyazonosságát. A javított kontroll csak a mért megfigyelési ablak negatívja.

A korábbi Nuclei / POST / JSON / form / multipart / session refresh / body-token /
automatikus recapture és ffuf/httpx/Katana/VulnX/Arjun/sqlmap/Dalfox tesztek
ugyanebben a teljes futásban maradnak. A teljes csomag mockteszteket is tartalmaz;
azok installer-outputja nem valódi binárisbizonyíték. A tényleges engine-pinek,
receiptek és platformadatok külön mérési fájlok.

## Indítás

Repo-root: `/Users/akosdrx/Documents/rjkali`.

```sh
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment health
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment run \
  --config /absolute/path/approved-schema-oast.json \
  --output /absolute/path/engagement --max-jobs 16 --wait-ready-seconds 65
PYTHONPATH=RedJohn REDJOHN_REQUIRE_SCHEMA_OAST_E2E=1 \
  .venv/bin/python -m pytest RedJohn/tests/test_schema_oast_contract.py \
  RedJohn/tests/test_schema_oast_live.py -q -s -p no:cacheprovider
```

Angol korlát-/telepítési dokumentáció:
[schema-oast-adapters.md](../RedJohn/docs/schema-oast-adapters.md).
A példakonfiguráció üres seeds/jobs listája nem indít scannert.
A valódi tesztfutás envje és parancsa a mérések mellett megmarad.

## Blokkolt / unsupported / nem igazolt

- Távoli CLI-worker egress macOS-en: Linux kernel-izoláció hiánya miatt
  fail-closed. A loopback HTTPS-mérés külön profil. Linuxon valódi nem-loopback
  HTTPS és attesztált namespace adja a távoli workerbizonyítékot.
- Új adapterek: named actor / POST-body mutation, TInjA CSTI, több/ismételt query,
  általános OpenAPI/GraphQL, CRUD/stateful schema-teszt és Nuclei–OAST binding
  unsupported. A korábbi autentikált Nuclei replay és body/session út megmarad.
- OAST: publikus DNS-delegáció, publikus/IPv6 callback-elérhetőség és további
  callbackprotokollok nem igazoltak. Saját receiver engedélyezett infrastruktúra;
  nincs automatikus publikus fallback.
- Bizonytalan register/dispatch/draining poll operatori egyeztetést igényel;
  nem negatív eredmény. A privát allocation- és eventkorlát valódi implementáció.
- RAM-admission kooperatív, nem univerzális hard limit. Hosszú soak, AMD64/Kali
  kiadás és a teljes termék kereskedelmi csomagolása nem lett itt igazolva.
- Az eredeti RCE-fixture hiányzik: `not_reproduced_missing_fixture`. Egyik
  scannerjelzés vagy callback sincs confirmed RCE-ként feltüntetve.

## Megőrzés, fájlok és takarítás

A 62 meglévő teszt/support fájl mind byte-azonos, két új aktív tesztfájl marad.
A 47 angol skillből három célzott kontraktus és manifest frissült, a source-provenance
hash-ek megmaradtak. A master prompt, HEAD, origin, Git-index és a privát MCP-konfiguráció
hash-e változatlan; baseline fájl nem hiányzik. Részletek:
`measurements/schema-oast/preservation.json`.

A kód-, konfiguráció-, dokumentáció- és mérési fájlok:
[célzott fájllista](redjohn-schema-oast-changed-files.md),
[kumulatív fájllista](redjohn-changed-files.md). A generált/debug/fixture-adatokat
visszaállítható Lomtár-mozgatással eltakarítottam. A saját E2E-VM-et és adatlemezét
eltávolítottam. Aktív teszt, saját RedJohn-kód és működő managed engine megmaradt. A tényleges takarítást a
`measurements/schema-oast/cleanup.json` rögzíti.

## Diagnosztika

Az első teljes Linux-kör négy változatlan mock CLI-státusztesztben tárta fel,
hogy az új opcionális várakozási paraméter alapértelmezett továbbadása eltért
a korábbi hívási alaktól. A CLI megőrzi a régi hívást nulla várakozásnál;
a teszteket nem módosítottam. A külön kompatibilitási kör 78/78 lett. A végső
teljes csomag ennek javítása és a külön CONNECT-escape regresszió után fut.
Az előző teljes kör kimenete külön diagnosztika, nem sikeres végső tesztként szerepel.
