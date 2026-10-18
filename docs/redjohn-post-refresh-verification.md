# RedJohn: autentikált POST replay és session refresh

Történeti HTTPX-capture/POST/session-refresh baseline a valódi Chromium POST-capture
és deklarált body-token frissítés előtt. A lenti számok változatlanok; az új
[Chromium/body-token mérés](redjohn-browser-token-verification.md) külön workload.

Ellenőrzés: 2026-10-17, a meglévő `/Users/akosdrx/Documents/rjkali` checkoutban.
Ez a jelentés a POST/JSON/form/multipart replay és a tartós session refresh
kiegészítéséről szól. A korábbi GET/HEAD- és böngészős mérések külön maradnak.

## Implementált működés

- A meglévő Nuclei adapter és SQLite scheduler maradt használatban. JSON,
  URL-encoded form és multipart POST pontos, jóváhagyott bytejai játszhatók
  vissza; a limit 64 KiB. A formok ismételt paraméterei, a multipart sorrendje,
  boundary-ja és bináris feltöltése megmaradnak.
- POST csak `active-staging` / `isolated-lab` profilban, név szerinti actorral,
  pontos `allowed_replay_urls` engedéllyel, tényleges elküldést igazoló capture-rel
  és privát v2 vault-jóváhagyással fut. A vault és a body nem kerül a workerhez;
  az ellenőrzött template nyilvános sentinel bodyját a host proxy helyettesíti.
- A `capture_authenticated_request` valódi, CA/hostname-ellenőrzött HTTPS SDK-hívás.
  A tartós `rj_request_capture` foglalás, fencing és atomi budget-admission
  akadályozza a párhuzamos vagy újraindítás utáni vak ismétlést. A lezárt capture
  ugyanazt a surface-t adja vissza hálózati kérés nélkül. Elveszett válasz után
  az állapot bizonytalan, automatikus újraküldés nincs.
- A külön `session_refresh` nem idempotens scheduler-job. Saját pontos
  `allowed_refresh_urls` és privát provider-konfiguráció kell hozzá. A host
  ellenőrzött HTTPS-válaszból frissíti az auth-/CSRF-fejléceket és cookie-kat,
  majd numerikus session-revíziót vált, például 7 → 8. A régi job/capture nem
  kap új címkét: friss capture és külön privát jóváhagyás szükséges.
- A refresh SQLite lease/CAS-t, vault-fájlzárat és fájl-CAS-t használ. A sikeres
  frissítés ténylegesen invalidálja a runtime régi sessionhöz tartozó cache-ét,
  a későn befejeződő cache-írásokat is elkerítve. A 429/503 ugyanabba a tartós
  rate limiterbe kerül. Hiányzó konfiguráció `blocked`, nem negatív találat.
- A proxy továbbra is pontos origin/IP/URL/method ellenőrzést, ellenőrzött
  upstream TLS-t és kérésenkénti admissiont használ. A távoli Nuclei-workerek
  Linux kernel namespace-be zárva futnak. Chunked/ellentmondó framing, redirect,
  body/hash/identity eltérés és nem engedélyezett metódus blokkolt.
- A Nuclei a bounded eredeti kimenetet csak hostmemóriában osztályozza; minden
  tárolás előtt redakció történik. Egy `stdout` nevű titok vagy JSON-skalár nem
  tüntethet el találatot és nem gyárthat téves negatív eredményt.

## Teszt és mérés

| Ellenőrzés | Tényleges eredmény |
|---|---|
| Teljes Linux Python suite | **438 passed, 1 skipped, 105,78 s**, 439 eset, nulla failure/error |
| Teljes macOS Python suite | **434 passed, 5 skipped, 93,58 s**, 439 eset, nulla failure/error |
| Ruff + formatter | Sikeres; 72 fájl formátuma ellenőrizve |
| Célzott strict mypy | Sikeres; 9 forrásfájl, köztük az új capture/body/refresh modulok |
| Bővített strict mypy | **Nem sikeres**: 84 hiba 5 modulban, 14 ellenőrzött fájl. Az `adapters`, `store`, `runtime`, `scheduler`, `registry` teljes típusosítása nincs lezárva; ez nem általános mypy-green állítás. |
| Python AST + natív skill manifest | 223 Python-fájl parse-olva; 47 angol assessment contract tartalom- és külön forráshash-e helyes |
| Viewer build, a munkamenet korábbi szakaszában | Sikeres; 2260 modul, 4,48 s; az 500 kB feletti chunk figyelmeztetés megmaradt |
| `go test ./...`, ugyanebben a munkamenetben | Sikeres; 4 package, **nincs Go tesztfájl**, ezért ez fordítási ellenőrzés |

A macOS öt skipje a Linux kernel namespace-t igénylő három izolációs teszt és
a két remote pipeline E2E. Ugyanezek Linuxon ténylegesen lefutottak. A Linux
egyetlen skipje a repositoryn kívüli, felhasználói eredeti skillpack
forrásfájljainak hash-összehasonlítása: ez a dokumentumcsomag nem került a
VM-be. A natív angol skill-hash ellenőrzés ott is lefutott; a forráspack
összehasonlítás macOS-en sikeres volt.

| Linux tartós POST/refresh lánc | Mérés |
|---|---|
| Időtartam | **16,503540 s** |
| Valódi HTTPS POST / tartós request charge | **11 / 11**: 4 capture + 6 Nuclei replay + 1 refresh |
| Külön CLI-folyamat | **13** |
| Pozitív candidate / új finding a fixed kontrollban | **4 / 0** |
| Újraindításból eredő duplikált kérés | **0** |
| Refresh kérés / credential-trap kérés | **1 / 0** |
| Session-revízió / CSRF-váltás | **7 → 8**, mindkettő ellenőrizve |
| Modelhívás | **0** |
| Mintavételezett CLI + leszármazott RSS-maximum | **252 186 624 byte = 240,50 MiB**, 652 minta; legfeljebb 7 folyamat |
| Mintavétel | 25 ms célköz; a legnagyobb megfigyelt mintaköz **71,45 ms** |

A memóriaeredmény a tényleges futó CLI és a kernel szerint hozzá tartozó
leszármazottak összesített RSS-e, a Nuclei/namespace workereket is beleértve.
Nem abszolút folytonos maximum; a közös lapokat többször számolhatja. A systemd
stdout végén szereplő 2,8 MB service-érték más mérési határ, ezért nem ezt
használjuk scanner-memóriaként. A ritka governor admission/heartbeat snapshot
külön marad a dedikált mintavételtől.

A három bodyformátum külön valódi engine-kontrollja macOS-en és Linuxon is
6 HTTPS POST: mindhárom marker pozitív, mindhárom javított kontroll negatív.
A további 5 valódi redakciós engine-eset 10 POST-tal ellenőrzi a numerikus és
boolean JSON-t, a `stdout` body-/credential-értéket és a külön extractorban
visszatükrözött numerikus PIN maszkolását. Minden pozitív candidate megmaradt,
minden fixed kontroll 0 lett. A privát fixture-értékeket a tesztek a nyers
SQLite-fájlokban, workerfájlokban, riportokban és CLI-kimenetben is ellenőrzik.
Ez ismert értékek maszkolásának igazolása, nem tetszőleges targetoldali
titkosítás/custom transzformáció felismerésének állítása.

A végleges suite valódi Chromiumja 5 SPA-ciklust, 25 HTTP-kérést, 5 megnyitott/
bezárt contextet és oldalt mért; előtte/utána egyaránt 2 folyamat volt a
mintavételi fában. A külön valódi HTTPS browser-teszt 9 kérést mért.
Ezek külön workloadok, nem adódnak a fenti 11 POST-hoz.

Futtatókörnyezet: saját, ideiglenes Ubuntu 24.04 ARM64 VM, 2 CPU / 4 GiB,
Linux `6.8.0-117-generic`, Python 3.12.3, bubblewrap 0.9.0,
Playwright 1.58.0 / Chromium 145.0.7632.0. Nem volt hostkönyvtár-mount vagy
SSH-agent forwarding. Az unprivileged user namespace AppArmor-beállítása csak
a saját, később eltávolított VM-ben változott.

Nuclei **3.11.1**, MIT, upstream commit
`a8c88feb4a1c8e961b7902534ce3af97e9d524a4`. Linux ARM64 binary SHA-256:
`f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477`;
macOS ARM64:
`f427ae885dcd60be25cf27c34a416ef18a803b29e153d5568057d7b6012a454d`.
A Linuxon futott 288 source/skill/template/workflow fájl mind egyezett a
hostoldali átadási manifest hash-eivel. A másolás nem tartalmazott privát
vaultot, `.env`-t, állapotadatbázist vagy workereredményt. GitHub-build/publish
ebben a folytatásban nem történt; a helyi workflow megkapta a POST-mérési
artifact változókat.

Ellenőrizhető bizonyítékok:
[összesítés](measurements/post-refresh-verification-summary.json),
[Linux stdout](measurements/post-refresh-linux/post-refresh-full.txt),
[Linux JUnit](measurements/post-refresh-linux/post-refresh-full.junit.xml),
[macOS stdout](measurements/post-refresh-macos-tests.txt),
[macOS JUnit](measurements/post-refresh-macos.junit.xml),
[POST/refresh részletes mérés](measurements/post-refresh-linux/post-refresh-e2e.json),
[macOS engine-kontroll](measurements/post-refresh-nuclei-live.json),
[Linux engine-kontroll](measurements/post-refresh-linux/post-refresh-nuclei-live.json),
[engine telepítési/licenc receipt](measurements/post-refresh-linux/nuclei-install.json),
[runtime](measurements/post-refresh-linux/runtime.json),
[dependency-verziók](measurements/post-refresh-linux/pip-freeze.txt),
[source-azonosság](measurements/post-refresh-linux/source-verification.json),
[Ruff](measurements/post-refresh-ruff.txt),
[célzott mypy](measurements/post-refresh-mypy.txt),
[bővített mypy hibák](measurements/post-refresh-mypy-expanded.txt).

## Valós integráció és unit/mock határa

A `test_post_refresh_pipeline.py` saját, nem loopback HTTPS-szolgáltatáson fut:
host HTTPX capture SDK → megfigyelt inventory → tartós SQLite job → külön CLI
→ tényleges, hashhez kötött Nuclei → host proxy → HTTPS POST → explicit refresh.
Ez nem Chromiumból automatikusan elfogott POST-folyamat. A valódi headless
Chromiumot a megtartott külön browser/GET pipeline tesztek futtatják.

A `test_nuclei_post_live.py` minden bodyformátumhoz valódi Nuclei pozitív és
javított negatív kontrollt használ. A `test_nuclei_replay_redaction_live.py`
a redakció/protokoll ütközéseket valódi engine-nel ellenőrzi. A refresh és
capture tesztcsomagban valódi HTTPS-hibák is szerepelnek; a CAS-, policy-,
template- és transport-seam unit/mock tesztek nem helyettesítik ezeket.
A harmless marker eredménye candidate; nem igazolt exploit, RCE vagy teljes
CVE-lefedettség. Az üres eredmény csak teljes, egészséges 2xx ellenőrzés után
negatív. A 401/403/429, TLS-hiba, redirect vagy hiányzó képesség külön állapot.

## Indítás és reprodukció

A telepítés külön, explicit művelet; scheduler-job nem indít telepítőt:

```bash
.venv/bin/python RedJohn/scripts/install-nuclei-pinned.py
.venv/bin/python RedJohn/scripts/create-nuclei-fixture-lock.py
.venv/bin/python -m playwright install chromium

PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/approved-post-refresh.json \
  --output redjohn_runs/approved-post-refresh --max-jobs 1
```

A konfigurációhoz működő Linux/bubblewrap enforcement, ellenőrzött engine és
egyedileg reviewzott template-lock kell. A privát `auth_vault_file` és
`refresh_provider_file` sémája, a capture és explicit job-beküldés kódja:
[POST/replay útmutató](../RedJohn/docs/post-refresh-replay.md),
[refresh szerződés](../RedJohn/docs/session-refresh.md).
A fixture-lock kizárólag a saját harmless tesztsablonját engedélyezi; más
alkalmazás POST-jához külön review és lock szükséges.

```bash
# Teljes helyi tesztcsomag; a Linux-képesség hiánya itt skipként látható.
PYTHONPATH=RedJohn .venv/bin/python -m pytest RedJohn/tests -q

# Linuxon: a hiányzó remote E2E-feltétel hiba, nem csendes skip.
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_POST_REFRESH_MEASUREMENTS=/tmp/redjohn-post-refresh.json \
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_post_refresh_pipeline.py -q -s
```

Azonos konfigurációval/outputtal újraindítva a lezárt job nem küld új kérést.
A CLI exit 1 maradhat egy későbbi sikeres job után is, ha az engagement korábbi
coverage-jében szándékos blocked/inconclusive kontroll szerepel. Ez a tárolt
összesített coverage-t jelzi, nem a sikeres job hibáját.

## Megmaradó korlátok

- A capture és privát jóváhagyás SDK/fájlos munkafolyamat. Nincs automatikus
  browser POST-capture, bodyfeltöltő CLI-varázsló, általános login/OAuth/MFA,
  CAPTCHA vagy browser `storage_state` automatikus frissítése.
- Body-ba ágyazott CSRF/credential átírása, a provider saját egyszer használatos
  refresh-tokenjének válaszból rotálása és cross-origin credential-szétosztás
  nincs implementálva. PUT/PATCH/DELETE, XML/raw HTTP, nested multipart,
  tetszőleges template/fuzzing/OAST továbbra sem része ennek az adapternek.
- A refresh provider JSON/form kérést és szigorú, tömörítetlen HTTP 200 JSON
  választ fogad; legfeljebb 30 s és 64 KiB. A capture legfeljebb 15 s. A vault
  0600-as, saját tulajdonú, nem symlink, single-link fájl, legfeljebb 256 KiB.
- A vaultcsere és SQLite commit két tartós művelet; nincs köztük elosztott atomi
  tranzakció. Crash/lost-response után bizonytalan állapot marad. Kézi
  egyeztetés és új reviewzott policy-revízió szükséges; nincs vak resend.
- A cache runtime-onként él. Más folyamatok a tartós session-fence-t és
  revízióhoz kötött kulcsokat ellenőrzik; globális cache-invalidation nincs.
- A memória-admission és a mérés valós, de a mintavételezett összesített RSS
  közös lapokat többször számolhat, és nem bizonyít kemény cgroup RAM-korlátot.
- A teljes master prompt összes opcionális adaptere és release-elfogadási
  követelménye ettől még nem kész. A hiányzó képességeket a registry/report
  külön jelzi. A korábbi böngészős remote teszt blokkolt háttérkérései részleges
  coverage-ként maradnak láthatók.

## Megőrzés és fájlátadás

A kiindulási snapshot mind a **205 Python-forrás-/tesztfájlja megmaradt**;
a korábbi **27 aktív teszt-/supportfájl hash-e változatlan**. Az újakkal együtt
220 Python source/test fájl van. A végleges hostoldali source snapshot 288
fájlja egyezik a Linuxon tesztelt változattal.
A master prompt SHA-256-ja, a Git HEAD és a Git index hash-e változatlan;
az origin `https://github.com/akosdrx/redjohn.git`. A korábbról örökölt nagy Git
átstrukturálást nem reseteltük, stage-eltük vagy publikáltuk.
[Megőrzési bizonyíték](measurements/post-refresh-preservation.json).

A takarítás **419 generált/cache/tesztadat-fájlt, 114 095 430 logikai byte-ot**
mozgatott külön privát macOS Trash-könyvtárba, visszaállíthatóan. Production
vagy aktív tesztforrás nem törlődött. A saját `redjohn-e2e` VM leállt és a
profiljával, instance-ével és külön adatalemezével együtt eltűnt; ezt külön
ellenőriztük. A managed engine/dependency-k, viewer static artifactok, a két
korábban elfogadott demo-run és minden átadott mérés megmaradt.
[Pontos takarítási lista](measurements/post-refresh-cleanup.json).

A jelen folytatás fájlonkénti SHA-256 listája:
[POST/refresh változások](redjohn-post-refresh-changed-files.json).
Az eredeti audit óta összevont lista:
[fájlindex](redjohn-changed-files.md),
[összesített manifest](redjohn-changed-files.json).

A skillek angol nyelvűek maradtak; a két érintett assessment contract a pontos
POST/refresh képességet és a hiányzó általános auth-workflow-t külön kezeli.
Az eredeti forráshash és az angol tartalomhash külön marad. Firecrawl nem került
be, külső Strix/HexStrike kódot ez a kiegészítés nem vett át.
