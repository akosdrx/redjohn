# RedJohn: automatikus sessionlejárat/401 helyreállítás

Ellenőrzés: 2026-10-17, `/Users/akosdrx/Documents/rjkali`. A jelenlegi,
hash szerint ellenőrzött forrásra vonatkozó eredmények. A korábbi
continuous/browser-token jegyzőkönyvek történeti baseline-ok.

## Mi működik

Explicit `continuous_replay.session_recovery` konfiguráció mellett a teljes,
hitelesített 401 vagy az adott kéréshez tartozó privát credential lejárata
automatikusan külön refresh-jobot sorol be. A sikeres refresh → valódi új
Chromium-capture → kijelölt Nuclei-replay ugyanabban a futó runtime-ban és
schedulerben folytatódik. Nincs kézi refresh- vagy gyermekjob-beküldés.

A trusted proxy csak teljes, helyesen keretezett, méretkorlátos válasz után
adhat 401-jelet, pontos GET-start vagy POST-route és HTTP-metódus alapján.
A Playwright-metaadat vagy a csonkolt 401-status önmagában nem elég. A lejárati
előellenőrzés a kiválasztott start GET- és reviewzott POST-bindingjait vizsgálja;
egy másik start/endpoint lejárata nem fogyaszthatja a helyreállítási keretet.
A régi `context_metadata` API alapviselkedése megmaradt; az új felismerés opt-in.

A `max_refreshes` egész 1–3, a `cooldown_seconds` egész 0–3600 lehet. A
`rj_auth_recovery_budget` és `rj_auth_recovery_job` táblák identitás/policy szerint,
sessionrevíziókon és újraindításon át megőrzik a keretet. Az auth-failure esemény
és a hibás szülő lezárása atomi; a keret, gyermekjob és esemény-nyugtázás szintén
egy tranzakció. Azonos régi revízió hibái egy canonical refresh-be olvadnak.
Queue/tárhelyhiba nem hagy részleges charge-ot, kései régi 401 nem frissíti az
új sessiont. A korábbi outbox additív migrációval megmarad.

A régi hibás POST/job és bizonyítéka megmarad, nem lesz retry vagy újracímkézett
siker. A teljes POST-401 régi capture-reservationje nem ad approvalt; az új
revízióhoz új valódi byteok és jóváhagyás szükséges. Ismeretlen/eltűnt refresh
nem ismétlődik automatikusan. A lejárt browser-credential Chromium-indítás előtt,
a lejárt Nuclei-binding scannerindítás előtt felismerhető. A workerátadás továbbra
is `max_workers=1` mellett, browser–scanner lease-átfedés nélkül működik.

## Valódi E2E

Hét eset saját, nem loopback HTTPS-fixture-ön, tényleges headless Chromium és
pinned Nuclei mellett, Linux kernel-attesztált egress-határral. Esetenként a
helyreállítás végéig ugyanaz a controller PID, runtime és browser-service objektum
marad; a workerfolyamatok szükség szerint lezárulnak. A későbbi újranyitás külön
deduplikációs kontroll, nem a folytatás előfeltétele.

| Eset | Workload idő | HTTPS-kérés | Refresh | Tényleges friss Nuclei candidate |
|---|---:|---:|---:|---:|
| Browser GET 401 | 5,340 s | 9 | 1 | 3 |
| Browser POST-capture 401 | 5,174 s | 10 | 1 | 3 |
| Nuclei POST 401 | 4,408 s | 13 | 1 | 3 |
| Lejárt Nuclei-binding | 3,663 s | 12 | 1 | 3 |
| Lejárt browser-vault | 2,841 s | 8 | 1 | 3 |
| Ismételt 401 az új sessionnel | 5,407 s | 3 | 1 | **nem futott: blocked** |
| Csonkolt 401-body | 2,755 s | 2 | **0** | **nem futott: inconclusive** |

Összesen **57 HTTPS-kérés, 6 refresh, 15 candidate**, 0 modelhívás, 0 új
HTTP/refresh az ismételt batch és újranyitás során. Az öt sikeres helyreállítás
mind valódi JSON/form/multipart capture-t és három tényleges Nuclei POST-replayt
végez a friss 8-as sessionnel és friss body-tokenekkel. Bináris upload megmarad.
A privát byteokat nem a teszt építi át capture-ként; Chromium állítja elő őket,
a proxy teljes 2xx-bizonyítéka és a privát approval engedi a replayt.

A lejárt browser-vault esetben az első HTTP-kérés a refresh, és a mintavételezés
sem látott előtte browser-lease-t. A lejárt scanner-binding esetben a már
elkészült 7-es capture után refresh az első új HTTP; nincs régi scanner-POST vagy
401. A normál scanner-401 esetben a régi Nuclei valóban elküldi a hitelesített
POST-ot és 401-et kap. A két elutasító eset **nem negatív sérülékenységteszt**:
ismételt 401-nél a tartós budget tiltja a második refresh-t, csonkolt válasznál
nincs admitted auth-jel, approval vagy scanner-job. A régi uncertain capture
újranyitás után sem küldődik újra.

Verziók: Playwright **1.58.0**, Chromium **145.0.7632.0**, Nuclei **3.11.1**,
bubblewrap **0.9.0**, Linux ARM64/Python **3.12.3**. A tényleges engine SHA-256:
`f27098e0be0cc370af52274611608ad61896d7f0a024e35b136327d39e725477`.
MIT, upstream commit `a8c88feb4a1c8e961b7902534ce3af97e9d524a4`; külön saját,
reviewzott és hash-pinnelt fixture-bundle. Nincs új Strix/HexStrike kódátvétel.

Az esetek workload-idejének összege **29,589075 s**; ez nem a teljes pytest-futás
ideje. A controller és leszármazottai mintavételezett processfa-RSS maximuma
**1 066 147 840 byte = 1016,76 MiB**, 1171 mintából. Célköz 25 ms, legnagyobb
megfigyelt köz **76,89 ms**, max. 17 folyamat. Minden esetben legfeljebb egy
worker-lease, és nulla mintában browser/scanner lease-átfedés. A megosztott lapok
többször számolódhatnak; ez nem abszolút csúcs vagy OS hard-limit. A systemd
service memóriaadata eltérő mérési határ, ezért nem helyettesíti a worker-RSS-t.

[Nyers hét-esetes E2E](measurements/auth-recovery-linux/automatic-session-e2e.json),
[külön E2E-futtatás](measurements/auth-recovery-linux/automatic-session-focused.json),
[valódi engine-receipt](measurements/auth-recovery-linux/nuclei-install.json),
[runtime](measurements/auth-recovery-linux/runtime.json).

## Tesztmátrix és bizonyítási határ

| Ellenőrzés | Tényleges végleges eredmény |
|---|---|
| Linux teljes Python-csomag | **644 passed / 1 skipped**, 645 eset, **185,04 s**, 0 failure/error |
| macOS teljes Python-csomag | **631 passed / 14 skipped**, 645 eset, **103,76 s**, 0 failure/error |
| Új tesztesetek | **103**, a korábbi 542 eset megmaradt |
| Strict mypy | **23 modul sikeres**, változatlan projektkonfiguráció |
| Ruff és formatter | **90 fájl sikeres** |
| AST / angol natív contractok | **241 Python-fájl / 47 skill hash sikeres** |
| Viewer build | **2260 modul, 2,97 s**; meglévő nagy-chunk figyelmeztetés megmaradt |
| Go TUI | **4 package, tesztfájl nélkül**; `go test ./...` fordítási ellenőrzés sikeres |

Az új csoportok: 15 fake-browser/adapter/metódus-kontraktus; 49 valódi SQLite
outbox/budget/cooldown/fault teszt fake workerekkel; 28 szintetikus workflow-
kontraktus; 4 valódi privát vault-séma/binding teszt hálózat nélkül; 7 teljes
valódi E2E. A mock/kontraktuscsoportok nem jelentenek scanner-live igazolást.
A korábbi valódi browser/token/refresh/restart és pozitív/javított scanner-
kontrollok is újrafutottak. A teljes scanner/control tesztanyag candidate és
fixed-0 eredményei külön maradnak a hiányzó vagy blokkolt képességektől.

Linuxon egyedül a VM-be át nem másolt külső eredeti skillpack forráshash-tesztje
maradt ki; a 47 angol natív contract hash-e ott is helyes. Az eredeti source-
ellenőrzés macOS-en sikeres volt. A 14 macOS-skip három Linux-namespace teszt
és tizenegy remote E2E-eset; ugyanazok Linuxon ténylegesen lefutottak.
Mind a 645 azonosított teszteset sikeresen lefutott legalább az egyik tényleges
platformon; nincs mindkét helyen kihagyott eset.
A stdout mock installer tesztje külön fake, 35 byte-os Darwin-engine adatokat
is kiír; a használt valódi Linux binárist a fenti külön receipt igazolja.

[Linux JUnit](measurements/auth-recovery-linux/auth-recovery-full.junit.xml),
[Linux stdout](measurements/auth-recovery-linux/auth-recovery-full.txt),
[macOS JUnit](measurements/auth-recovery-macos.junit.xml),
[macOS stdout](measurements/auth-recovery-macos-tests.txt),
[mypy](measurements/auth-recovery-mypy.txt), [Ruff](measurements/auth-recovery-ruff.txt),
[Go](measurements/auth-recovery-go-tests.txt),
[Viewer](measurements/auth-recovery-viewer-build.txt),
[gépi összesítő](measurements/auth-recovery-verification-summary.json).

## Indítás és reprodukció

Teljes konfigurációs feltételek, mapping, privát anchor és státuszok:
[automatic session recovery](../RedJohn/docs/automatic-session-recovery.md).
Az új beállítás a már reviewzott `continuous_replay` objektumba kerül:

```json
"session_recovery": {"max_refreshes": 1, "cooldown_seconds": 0}
```

```sh
PYTHONPATH=RedJohn .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/assessment.json \
  --output /absolute/private/assessment-output --max-jobs 32

REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_AUTOMATIC_SESSION_MEASUREMENTS=/tmp/redjohn-automatic-session.json \
PYTHONPATH=RedJohn .venv/bin/python -m pytest \
  RedJohn/tests/test_automatic_session_recovery_pipeline.py -q -s

# Teljes regresszió; a strict flag Linuxon hiányzó core képességnél hibát ad:
REDJOHN_REQUIRE_REMOTE_E2E=1 PYTHONPATH=RedJohn \
  .venv/bin/python -m pytest RedJohn/tests -q -s
PYTHONPATH=RedJohn .venv/bin/python -m pytest RedJohn/tests -q \
  --basetemp=/tmp/redjohn-auth-recovery-macos-tests-final

.venv/bin/ruff check RedJohn/redjohn/assessment \
  RedJohn/redjohn/tools/hunt/nuclei.py RedJohn/tests
.venv/bin/ruff format --check RedJohn/redjohn/assessment \
  RedJohn/redjohn/tools/hunt/nuclei.py RedJohn/tests
(cd RedJohn && ../.venv/bin/mypy \
  redjohn/assessment/{auth_replay,request_body,session_refresh,session_recovery,capture,models,policy,browser_proxy,adapters,store,runtime,scheduler,registry,native_session,contracts,browser,browser_capture,browser_workflow,body_tokens,browser_tls,egress,_egress_worker}.py \
  redjohn/tools/hunt/nuclei.py)
(cd RedJohn/redjohn/interface/tui && go test ./...)
(cd RedJohn/redjohn/interface/viewer/frontend && \
  npm run build -- --outDir /tmp/redjohn-auth-recovery-viewer-build)
```

A Linux-ellenőrzés dedikált helyi VM-ben, mount/SSH-agent-forward nélkül,
saját systemd service-ből futott. **306** engedélyezetten átmásolt forrás/
teszt/skill fájl SHA-256-ja egyezett a végleges hostforrással:
[manifest](measurements/auth-recovery-linux-source-files.json),
[ellenőrzés](measurements/auth-recovery-linux-source-verification.json).
A GitHub workflow mérési változót kapott; GitHub Actions-futtatást nem állítunk.

## Megőrzés és kért takarítás

Mind a **235** kiinduló Python forrás/teszt/script megmaradt. Hét meglévő
implementációs modul módosult, egy új modul és öt új aktív tesztfájl készült.
Mind a **47** korábbi aktív teszt/segédfájl byte szerint változatlan, HEAD,
index és master prompt változatlan. A RedJohn név, meglévő integrációk és az
`akosdrx/redjohn` origin megmaradt; nem történt reset/clean/commit/push.
[Megőrzési bizonyíték](measurements/auth-recovery-preservation.json).

A sikeres teljes tesztmátrixról visszajelzés után kizárólag saját generált
tesztadatok, bytecode/cache-ek, temp build/archívum/debug fájlok kerültek
visszaállítható privát Trash-ba; a teszt-VM és saját adatlemeze eltávolítva.
A korábbi pontosítás szerint az aktív regressziós/E2E-tesztek maradtak.
A nyolc érintett modul célzott AST/referencia- és Ruff-auditja nem talált
igazoltan biztonságosan törölhető halott privát helpert; public/kompatibilitási
API-t nem töröltünk feltételezés alapján. Ez nem globális dead-code-mentességi
állítás. A managed toolok, függőségek és korábbi elfogadott runok megmaradtak.
[Takarítás](measurements/auth-recovery-cleanup.json),
[célzott kódaudit](measurements/auth-recovery-dead-code-audit.json),
[módosított fájlok](redjohn-auth-recovery-changed-files.json).

## Korrekt blokkolások és nyitott képességek

Ismételt 401 keretkimerülése, cooldown, lejárt capture-jóváhagyás,
hiányzó/hibás privát provider vagy anchor, 403/challenge és unknown mutáló
kimenetel nem sikeres negatív teszt. A régi failed/blocked coverage a sikeres
új revízió mellett is megmarad; ezért a CLI exit lehet nem nulla. A browser
aggregate partial coverage-e és a blokkolt háttérkapcsolatok is láthatók maradnak.
Linux-kernelhatár nélkül a remote profil blokkolt. Teljes login/MFA/password-reset,
OAuth-felderítés, provider-refresh-token rotáció, heurisztikus body-token-
kinyerés és XML/raw/nested multipart továbbra sincs implementálva. Az eredeti
RCE-fixture hiányzik (`not_reproduced_missing_fixture`); a candidate marker nem
RCE-bizonyíték. Hosszú soak, teljes Kali release és minden master-specialista
elfogadását ez a szakasz nem állítja.
