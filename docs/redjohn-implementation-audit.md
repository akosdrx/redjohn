# RedJohn implementációs audit

2026-10-18 MIME/restart folytatás: byte-megőrző, verziózott MIME-értelmezés,
Chromium-default UTF-8 charset és idézett multipart boundary; pontos, titokmentes
policy-hibaok és azonnali auth-admission kerítés. [Új mérések és diagnózis](archive/redjohn-mime-restart-verification.md).

2026-10-18 aktuális folytatás: autentikált TInjA/Schemathesis/Interactsh POST,
JSON/form/multipart mezőváltoztatás és tartós refresh → friss Chromium-capture →
új adapterjob. [Aktuális ellenőrzések és korlátok](archive/redjohn-authenticated-schema-oast-verification.md).

2026-10-18 újabb folytatás: pinned TInjA / Schemathesis profilok és saját
Interactsh receiverrel ellenőrzött host-protokollkliens, tartós late-poll outbox
és véges CLI-várakozás. [Aktuális profilok, tesztek és hiányok](archive/redjohn-schema-oast-verification.md).
Az alábbi korábbi mérési körök továbbra is történeti bizonyítékok.

2026-10-18 specialist folytatás: Arjun 2.2.7 / sqlmap 1.10.10 / Dalfox 3.2.4
GET-adapterek, meglévő scheduler/egress/vault újrahasznosítással és külön tartós
Chromium XSS-megerősítéssel. [Mérési jegyzőkönyv](archive/redjohn-specialists-verification.md),
[angol használati leírás](query-specialists.md). A korábbi
megfigyelések történeti állapotok; az új folytatás nem jelenti a teljes
platform vagy valamennyi inputformátum elfogadását.

Dátum: 2026-10-17. Specifikáció: `REDJOHN_FULL_BUILD_MASTER_PROMPT_HU.md`, 2.0,
675 sor, teljes egészében elolvasva. A dokumentum az audit és az ezt követő
implementáció eredményét külön jelöli. A teljes master prompt elfogadása még nem
teljesült. Az alábbi kiinduló táblázat és HTTP-only korlátleírás történeti
auditpillanatkép; a későbbi implementációk és mérések felváltják.

Aktuálisan valódi HTTP(S) Chromium/Nuclei, autentikált POST/session recovery és
Linux kernel-egress működik saját cél-fixture-ön. Az ffuf tartós felderítése és
az assessment Web View is elkészült. [Aktuális eredmények és nyitott részek](archive/redjohn-ffuf-verification.md).

2026-10-18: a httpx, standard Katana és VulnX adapterek a tartós schedulerhez
csatlakoznak. A saját HTTPS-fixture-lánc és a valódi publikus VulnX-adatforrás
külön ellenőrzés. A forrás-/licenc-/verziópinek, mérési bizonyítékok és
platform-/URI-korlátok az [új ellenőrzési jelentésben](archive/redjohn-projectdiscovery-verification.md)
találhatók. A történeti kiinduló táblázat alább változatlanul megmarad.

## Kiinduló állapot

- Ellenőrzött aktuális origin: `https://github.com/akosdrx/redjohn.git`;
  a korábbi `itsolutionshu/rjkali` hivatkozás helyesbítve. A meglévő checkout és
  a felhasználói munka maradt meg. A kezdeti commit:
  `115c7958232f1be5b34fe95159b21b86e85af06f`.
- A működő forrás a `` alkönyvtárban található. Csomag:
  `redjohn-agent` 1.7.0, CLI: `redjohn`, `rj`. Python backend, Go TUI,
  React/Vite viewer. Nincs átnevezés vagy platformcsere.
- Induláskor 508 `RD`, 485 `D`, 2 `M`, 1 `AD` Git-bejegyzés és sok untracked
  `` fájl volt. Ezek korábbi felhasználói munkák. Nem futott reset,
  clean, checkout, commit vagy push. A pontos állapot és fájlhash-ek:
  `redjohn-initial-state.json`. A snapshot az audit során készült; két új
  erőforrásmodul már létrejött benne, ezért nem teljesen érintetlen checkout.
- A munkagép macOS ARM64, a céltermék Kali Linux. Ez nem Kali/Linux release-teszt.
- Kiinduló tényleges teszt: `.venv/bin/python -m pytest tests -q
  --disable-warnings --maxfail=3`: **7 passed, 0.11 s**. A Gitben törölt régi
  teszteket nem állítottuk vissza és nem számítottuk a lefutott készlethez.
- Régi, összehasonlítható browser-workload nem volt: **baseline_unavailable**.
  Az új mérésekből nem állítunk régi/új gyorsulási százalékot.

## Meglévő képesség, hiány és újrahasznosítás

| Terület | Auditált meglévő kód | Változtatás és határ |
|---|---|---|
| Browser | `redjohn/tools/agent_browser/README.md`: agent-browser CLI; nincs host-side determinisztikus Playwright-service | Új bounded Playwright-service és HTTP-proxy; a régi agent-browser megmarad |
| Proxy/replay | `redjohn/tools/proxy/caido_api.py`, `runtime/caido_bootstrap.py`, SDK toolok | Megőrizve. Caido bináris/élő szolgáltatás itt nem igazolt; browser-metaadat nem bájthű capture |
| Nuclei | `redjohn/tools/hunt/tool.py`: egyetlen motorútvonal, `session.exec(shell=False)`, severity/tag szelekció, kimenet utólagos vágása | Ugyanazon hunt megerősítése explicit lockkal, subset-template ellenőrzéssel és bounded supervisorral; nincs második motor |
| Nuclei függőség | Nincs `nuclei` a PATH-ban és az ellenőrzött szokásos helyeken; nincs telepített template-bundle lock | `blocked_missing_dependency`, valódi Nuclei-futás nem igazolt |
| Agent | `agents/factory.py`, `core/runner.py`, meglévő OpenAI/LiteLLM és providerintegrációk | Megőrizve; egy új caller-bound `assessment_control` tool. A rutin új pipeline 0 modellhívással működik |
| Ütemezés | SDK agent orchestration, lease-es, gépi tesztcsalád-scheduler nem volt | Új tartós fair scheduler, idempotens kulcs, attempt, heartbeat, cancellation, restart reconciliation |
| Adatok | `.state/agents.db` SDK SQLite session, JSON report/coverage | Ugyanabba az SQLite adatbázisba additív `rj_*` táblák. SDK táblák érintetlenek |
| Memória | LLM model-meta LRU, token counter/fallback és compaction már létezett; egyes globális dict-ek nem bounded | Új admission governor, process-tree RSS, cachekvóta, bounded frontier/output/evidence, token-budget szerződés. Régi globális sessioncache teljes migrációja még hiányzik |
| Intelligence | `tools/cve/tool.py` meglévő NVD/OSV/KEV/EPSS integráció | Megőrizve. Új bounded applicability/correlation/logika fixture-tesztelve; élő új VulnX-adapter nincs |
| Skillek | 12 rövid, meglévő koordináció/domain/tooling kontraktus | Megőrizve; 47 új app-native, lazy kontraktus és capability-ellenőrző registry a felhasználó csomagja alapján |
| Firecrawl | A forrásaudit nem talált aktív Firecrawl-integrációt | Nem került be dependency, adapter vagy konfiguráció; Firecrawl eszközt sem használtunk |
| CI/lock | Frontend package-lock volt; Python frozen lock és aktív CI nem volt a hozzáférhető forrásban | Új böngészős függőségpin és reprodukálható helyi tesztparancsok; CI-futás nincs állítva |

## Kompatibilitás és fennmaradó kockázatok

A `rj assess` új determinisztikus útvonal. A hagyományos interaktív `rj`/TUI
továbbra is a meglévő agent/shell/proxy workflow; annak teljes, kernel-szintű
policy-migrációja **nincs kész**, és nem tekinthető az új útvonallal azonos
biztonsági határnak. A `hunt` policy nélkül már blokkol, és specialistahiányt
jelent; nincs szabad shellre visszaesés. A rendszerprompt régi „négy scanner egy
fordulóban” utasításait eltávolítottuk, de az érvényes korlátot programkód adja.

A determinisztikus browser most **HTTP + explicit loopback lab-fixture** módot
támogat. HTTPS CONNECT nem adna ellenőrizhető kérésenkénti keretet, ezért
unsupported. Külső web/network/cloud/Kubernetes profilt a policy blokkol, amíg
a tényleges worker/kernel egress nincs implementálva és ellenőrizve. Egy
konfigurációs `enforced` szöveg önmagában nem oldja fel ezt.

A Nuclei-adapter szándékosan szűk, felülvizsgált, read-only HTTP-template
subsetet támogat. Dinamikus, raw/DSL/code/file/headless/OAST képesség nem lesz
hallgatólagos fallback. A valódi motor és templatecsomag telepítése, lockja,
verziókompatibilitása és élő forgalombizonyítéka továbbra is külön ellenőrzendő.
Részletek: [Nuclei-integráció](nuclei-integration.md).

Az eredeti kimaradt RCE mechanizmusa/fixture-je nincs megadva:
**not_reproduced_missing_fixture**. A helyi marker-, header- és routingteszt
nem valódi RCE-detektálás és nem teljes sérülékenységi lefedettség.


### 2026-10-18: selected TInjA / Schemathesis / Interactsh

The current implemented profiles use actual captured anonymous GET inputs,
pinned TInjA 1.2.0 / Schemathesis 4.31.1, and a host Interactsh 1.4.1 protocol
client with an owned receiver and durable late polls. Scanner/callback signals
remain candidates. Broad API/GraphQL, body/auth mutation and public DNS OAST
are separate coverage gaps. See `docs/redjohn-schema-oast-verification.md`
and `docs/schema-oast-adapters.md` for current evidence and bounds.

## Authenticated schema/OAST follow-up (2026-10-18)

The three selected adapters reuse the existing private replay vault, Chromium capture,
body-token rotation and transactional recovery outbox. Adapter-only continuous
configurations need no Nuclei lock; mixed existing rules retain their lock requirements.
A public input projection protects credentials/uploads from scanner workers.
See [the scoped verification](archive/redjohn-authenticated-schema-oast-verification.md) for
actual tests, source hashes, measurements and remaining coverage gaps.
