# Indítás, konfiguráció, újraindítás és hibaelhárítás

Current [ffuf / Web View runbook](ffuf-discovery.md): explicit pinned installation, approved paths, kernel egress, restart/QoS deduplication and `redjohn view --assessment-dir`.

A [korlátozott automatikus session-helyreállítás](automatic-session-recovery.md)
explicit `continuous_replay.session_recovery` mellett kezeli a teljes 401-et és
az igazolt privát lejáratot. A tartós budget/cooldown hiányt vagy bizonytalan
mutáló kimenetelt nem kerüli meg. A valódi Linux-csoport külön futtatható:

```sh
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_AUTOMATIC_SESSION_MEASUREMENTS=/tmp/redjohn-automatic-session.json \
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_automatic_session_recovery_pipeline.py -q -s
```

Az [explicit continuous workflow](continuous-refresh-replay.md)
a futó schedulerben kapcsolja össze a sikeres refresh-t, friss Chromium-capture-t
és a kijelölt Nuclei-replayt. A szülő és az outbox, illetve a gyermekjobok és a
nyugtázás atomiak; `--max-jobs` minden végrehajtott lépést számol.

```sh
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_CONTINUOUS_REFRESH_MEASUREMENTS=/tmp/redjohn-continuous-refresh.json \
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_continuous_refresh_pipeline.py -q -s
```

A parancsok a repository gyökeréből futnak. A már működő `.venv` megmaradt;
a korábbi macOS-mérés Playwright 1.58.0 / Chromium 145.0.7632.6 verziót használt.
A Linux ARM64 ellenőrzőkörnyezet Chromium-verziója 145.0.7632.0. Az install
parancs **dependency-előkészítés**, a verziók a lockfájlban szerepelnek.

```bash
.venv/bin/python -m pip install -e '.[browser]'
.venv/bin/python -m playwright install chromium
```

Ez nem telepít Nucleit vagy opcionális scannerarzenált. A valódi Nuclei-engine
külön, explicit és checksum-pinnelt előkészítése lent szerepel. A normál `rj`,
`redjohn`, `redjohn view` útvonalak megmaradtak. Az új útvonal:

```bash
.venv/bin/redjohn assess --help
.venv/bin/redjohn assess health
.venv/bin/python -m redjohn.assessment demo --cycles 5 \
  --output redjohn_runs/local-assessment
```

Ez a korábbi HTTP-demo valódi local fixture-t, Chromiumot, SQLite inventoryt/
schedulert, HTTP-header megfigyelést, külön, lock nélkül blokkolt Nuclei-jobot
és explicit javított kontroll-retestet futtat. A Nuclei telepítésétől ez a demo
nem választ magától motort vagy template-et; a teljes HTTPS/Nuclei demonstráció
külön `https-demo` parancs. Nem használ LLM-et. Output:
`.state/agents.db`, `assessment-report.json`, `assessment-report.html`,
`benchmark.json`. A demo új engagementet hoz létre, a meglévő futásokat megőrzi.
A régi adatokat nem törli. A `health` csak capabilityt vizsgál; motorokat nem indít.

## Valódi HTTPS → inventory → Nuclei → tartós folytatás

A következő parancsok első két sorát a repository gyökeréből futtasd. Az installer
az ellenőrzött hivatalos v3.11.1 motort a `.tools/nuclei/3.11.1/` alá
telepíti, globális binárist vagy meglévő destinationt nem ír felül. A már sikeres
telepítést nem kell ismételni. A második parancs a saját ártalmatlan fixture
külön content-lockját állítja elő, abszolút helyi útvonalakkal.

```bash
.venv/bin/python scripts/install-nuclei-pinned.py
.venv/bin/python scripts/create-nuclei-fixture-lock.py
.venv/bin/python -m redjohn.assessment https-demo --output ../redjohn_runs/https-e2e
cd ..
```

A `https-demo` saját ephemeral HTTPS loopback fixture-t indít. Valódi Chromiumból
megfigyelt `/api/items` surface kerül tartós inventoryba, majd a Nuclei-job külön
CLI-processzben a tárolt surface/queue alapján fut. A következő processz azonos
jobbal ellenőrzi a dedupot, majd explicit új retestrevisionnel javított kontrollt
futtat. Az engine/template verzió a jobhoz kötött; eltérő lock blokkol.
A marker kezdetben candidate, a javított kontroll csak teljes 200-válasz és
markerhiány alapján negatív. Ez integrációs bizonyíték, nem CVE-/RCE-bizonyítás.

Az outputban `.state/agents.db`, JSON/HTML riport és
`https-e2e-measurements.json` keletkezik. A mérések a tényleges processzeket,
kérésszámot, tartós request budgetet, restart utáni duplikációt és proof levelt
rögzítik; a végrehajtott eredményeket az [ellenőrzési jegyzőkönyv](archive/redjohn-verification.md)
adja meg. A fixture CA-/kulcsfájljai csak a futás idejére élnek, a rendszer
truststore-ja nem módosul. Az output `fixture-config.json` fájlja ezért a demo
lezárása után nem használható változtatás nélkül élő célként: a fixture és CA-ja
már nem létezik. Új demo új engagementet hoz létre, a régi state megmarad.

A `https-demo` továbbra is saját literal-loopback labot használ. A távoli HTTPS
külön Linux enforcement-útvonal: az `enforced` megjelölés tényleges namespace-
attesztáció nélkül nem nyitja fel. Az upstream proxy HTTP/1.1-es subsetet kezel.

## Konfigurált helyi lab és tartós folytatás

Másold a `examples/assessment-local.json` fájlt, és a saját, előzetesen
engedélyezett loopback labod pontos originjét/portját add meg. Az ott szereplő
`127.0.0.1:3000` példa, a repository nem indít oda önkényesen szolgáltatást.

```bash
.venv/bin/python -m redjohn.assessment run \
  --config examples/assessment-local.json \
  --output redjohn_runs/approved-lab --max-jobs 16
```

Azonos konfigurációval és outputkönyvtárral újraindítva a már létező
jobkulcsok nem futnak újra. A queued/ready jobok folytatódnak. Lejárt running
lease bizonytalan kimenetelként lezárul; nem indít vak ismétlést. A konfigurált
run exit1 lehet, ha blocked/unsupported/inconclusive maradt, exit2 hibás
konfiguráció/hozzáférés. A példa lock nélkül futtatott Nuclei-ja szándékosan
látható coverage gap; telepítés és explicit konfigurált lock együtt szükséges.

HTTPS-labnál a konfiguráció `tls.upstream_ca_file` mezője adhatja meg a saját CA
PEM-fájlját; enélkül a rendszer hitelesített alapértelmezett CA-készlete érvényes.
A `nuclei_lock` a generált lock JSON objektuma, és a host ennek alapján készít
korlátozott `NativeFixtureSession`-t. Tetszőleges proxy-, shell- vagy engine-flag
nem adható jobopcióként. A CA-/hostname-ellenőrzés nem kapcsolható ki fallbackként.

Policy módosításakor növeld a revisiont. A policyhistory megmarad, korábbi
queued jobok blocked állapotba kerülnek, a running job cancellationt kap.
Ugyanaz a revision eltérő tartalommal nem fogadható el. A request/retrybudget
nem nullázódik restart vagy policyváltoztatás miatt. Retesthez új
`JobSpec.retest_revision`, új actor-sessionhez új `Surface.session_revision`
szükséges. A kis API ezt a host által beállított policy alatt validálja.

Ha nincs explicit epoch `deadline`, az első regisztráció egyszeri, tartós
egyórás határidőt állít be; restart nem hosszabbítja meg. Lejárt kampány
coverage/evidence állapota továbbra is olvasható, új végrehajtás blokkolt.

Named actorok programozott használatakor a host adja át a hozzáférés-védett
storage state-et az `AssessmentRuntime(actor_states=...)` paraméterében.
Ajánlott forma:

```python
actor_states = {
    "alice": {
        "actor_id": "alice",
        "tenant_id": "tenant-a",
        "session_revision": "2",
        "storage_state": load_from_private_secret_store(),
    },
}
```

A példa nem tartalmaz credentialt. Üres/hiányzó/eltérő revisionű state blokkol;
401 után nincs anonim fallback. Az explicit session refresh külön, privát
providerrel konfigurált scheduler-job; az interaktív bejelentkezési wizard és
a teljes login/MFA-workflow továbbra sincs implementálva. Azonos actor neve önmagában nem
bizonyít helyes bejelentkezést: megfelelő readiness és sessionellenőrzés kell.

## Valódi Chromium POST-capture és body-token frissítés

A külön `browser_post_capture` capability a tényleges headless Chromium által
küldött JSON/form/multipart bodyt figyeli. A privát `browser_capture_file` exact
actor/tenant/policy/session/URL/media-type és `automatic_approval=true` szabályt
igényel; a sima `browser_discover` read-only marad. Csak teljes 2xx transportproof
után kerül valódi observed SHA/ref és jóváhagyás a privát v2 vaultba.

A privát rule `start_url` + `session_revision="current"` mezőivel az induló
koordinátor determinisztikus nem idempotens capture-jobot queue-z. Frissítés után
az újraindítás az új revision capture-jét készíti elő. Nuclei-template és
scanner-job továbbra is explicit review/selection, nem automatikus toolindítás.
Az induló current-identityhez privát credential/start-anchor kell; üres vault nem
helyettesít loginfolyamatot.

```bash
PYTHONPATH=. .venv/bin/python -m redjohn.assessment run \
  --config /absolute/private/assessment.json \
  --output /absolute/redjohn-runs/approved-assessment --max-jobs 1

REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_BROWSER_TOKEN_MEASUREMENTS=/tmp/redjohn-browser-token.json \
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_browser_token_pipeline.py -q -s
```

A reviewzott `body_tokens` deklaráció csak a kiválasztott JSON-stringet,
formértéket vagy multipart text-payloadot frissíti; uploadot nem. Az új body/SHA
pending lesz, és csak valódi friss browser-capture oldhatja fel. Multipartnál
csak az érvényes boundary framing változhat; partheader/order/payload byte-azonos.
A fix `multipart/form-data; boundary=REDJOHN_HOST_REPLAY_BOUNDARY_V1` template-header
és a meglévő body-sentinel mellé a host injektálja az aktuális privát értékeket.

A teljes privát séma, limitek, bootstrap és recovery:
[browser/body-token workflow](browser-post-body-tokens.md).
Az aktuális, valódi Chromium-lánc mérését az
[új jegyzőkönyv](archive/redjohn-browser-token-verification.md) külön tartalmazza;
a korábbi HTTPX capture-mérés ettől nem válik browser-bizonyítékká.

## Távoli HTTPS és autentikált Nuclei-replay

A remote mód Linuxot, `bubblewrap`-ot, működő unprivileged namespace-eket és
`SO_PEERCRED` peer-ellenőrzést igényel. A policy `egress_mode` értéke `enforced`,
az `allowed_origins` pontos HTTPS-originlista, az `allowed_ips` külön IP/CIDR
allowlist. Minden DNS-válasznak bele kell férnie; a proxy jóváhagyott numerikus
IP-re kapcsolódik az eredeti hostname/SNI megtartásával. A discovery nem ad új
célengedélyt. A Chromium/Nuclei a kernelből attesztált, csak loopback interfészű
namespace-ben indul; hiányzó enforcement blokkolás, nem fallback.

Named-actor Nucleihoz a host `AuthReplayVault`-ot adhat át a runtime-nak, a CLI
pedig explicit `auth_vault_file` konfigurációs mezőt fogad. Ez egy legfeljebb
256 KiB-os, aktuális tulajdonú, `0600` regular file; symlink/hardlink tilos.
Ne kerüljön a repositoryba vagy riportkönyvtárba. A vault a policy/actor/tenant/
sessionrevision és az observed, ténylegesen elküldött kérés pontos URL/metódus/
request-ref kombinációjára ad véges engedélyt. Az imported seed nem auth-capture.
Az új session credentialje nem írhatja át csendben a korábbi jobot.

A GET/HEAD mellett explicit, legfeljebb 64 KiB-os JSON/form/multipart POST replay
is támogatott, `active-staging` vagy `isolated-lab` profillal, exact
`allowed_replay_urls` listával, privát v2 vaulttal és valódi sent/body-SHA
capture-rel. A reviewed template csak `REDJOHN_HOST_REPLAY_BODY_V1` sentinelt
kap; a privát byte-okat a host proxy injektálja. Capture és POST-job nem
idempotens, a tartós capture-reservation és request-budget atomikus.

A `refresh_provider_file` + `auth_vault_file` külön `session_refresh` jobot köt a
schedulerhez; ehhez exact `allowed_refresh_urls`, üres options és
`idempotent=False` kell. A header/cookie/CSRF credential és numerikus revision
frissül; régi job/capture nem íródik át, új revisionhöz friss observation kell.
Bodyba ágyazott token csak explicit body_tokens bindinggal frissül; provider-refresh-token
automatikus rotációja, XML replay,
valamint interaktív secretbeállító wizard nincs. A teljes séma és SDK-példa:
[POST/session workflow](post-refresh-replay.md).

Redirect, más URL/metódus, lejárt vagy eltérő actor/tenant/session nem negatív
check; nincs anonim fallback vagy ismeretlen mutáló kérés automatikus újraküldése.
A namespace- és TLS-határokat a
[remote/auth dokumentum](remote-egress-auth.md) rögzíti.

A POST/refresh lánc külön futtatandó a korábbi GET/HEAD E2E mellett:

```bash
REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_POST_REFRESH_MEASUREMENTS=/tmp/redjohn-post-refresh.json \
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_post_refresh_pipeline.py -q -s
```

A végleges aktuális eredményt a [POST/session mérési jegyzőkönyv](archive/redjohn-post-refresh-verification.md)
őrzi; a lenti korábbi GET/HEAD parancsok külön workloadot igazolnak.

Az előkészített Linux környezetben a valódi ellenőrzés:

```bash
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_assessment_egress.py -q -s

REDJOHN_REQUIRE_REMOTE_E2E=1 \
REDJOHN_REMOTE_E2E_MEASUREMENTS=/tmp/redjohn-remote-auth-e2e.json \
PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_remote_authenticated_pipeline.py -q -s

PYTHONPATH=. .venv/bin/python -m pytest \
  tests/test_nuclei_auth_live.py \
  tests/test_assessment_auth_replay.py -q -s
```

A remote fixture a teszt saját HTTPS-szolgáltatása valódi, nem loopback lokális
interfészen; nincs idegen internetes célvizsgálat. A require kapcsoló hiányzó
Linux/bwrap/Chromium/Nuclei esetén failt ad, nem skipet. A namespace-only eredmény,
a helyi auth-engine teszt és a teljes remote browser–inventory–scheduler–Nuclei
lánc külön bizonyíték. A korábbi loopback-jegyzőkönyvek történeti baseline-ok.
A sikeres Linux lánc kérésszáma, kontrolljai és coverage-határai a
[remote/auth mérési jegyzőkönyvben](archive/redjohn-remote-auth-verification.md) vannak.

Linuxon célszerű dedikált systemd scope-ban futtatni a mérést, hogy más build/
download folyamat ne terhelje ugyanazt a cgroupot. A memóriaadmission a process-
tree RSS és a saját cgroup `memory.current - inactive_file` maximuma; a nyers
értékek a snapshotban is megmaradnak. Hiányzó `memory.stat` mellett a teljes
`memory.current` számít. A systemwide gyökér-cgroup nem admissionforrás. Ez nem
OS hard memory-limit és nem indokol budgetemelést hibás mérés elfedésére.

A `.github/workflows/redjohn-remote-egress.yml` az `akosdrx/redjohn` repositoryhoz
előkészített workflow. A helyes repositoryhoz nem állt rendelkezésre GitHub-auth,
ezért nincs itt elvégzett CI-futtatást igazoló állítás; a Linux VM-teszt külön mérés.

## Nuclei

A meglévő `hunt` útvonalhoz külön engine- és teljes bundle-lock kell.
Séma, támogatott template subset, API, parser/partial szabályok:
[Nuclei-integráció](nuclei-integration.md).
Telepített motor nélkül ne készíts fiktív lockot. A fenti explicit pinned installer
a tényleges hivatalos executable-t, MIT licencet és provenance receiptet menti,
a fixture-lock pedig csak a saját reviewed marker template-et engedélyezi.
A `scripts/install-kali.sh` külön meglévő motort/templates-t használ;
templatefrissítés csak explicit `REDJOHN_UPDATE_NUCLEI_TEMPLATES=1` installkori
döntés. Kampány közben nincs engine-/template-update.

A hiányzó bináris, hiányzó lock, template- vagy verzióeltérés külön állapot.
Engine exit0 és üres stdout sem bizonyít negatív eredményt, ha nem igazolható
minden reviewzott cél-URL teljes, bounded 2xx-válasza. 401/403/429/5xx, rossz CA/
hostname, policy- vagy request-budget elutasítás, csonka válasz és outputlimit
nem negatív. HTTPS-hez a controller által kötött, upstream TLS-t ellenőrző proxy
és response observer kötelező. A match candidate marad.

## Reprodukálható ellenőrzés

```bash
# A jelenleg elérhető teljes Python-tesztkészlet:
.venv/bin/python -m pytest tests -q

# Valódi Chromium + a valódi browser/persistent-pipeline integráció:
REDJOHN_BROWSER_SOAK_CYCLES=20 .venv/bin/python -m pytest \
  tests/test_assessment_browser.py \
  tests/test_assessment_pipeline.py -q

# SQLite/policy/cache/skills és fault/kontraktus tesztek:
.venv/bin/python -m pytest tests/test_assessment_scheduler.py \
  tests/test_assessment_resource_control.py \
  tests/test_assessment_intelligence.py \
  tests/test_assessment_skills.py -q

# Valódi Chromium HTTPS + per-request proxy, majd tartós Nuclei E2E:
.venv/bin/python -m pytest tests/test_assessment_browser_https.py \
  tests/test_assessment_browser_proxy_https.py \
  tests/test_assessment_https_e2e.py \
  tests/test_assessment_https_pipeline_failures.py -q

# Valódi pinned Nuclei-engine, saját HTTP(S) fixture (nem telepít dependencyt):
.venv/bin/python -m pytest tests/test_nuclei_live.py -q -rs

# Mock scanner + valódi supervisor-processz; külön mock installer download:
.venv/bin/python -m pytest tests/test_hunt_nuclei.py \
  tests/test_native_fixture_session.py \
  tests/test_nuclei_installer.py -q

# Hosszabb, foreground helyi pipeline-mérés (a tényleges időt jelenti):
.venv/bin/python -m redjohn.assessment demo --cycles 100 \
  --output redjohn_runs/soak-local
```

100 ciklus nincs ettől automatikusan lefuttatva. A végrehajtott ciklusszámot,
időt és módszert a mérési JSON igazolja. A standalone browser-service teszt
és a demo eltérő workload: az utóbbi batchenként lezárja a Chromiumot, hogy
két koordinátor ne tarthasson a flockon kívül külön idle browserpoolt.

## Hibaelhárítás

| Jelzés | Jelentés / teendő |
|---|---|
| `blocked_missing_dependency`, `tool_missing` | Hiányzó dependency; telepített bináris/lock igazolása kell, nem negatív teszt |
| `unsupported_browser_input` | Nem támogatott browser-input/metódus; a helyi HTTPS önmagában már támogatott |
| `nuclei_upstream_tls_denied` / TLS-failure | A saját CA, lánc vagy hostname ellenőrzése sikertelen; nem negatív check és nincs TLS-kikapcsolás |
| `https_requires_verified_egress_proxy` | A Nuclei HTTPS-hívásból hiányzik a controller által kötött ellenőrző proxy/response observer |
| `nuclei_job_lock_version_mismatch` | A tartós job engine-/bundle-verziója eltér az aktuális locktól; ne írd át a régi job bizonyítékát |
| `nuclei_proxy_limit_exceeded` | A teljes, bounded válasz nem igazolható; a részleges állapot nem negatív |
| `blocked_egress_enforcement_unavailable` | Külső célhoz tényleges infrastruktúrahatár hiányzik; konfigurációval nem kerülhető meg |
| `blocked_linux_network_namespace_required`, `blocked_bubblewrap_missing` | A remote workerhez hiányzik a támogatott Linux-határ/dependency; helyi loopback eredmény nem helyettesíti |
| `blocked_namespace_attestation_failed`, `egress_boundary_not_attested` | A kernelből ellenőrzött izoláció nem igazolt; ne indítsd a workert közvetlenül |
| `resolved_ip_denied`, `remote_special_address_denied` | DNS-/IP-cél nem felel meg az explicit remote allowlistnek; nincs scope-bővítés |
| `auth_replay_expired`, `auth_replay_identity_or_request_mismatch` | Friss, pontosan ugyanahhoz az actor/tenant/session/requesthez engedélyezett host-vault szükséges; nincs credential/anonim fallback |
| `auth_replay_capture_unavailable`, `auth_replay_capture_identity_mismatch` | Hiányzó vagy eltérő valódi request-evidence; imported seed nem bizonyít auth-replayt |
| `authentication_state_missing` / revision mismatch | Ugyanazon actor megfelelő state/revision betöltése szükséges; anonim fallback tilos |
| `capture_in_progress`, `capture_uncertain`, `capture_outcome_uncertain` | Tartós capture-reservation; concurrent/unknown mutáló kérés nem küldhető újra automatikusan |
| `session_revision_superseded`, `session_refresh_uncertain` | Régi revision blokkolt; server/private state reconciliation és friss, reviewzott policy/vault szükséges |
| `session_refresh_vault_changed` | A párhuzamos kézi vaultmódosítás megmarad; az új credential eredménye uncertain, nincs automatikus overwrite/retry |
| `coordinator_already_running` | Azonos DB-n más koordinátor dolgozik; ne indíts második poolt |
| `resource_exhausted` | Admission/queue/request keret elérve; a részleges evidence megmarad |
| `rate_limited` | Origin/group/account cooldown a `rj_rate_limit` SQLite táblában; újraindítással sem törlődik; nincs proxy- vagy identitásrotáció |
| `blocked_configuration` / `reviewed_template_lock_not_configured` | Az engine jelen van, de nincs futáshoz kiválasztott reviewzott lock; telepített bináris nem jelent scan-ready állapotot |
| `unknown_execution_outcome` | Lejárt running lease; előbb reconciliation, csak utána explicit retest |
| `evidence_write_failed` | Kontrollált leállítás; tárhely/kvóta helyreállítása kell, confirmed állapot nem keletkezik |
| `adapter_not_implemented` | A skill/név nem jelent valódi adaptert; nem dependencytelepítési hiba |

Megszakításra a caller-bound `jobs_cancel` API vagy foreground Ctrl-C szolgál.
Nincs új publikus debugger/MCP/HTTP port; a saját proxy csak dinamikus
literal-loopback portot használ, majd bezár. Hosszú távú audit-retention,
automatikus evidence-GC, production kernel hard limit, teljes régi agentpolicy
migráció és Kali release/CI teszt továbbra is nyitott.
