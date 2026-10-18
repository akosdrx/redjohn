# RedJohn determinisztikus assessment-réteg

Current extension: [ffuf and assessment Web View](../RedJohn/docs/ffuf-discovery.md). Reuses the proxy/governor/supervisor; only selected jobs launch the optional executable. Cancellation retains committed evidence. Reports use the configured capability registry.

Az új réteg a meglévő Python-csomag része. Nincs második platform,
adatbázismotor, Redis, Temporal, Neo4j, Crawlee queue vagy LLM-kötelezettség.

Az aktív assessment-foglalásokat most egy privát, felhasználónként közös SQLite
ledger koordinálja (`~/.redjohn/resources/host.sqlite3`). Erre a külön kampány-DB-k
közötti atomikus kapacitáskezeléshez van szükség; nem új adatbázismotor vagy
szolgáltatás, és nem tárol kampányt/sessiont/evidence-t. A régi interaktív runtime
SDK-műveletei is ugyanazon governorhoz kötődnek: a modellek aktív hívásra,
a Shell/PTY a teljes processz-élettartamra, az MCP stdio-kapcsolatok az idle
időszakra is foglalnak. A CVE-cache külön korlátos RAM/disk tárolót és közös
governorhoz kötött refresh-foglalást használ. Ez nem zárja le a generikus MCP
szemantikai célengedélyezését vagy minden sandbox backend hálózati bekötését.
[Jelenlegi legacy-kontraktus](redjohn-legacy-execution.md),
[cache/session-életciklus](redjohn-legacy-cache-lifecycle.md).

Az explicit `os_memory` profilban a supervisor exec előtt cgroupba helyezi az új
CLI-controllert. Ugyanaz a scheduler és adapterlánc fut benne. A kernelhatár
ellenőrzése, az OOM evidence és a halott ownerhez tartozó processzfa lezárása
tényleges implementáció. A supervisor RAM-ja a host-admissionben számít; a
dedikált CLI hard limitje különbözik egy teljes hostra vonatkozó OS-kerettől.
[Kontraktus és határok](../RedJohn/docs/shared-resources-and-os-memory.md).

```text
operator configuration / caller identity
    -> EngagementPolicy
    -> BrowserDiscoveryService + BrowserEgressProxy
    -> rj_surface / immutable rj_evidence
    -> IntelligentDecisionEngine -> durable rj_job / rj_attempt
    -> Scheduler -> ResourceGovernor -> selected adapter
    -> evidence / separate execution, coverage, finding states
    -> escaped JSON/HTML report -> explicit versioned retest
```

## Állapot és migráció

`AssessmentStore` az SDK meglévő `.state/agents.db` fájlját használja additív
`rj_*` táblákkal. A `rj_schema` az új sémaverziót kezeli. Policyhistory,
surface, job, attempt, fairness, plannercursor, evidence, finding és audit
tartós. A technology/correlation modul ugyanott saját indexelt táblákat nyit.
Az SDK táblanevei, meglévő providerkonfiguráció és JSON jelentései megmaradnak.
Adatbázis-visszaállítás előtt a teljes `.state` mentése szükséges; automatikus
destruktív down-migráció nincs.

Az idempotenciakulcs pontos URL-t, metódust, content type-ot, inputhelyet és
nevet, actort/tenantet, sessionrevisiont, workflowt, policy/profile/tool/template
verziót és explicit retestrevisiont használ. Nem rendezi át a queryt és nem
egységesíti a percent-encodingot. Priority/timeout/idempotent flag módosítása
nem jogosít új hálózati próbára. A régi adat provenance-e nem írható felül
inference-szel; a valódi megfigyelés feljebb léptetheti az inferred endpointot.

## Ütemezés és hiba

A `BEGIN IMMEDIATE` tranzakció foglal jobot. A fair családszámláló tartós;
a következő terv kihagyja a már létező jobkulcsokat. Az inventoryt keyset
lapokban olvassa, egy terv legfeljebb 512 surface-t vizsgál, és tartós cursorral
folytat. A kiválasztás és a végrehajtás modellfüggetlen. Egy batch sorosan
indítja a kiválasztott workereket; opcionális motorlista nem indul automatikusan.
A DB-hez tartozó POSIX flock kizárja a párhuzamos koordinátorokat ugyanazon
assessment-adatbázison. A külön kampány-DB-k közös felhasználói host-ledgere
atomikus foglalással és owner/processz-helyreállítással együttműködő globális
admissiont ad. Ez nem teljes hostra érvényes kernel-RAM-korlát; az explicit
Linux cgroup-profil külön, exec előtt alkalmazott hard limit.

A lease/heartbeat tulajdonoshoz és attempthez kötött. Lejárt lease esetén
`unknown_execution_outcome` + `inconclusive`; nincs vak újraküldés. Csak a
küldés előtti cooldown kaphat automatikus, véges retryt, közös tartós retrybudgettel.
Timeout/módosító workflow bizonytalan kimenetele explicit reconciliationt vagy
retetst igényel. A circuit breaker bounded és origin/tool szerint különül el.
Cancellation leállítja az admissiont, lezárja az auditot és felszabadítja a lease-t.

## Browser és hálózat

Egy service egy Chromiumot birtokol. Actor/session futásonként új context,
admission a process/context/page előtt, bounded frontier/DOM/requests. Nincs
formsubmit, ismeretlen click vagy automatikus logout-link követés. A seed
navigáció explicit, további navigáció csak külön allowlisten engedélyezett.
Readiness selector + határidő; nincs kizárólagos networkidle-függés.

A proxy minden tényleges HTTP(S)-kérésnél policyt, közös read-only guardot és
tartós requestbudgetet ellenőriz. A redirect új ellenőrzést/admissiont igényel.
HTTPS-nél a CONNECT-et saját ephemeral certtel terminálja; a dekódolt HTTP/1.1
metódust, célt és headereket az upstream kapcsolat megnyitása előtt vizsgálja.
Az upstream CA-/hostname-ellenőrzés szigorú, saját labhoz explicit PEM CA adható.
Chromium csak a saját ephemeral leaf kulcsának pontos SPKI-pin exceptionjét kapja;
nincs globális ignore-TLS flag vagy truststore-import. A privát certkönyvtár és
kulcsok cleanupkor eltűnnek. A `local-fixture` profilban csak explicit literal
loopback engedélyezett, DNS alias nem. Browser-routing további védelem. JavaScript
aktív; a módosító JS request metadata megfigyelhető, de `sent=false`, és nem
számít végrehajtott bodytesztnek. Service worker/WebSocket/meta-capture korlátok
a resultban megmaradnak.

Az `enforced` remote út külön Linux user/network/mount/PID namespace-t indít a
Chromium/scanner workerhez. A controller `SO_PEERCRED`, `/proc/<pid>/ns`, interfész-
és privilegizációs adatok alapján attesztál; csak loopback, effective-capability 0
és `NoNewPrivs` engedett. A csak a kiválasztott host-proxyhoz vezető privát Unix
relay ellenőrzi a peer és a namespace tulajdonát. Hiányzó támogatás/attesztáció
blokkol, és nincs közvetlen subprocess-fallback. A trusted controller maga
megtartja az upstream networkjogot; ez nem hostglobális firewall.

A remote policy csak HTTPS-t és explicit IP/CIDR allowlistet enged. DNS esetén
minden feloldott címnek illeszkednie kell, a connect jóváhagyott numerikus IP-t
használ az eredeti TLS hostname/SNI megtartásával. Loopback/link-local/multicast/
unspecified cím remote módban tiltott. A policy `enforced` stringje nem attesztáció.

Named actorhoz hiányzó/eltérő revisionű storage state blokkolás; nincs anonim
fallback. A runtime csak host által betöltött állapotot fogad, a kis vezérlő API
nem ad credential-feltöltési műveletet. A raw állapot nem kerül promptba/Gitbe.

A `PersistentRateLimitDetector` az eredeti in-memory limiterrel kompatibilis
admission/observe felületet ad, de az origin/group/account ablakok és 429/503
cooldownok a `rj_rate_limit` táblába kerülnek. UTC határidők, indexelt expiry,
legfeljebb 2048 aktív hash-scope és egy vezérlőrekord; három scope terhelése
egy `BEGIN IMMEDIATE` tranzakció. A browser, HTTP és Nuclei ugyanazt használja;
a SQLite újranyitása sem törli a várakozást. Az engagement request budget külön
tartós korlát marad. Lejárt rekord törölhető, aktív limit kapacitás miatt nem.

## Memória, cache, evidence

`ResourceEnvelope` valódi validációt és admissiont ad. A process-tree RSS
összege tartalmazza a gyermekfolyamatokat/Chromiumot, de osztott lapot többször
számolhat. Linuxon az admission a process-tree RSS és a saját cgroup-v2
`memory.current - inactive_file` maximuma. A nyers `memory.current` és
`inactive_file` érték külön telemetria; hiányzó `memory.stat` esetén nincs
feltételezett levonás. A rendszer gyökér-cgroupja nem használható saját munkaként.
Így a letöltések reclaimable page cache-e nem válik automatikusan worker-RSS-é,
az aktív memória és a tényleges process-tree RSS viszont nem tűnik el. A macOS
mérésben cgroup-adat nincs. A soft/high/resume watermark konfigurálható hiszterézis,
nem minden gépre igazolt optimális százalék. Ez együttműködő admission,
nem OS-szintű hard RAM-limit. Az utóbbi production előtt még szükséges.

A SmartCache serializált JSON bájtokra és elemszámra korlátos LRU/TTL,
bounded single-flight workerpoollal. Retest és idő-/authállapot-érzékeny család
bypassolja. Session/policy/deploy revision kulcsrészek és explicit invalidálás
védik a frissességet. A Python callback maga köteles saját I/O deadline-t tartani;
a timeout nem öl meg tetszőleges threadet, a foglalt slot viszont nem pótolható
korlátlan új threaddel. Az evidence SQLiteban külön kvótás, immutable, nem LRU.
Automatikus evidence-retention/GC és auditrotáció még nincs; a quota blokkol.

A HTTP worker raw encoded bodyt streamel quota mellett, így nem fejt ki előbb
óriási gzip bodyt. A Nuclei worker külön stdout/stderr drain, outputkvóta,
timeout és TERM/KILL supervisor. A képernyő-/HAR/trace-capture nem alapértelmezett.

A `benchmarks/mixed_soak.py` a meglévő queue/governor/proxy útvonalakat használja,
nem második ütemezőt. A valódi Chromium/httpx/Nuclei oracle-ciklusoktól külön
jelöli a tényleges processz/socket/SQLite limiteket terhelő szintetikus bemenetet.
A hiányzó mérés, cleanup, engine vagy hibás forrásazonosság nem siker.
[Mérési kontraktus és célzott eredmény](redjohn-mixed-soak-verification.md).

## Meglévő Nuclei a tartós HTTP(S) láncban

Az explicit pinned installer által előkészített hivatalos v3.11.1 executable
hash/verzió/forrás/MIT licence lockja elkülönül a saját reviewed template-bundle
content-lockjától. Teljes upstream template-készlet nem települ. A runtime
host-oldali `NativeFixtureSession` transportja csak a megbízható supervisor-
forrást, lockból rekonstruált argv-t és pontos processzcancel műveletet engedi;
nem tetszőleges shelltool. A scheduler ResourceGovernor-foglalás után egyesével
indítja a kiválasztott scanner-jobot. A browser és a Nuclei ugyanazon tartós
inventory/evidence/job/fairness/rate/request-budget szabályokat használja.

A NucleiPipelineAdapter csak a controller által létrehozott dinamikus loopback
proxy URL-jét köti a sessionhöz; `-proxy` és `-proxy-internal` biztosítja ezt az
engine útvonalán is. HTTPS proxy/response observer nélkül blokkolt. A proxy
minden valódi kérés előtt von le a tartós budgetből; nincs második pre-reservation
vagy rejtett hálózati retry. A job engine- és bundle-verziója megegyezik a lockkal,
a meglévő queued job nem írható át egy új lockra.

A response callback csak teljes, framing-ellenőrzött, bounded válasz után fut,
szűk URL/státusz/Content-Type/Retry-After metaadattal. Minden template-ből számolt
URL teljes 2xx-válasza, sikeres engine-exit és hibamentes parser/proxy szükséges
az üres output befejezett negatív értelmezéséhez. 401/403/429/5xx, TLS/scope/budget
elutasítás vagy csonkolás nem negatív. A hit candidate marad. Az immutábilis
nyers/normalizált evidence és a külön retestrevision őrzi a korábbi candidate-et.
A `https-demo` külön CLI-processzek között igazolja a browserből megfigyelt
surface-re queue-zott Nuclei-jobot, a restart dedupot és a javított kontrollt.
A saját marker nem valódi CVE-/RCE-proof.

Named-actor scanhez az `AuthReplayVault` host-only bindingot ad. Pontos policy/
actor/tenant/sessionrevision/expiry és observed URL/metódus/request-ref kell,
továbbá a rögzített request-evidence identitás- és `sent`-ellenőrzése. A secret
nem része a tartós jobnak, argvnak vagy template-nek. A proxy eltávolítja a kliens
credentialjeit, és csak a kötött GET/HEAD vagy explicit jóváhagyott POST kéréshez injektál. A target által
visszatükrözött ismert secret raw-evidence előtt redaktálódik. Redirect, eltérő
request/actor vagy lejárat nem örököl engedélyt. A scannernek továbbra is a
reviewzott template és az attesztált boundary útján kell futnia.

A privát vault v2 exact JSON/form/multipart POST bodyt és SHA-256-ot köt a
sent/observed capture-höz, legfeljebb 64 KiB-ig. A Nuclei csak publikus sentinelt
lát; a proxy memóriában injektálja az eredeti byte-okat. Az exact POST endpoint
külön policy-allowlist és active/lab profilt igényel. A `rj_request_capture`
fenced reservation atomikusan terheli a request-budgetet és rögzíti a kész
surface-t; restart/concurrency nem ad új mutáló I/O-t. Elveszett kimenetel
uncertain, nem automatikus retry.

A külön `session_refresh` nem idempotens scheduler-job host-only HTTPS providert
használ. `rj_session_state` és `rj_session_refresh` CAS/lease/fencing mellett
forgat header/cookie/CSRF credentialt és numerikus revisiont. A privát vault
0600-as atomikus cseréje és az SQLite commit közti crash uncertain marad.
Régi job/capture nem módosul; az új revisionhöz friss observation szükséges.
A `browser_post_capture` külön privát rule-ok mellett valódi Chromium POST-ot
enged a proxyhoz; a sima browser_discover read-only marad. A teljes
2xx-válasz, fenced capture-CAS és privát vault-CAS együtt ad observed refet és
replay-jóváhagyást. Induláskor a `browser_workflow` a rule-ok start_url/current
contextjeit determinisztikus nem idempotens jobokká egyezteti; régi job nem változik.

Explicit `continuous_replay` konfigurációval a futó schedulerben is folytatódik
a refresh → friss capture → kijelölt Nuclei-template lánc. A `rj_followup_event`
a szülő sikerével atomi outbox-bejegyzést kap; a child-jobok beszúrása és az
esemény nyugtázása szintén atomi. A koordinátor lockja, a teljes batch-limit,
session/evidence/vault ellenőrzés és stabil jobkulcsok minden lépésre érvényesek.
Follow-up hiba nem változtatja retryvá a sikeres, módosító szülőjobot.
Séma és recovery: [continuous workflow](../RedJohn/docs/continuous-refresh-replay.md).

Az opcionális `session_recovery` csak teljes, pontos GET-start/POST-route proxy-401
vagy az adott start bindingjának igazolt lejárata után hoz létre auth-failure
outbox-eseményt. A `session_recovery.py` a privát GET-anchor és identity
ellenőrzését végzi; a store atomi `rj_auth_recovery_budget` és
`rj_auth_recovery_job` táblái adják a revíziókon/újraindításon át megmaradó
limitet és cooldown-t. Kései régi hiba nem frissíti az új sessiont. A hiányos
401 és a más endpoint lejárata nem ad jogosultságot; a régi POST nem retry.
[Séma és határok](../RedJohn/docs/automatic-session-recovery.md).

A `body_tokens` csak deklarált JSONPointer/form/multipart text mezőket cserél az
új header/cookie/response tokenből. Unbound wirebyte és upload változatlan; a
megújult SHA pending-capture státuszt kap. A tényleges friss browser-byte-oknak
egyezniük kell; multipartnál kizárólag a boundary framing térhet el. A pontos
publikus multipart Content-Type/body sentinel stabil template-lockot enged, a
host injektálja a privát boundaryt/bodyt. Provider-refresh-token rotáció és a
teljes login/MFA-workflow nincs. Sémák, limitek és recovery:
[browser/body-token workflow](../RedJohn/docs/browser-post-body-tokens.md).

## Kis API és meglévő agent

`AssessmentControl` caller-bound Python API és a meglévő registryben egyetlen
`assessment_control` SDK tool. Mind a tíz művelet inputvalidált, revisionhöz
kötött, auditált és legfeljebb 64 KiB válaszú; a lapok maximum 100 elemesek.
Engagement ID és evidence ref önmagában nem jogosít hozzáférésre. Nincs új
HTTP/MCP daemon, tetszőleges shell vagy scannerargumentum mező.

A normál TUI/agent CLI továbbra is a korábbi workflow. Az új service objektumot
csak a host illesztheti az agent contextbe. A teljes régi agent/shell útvonal
policy-migrációja és minden providerrel való új E2E ellenőrzése még nyitott.
