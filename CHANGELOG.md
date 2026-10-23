# RedJohn változásnapló

## 2026-10-23 — Remaining audit findings, batch 2

- LLM request logging builds events off the event loop: the full-payload
  `json_size` serialization moved to a worker thread on the LiteLLM and native
  routes (a 200k-token context no longer stalls every agent per call).
- Swarm bus is bounded (500-signal window; read cursors shift with the window;
  monotonic signal ids persist across resume), coordinator snapshots are
  debounced and written off-loop with a synchronous flush at shutdown, and
  `agents_graph` uses new `status_of`/`name_of`/`parent_of_agent` accessors
  instead of reaching into `coordinator._lock`.
- Caido replay bodies are byte-faithful (no `.strip()`; a request without a
  header/body separator has no body), and timed-out replays delete their
  leaked server-side replay session.
- Threat-model target identity is memoized (no git subprocess fan-out per
  call); todo persistence serializes under its lock, a second in-process run
  hydrating todos logs a loud warning, and todo ids are 96-bit with a
  collision retry.
- Viewer: the run listing tolerates runs vanishing mid-enumeration (no more
  HTTP 500 during cleanup) and the traversal-rejection log line is
  ascii-escaped against log forging.
- CVE lookups: a non-JSON 200 body (captive portal / WAF interstitial)
  degrades to "provider unavailable" instead of discarding the sources that
  did answer.
- Unreadable config files log a warning instead of silently reverting the
  model/provider to defaults; `redjohn.log` rotates (50 MiB × 3 backups)
  instead of growing unbounded.
- Audit corrections: the local-backend host-exec opt-in gate was verified
  already present (`REDJOHN_ALLOW_UNCONFINED_LOCAL`, fail-closed on
  non-darwin), and the MCP quarantine "counter race" was re-evaluated as a
  false positive (the mutations run in await-free blocks, atomic under a
  single event loop).

## 2026-10-23 — Full audit remediation (crashes, security, tests/CI, native sampler)

- Fix `import contextlib` NameErrors that crashed every vulnerability report,
  swarm broadcast, and scan finalization; `update_scan_final_fields` now uses
  the real `run_id` and `scan_config` (audit K1, M1).
- Fence recalled OpenViking memory as UNTRUSTED data in the scope prompt
  (fences neutralized, guard line added); the memory skill no longer asks
  agents to store credentials (K3).
- Restore MCP governance for the built-in `openviking` connection (policy
  checks and admission control); remote memory egress now requires
  `REDJOHN_OPENVIKING_ALLOW_REMOTE=1` and an https URL; `ov.conf` is written
  0600 with a generated root API key and empty CORS origins (K4).
- Restrict boundary-less local-backend agent shells to an environment
  allowlist (no ambient provider credentials, proxy credentials stripped) and
  refuse bind mounts of sensitive host paths (K2).
- Stop silently widening operator-narrowed host resource policies (schema 2
  with source markers); derive first-run host limits from actual RAM/CPU;
  partial CLI policies merge onto the current policy with browser clamping
  (M4, M5).
- Track and drain OpenViking background writes at shutdown; bound recall and
  catalog warmup with timeouts; debounce per-LLM-call artifact writes off the
  event loop (M6, M7, M9).
- Add half-open circuit breakers; refuse to mix deterministic fallback
  vectors into API-backed embedding collections; version-guard openviking
  monkey-patches and pin `openviking>=0.5.1.1,<0.6` (M11, M13).
- Fix the toggle inversion and the `clear_vlm_model` TypeError in the
  openviking TUI actions; dead Rust status branches removed; embed labels
  match the real 512d local model (M2, M3).
- Honest version display (real package version instead of a hardcoded
  "Enterprise" label); install.sh download org fixed; THIRD_PARTY_NOTICES.md
  restored with an AGPL-3.0 notice for the OpenViking dependency;
  CHANGELOG.md and .env.example restored (M15-M17).
- Medium/low sweep: caido port liveness, sidecar env scrubbing, lock files
  0600 with O_NOFOLLOW, off-thread model list/login, MCP request logging,
  vectordb backup-on-dimension-change (no silent deletes), health tool
  truthfulness, `suppress(BaseException)` removal, Go/Bubble Tea naming
  cleanup, README truthfulness, runbooks restored for skill contracts.
- Restore the test suite (20 modules from history plus new regression
  coverage: 181 passed / 17 skipped) and a minimal CI pipeline (ruff, strict
  mypy, pytest, cargo fmt/clippy/test on ubuntu + macos). ruff went 110 -> 0
  and mypy 30 -> 0 on the full package.
- New native Rust extension (`redjohn-native`, PyO3 abi3 + sysinfo):
  process-tree memory sampling for the resource governor with the `ps`
  implementation kept as an automatic fallback, wired into the wheel build.

## 2026-10-21 — Source/evidence integrity and assessment hardening

- Restore the canonical `` source tree in Git and require a clean
  worktree before CI source hashing.
- Wire the production policy/governor into `hunt`; quarantine browser capacity
  when Chromium cleanup cannot be proven.
- Make the viewer pagination-aware, require an explicit legacy boundary for
  local targets, install the governed Playwright browser, and validate real
  Chromium health.
- Add per-test real-integration classification, bounded retention, staged
  vault publication, bounded retention, and consistent CLI/TUI version
  and viewer URL handling. The attempted AppArmor narrowing was reverted after
  Linux namespace-attestation incompatibility; it remains an explicit open item. See the
  [commit-bound remediation status](docs/redjohn-remediation-status.md).


## 2026-10-18 — Shared resource admission and Linux containment

- Coordinate active worker/browser/page/context reservations across independent
  campaign databases with a private, bounded SQLite ledger.
- Place explicitly contained Linux CLI controllers in their owned cgroup before
  exec; verify memory/swap/PID limits, group cleanup and kernel-OOM evidence.
- Persist capacity waits only for idempotent work proven not to have admitted a
  request, under the existing retry, attempt and campaign deadline budgets.
- Recover explicitly classified in-process HTTP/refresh/OAST reservations after
  confirmed owner death. Legacy/unknown and process-owning claims retain their
  verified-fence requirement; uncertain network outcomes are never resent.
- Preserve existing tests, engines and private MCP configuration. See
  [actual checks and limitations](docs/redjohn-resource-runtime-verification.md)
  and the [remaining master-prompt scope](docs/redjohn-completion-status.md).

## 2026-10-18 — MIME preservation and restart controls

- Preserve supported UTF-8 MIME parameters and byte-exact authenticated replay;
  unsupported charsets and body operations remain explicit coverage gaps.
- Verify the Chromium–Nuclei restart chain and retain deadline/admission guards
  without duplicate target requests. See the
  [MIME/restart verification](docs/redjohn-mime-restart-verification.md).

## 2026-10-18 — Authenticated schema/OAST selected POSTs

- Add host-private JSON/form/multipart field mutation for TInjA, Schemathesis and OAST.
- Reuse durable same-actor refresh, fresh Chromium capture and selected child jobs.
- Preserve late OAST correlation after target session rotation without redelivery.
- Retain existing active tests and pinned integrations; add separate contract/actual E2Es.
- [Verification and remaining boundaries](docs/redjohn-authenticated-schema-oast-verification.md).

## 2026-10-18 — Selected schema and OAST adapters

Pinned TInjA/Schemathesis jobs on observed GET inputs, a bounded Interactsh
protocol client with persistent late-poll continuations, and finite CLI waiting.
Actual Chromium/CLI/receiver controls, restart/failure tests and source pins are
recorded in `docs/redjohn-schema-oast-verification.md`; unsupported profiles
and unknown network outcomes stay distinct from negative results.

## 2026-10-18 — Selected query specialists

- Optional pinned Arjun 2.2.7, sqlmap 1.10.10 and Dalfox 3.2.4 GET/query
  adapters use RedJohn's existing durable scheduler and enforced egress proxy.
- A durable Dalfox-to-Chromium continuation requires separate nonce/control
  evidence before promoting an existing XSS candidate.
- Named sqlmap credentials stay on the host. Subprocesses, streams, requests,
  file writes and cancellation are bounded; a fresh hint reference alone does
  not authorize a duplicate probe. Explicit retests remain available.
- Three English contracts and configuration readiness are updated. The new
  adapters do not support POST/body mutation or authenticated/stored/DOM-only
  XSS; existing Nuclei replay/session workflows retain their paths.
- Separate contract and real CLI/Chromium/SQLite/HTTPS tests, with
  [verification](docs/redjohn-specialists-verification.md) and
  [runbook](docs/query-specialists.md). Upstream licensing is recorded;
  proprietary sqlmap packaging remains uncleared.

## 2026-10-17 - ffuf, assessment Web View and partial evidence

- Pinned ffuf 2.1.0: approved paths, shared budgets/cooldowns, proxy TLS/input/output limits, Linux namespace and restart/retest/QoS deduplication.
- Cancellation retains owned evidence references and discards finding claims.
- Read-only assessment Web View distinguishes candidates, coverage and capability gaps. Legacy run records remain supported.
- Go TUI skill count comes from the actual registry; branding remains unchanged.
- [Runbook](docs/ffuf-discovery.md), [E2E evidence and images](docs/redjohn-ffuf-verification.md).

## 2026-10-17 — Korlátozott automatikus session-helyreállítás

- Explicit `session_recovery` mellett a teljes proxy-401 és az igazolt privát
  credential-lejárat tartós auth-failure eseményt ad. Hiányzó, hibás vagy
  bizonytalan input nem válik refresh-jogosultsággá.
- Identitás/policy szerint tartós budget és cooldown, revíziónként deduplikált
  refresh indítja a meglévő új capture → kijelölt Nuclei láncot.
- A régi hibás job és bizonyítéka megmarad; sem a régi POST, sem egy elveszett
  refresh nem lesz automatikus retry. Séma és mérési parancs:
  [automatic session recovery](docs/automatic-session-recovery.md).

## 2026-10-17 — Folyamatos refresh → Chromium → Nuclei lánc

- Explicit `continuous_replay` mapping mellett a futó tartós scheduler újraindítás
  nélkül indít friss capture-t és pontos template-ID-val kötött replayt.
- A sikeres szülő és a follow-up esemény, illetve a gyermekjobok és az esemény
  nyugtázása atomi SQLite-tranzakcióban maradnak. A batch limit minden lépésre
  érvényes; queue-hiba nem ismételteti meg a módosító szülőkérést.
- Konfiguráció, indítás, helyreállítás és valódi Linux E2E:
  [folyamatos workflow](docs/continuous-refresh-replay.md).

Az alábbi bejegyzések az akkori működést és méréseket őrzik.

## 2026-10-17 — Valódi Chromium POST-capture és reviewzott body-token frissítés

- Külön `browser_post_capture` capability: a tényleges Chromium/JavaScript/form
  forgalmat a host proxy validálja és tartós capture-reservation után küldi el.
  Csak exact privát automatic-approval rule és teljes 2xx-válasz írhat observed
  body-SHA/refet és privát v2 replay-jóváhagyást; a régi HTTPX SDK külön út marad.
- Induláskor a privát `start_url`/actor/tenant/`current` revision szabályok
  determinisztikus, nem idempotens browser-jobot queue-znak. Frissítés után az új
  koordinátor az új revisionhöz készít friss capture-t; régi job nem íródik át.
- Explicit JSONPointer/form/multipart field-binding frissít header/cookie vagy
  opcionális response `body_tokens` értékből. A többi byte, mezősorrend és upload
  változatlan; új SHA és pending státusz után csak tényleges browser-capture
  oldhatja fel az új body replayjét. Nincs heurisztikus tokenkeresés.
- A pontos publikus multipart Content-Type/body sentinel ugyanazzal a reviewzott
  bundle-lel engedi a friss browser-boundaryt; a host valódi privát headert/bodyt
  injektál. Ismeretlen mutáló kimenetel továbbra sem retry.
- A teljes login/MFA/password-reset, provider-refresh-token rotáció és általános
  cross-origin credential-workflow hiányzó képesség marad. Séma, indítóparancs és
  korlátok: [Chromium/body-token dokumentáció](docs/browser-post-body-tokens.md).

Az alábbi korábbi bejegyzések az akkori snapshotot és korlátokat őrzik.

## 2026-10-17 — Autentikált POST/body replay és explicit session refresh

- A meglévő Nuclei-adapter pontos, legfeljebb 64 KiB-os JSON, URL-encoded form és
  multipart POST replayt kapott. Privát v2 vault, ténylegesen elküldött observed
  capture, body-SHA, named actor és exact endpoint/policy-allowlist szükséges;
  a template csak publikus sentinelt kap, a privát bodyt a host proxy injektálja.
- Tartós, fenced capture-reservation és atomikus request-budget: concurrent vagy
  restart utáni duplikáció nem küld új kérést. Ismeretlen mutáló kimenetelnél
  nincs automatikus retry; az aktív regressziós és E2E-tesztek megmaradtak.
- Külön, nem idempotens `session_refresh` scheduler-job, privát HTTPS provider,
  bounded válasz, SQLite CAS és atomi privát vault-rotáció. Header/cookie/CSRF
  credential és numerikus sessionrevision frissül; a régi job nem íródik át.
  Az új revisionhöz valódi friss POST-capture és privát jóváhagyás kell.
- A bodyba ágyazott token automatikus átírása, a provider saját refresh-tokenjének
  válaszból rotálása és a teljes login/MFA/password-reset workflow továbbra sem
  támogatott. A tesztfajtákat és az aktuális mérési eredményt a
  [POST/session dokumentáció](docs/post-refresh-replay.md) külön kezeli.

Az alábbi bejegyzések az adott korábbi forrássnapshot állapotát őrzik.

## 2026-10-17 — Távoli HTTPS-egress, kötött auth-replay és angol skillek

- Linuxon a browser/scanner worker külön user/network/mount/PID namespace-t
  használ; a controller kerneladatokból attesztálja az izolációt, a loopback-only
  interfészt, a capabilityk hiányát és a `NoNewPrivs` állapotot. Az engedélyezett
  host-proxyhoz privát, peer-ellenőrzött Unix relay vezet. A puszta `enforced`
  konfiguráció nem kerülheti meg az indítási ellenőrzést.
- Pontos HTTPS-origin és IP/CIDR allowlist, DNS-válaszok ellenőrzése és numerikus
  connectpin; szigorú upstream CA/SNI/hostname-validáció. A browser/Nuclei-job a
  meglévő tartós scheduler és request/rate/cooldown/lease szabályaival fut.
- A Nuclei GET/HEAD auth-replay host-only vaultból, pontos observed requesthez,
  actorhoz, tenanthez, session-/policyrevisionhöz és lejárathoz kötött. Credential
  nem kerül scanner-argvba, template-be vagy jobopcióba; nincs anonim fallback,
  általános body-replay vagy automatikus credential-refresh.
- Mind a 47 assessment skill és manifestleírás angol; az eredeti forrás-SHA,
  fordításbemenet-SHA és angol tartalom-SHA elkülönül. Az eredeti 12 angol core
  skill és a külső felhasználói forráscsomag megmaradt.
- Linux memory admission: a process-tree RSS és a saját cgroup
  `memory.current - inactive_file` maximuma a mérvadó. A nyers cgroupértékek
  továbbra is telemetriában maradnak; ez cooperative admission, nem hard RAM-limit.
- Valódi namespace-, authenticated-engine- és távoli HTTPS E2E-tesztek külön a
  mock scanner/download és unit/kontraktustesztektől. A végső mérési jegyzőkönyv
  dönti el a teljes lánc elfogadását; a korábbi loopback-adatok történeti baseline-ok.

A helyes GitHub repository `akosdrx/redjohn`; a hozzá előkészített workflow
futtatása autentikáció hiányában nem igazolt. A Linux VM-mérés külön környezet.
A hiányzó specialist adapterek, általános auth-body replay, OS hard memory-limit,
teljes legacy agentpolicy és eredeti RCE-fixture továbbra is nyitottak.

## 2026-10-17 — Helyi HTTPS és valódi Nuclei a tartós schedulerben

- A meglévő Nuclei-integráció tényleges v3.11.1 motorral fut: hivatalos release,
  rögzített commit, archívum-/checksum-/licenc-SHA256 és helyi provenance receipt.
  Az explicit installer meglévő telepítést nem ír felül; teljes upstream
  templates-készlet nem települ, és nincs automatikus install a schedulerben.
- HTTP(S) browser- és scannerforgalomhoz controller-owned, bounded proxy;
  CONNECT-dekódolás után kérésenkénti scope/read-only/request-budget ellenőrzés,
  szigorú upstream CA/hostname-validáció és teljes válaszframing-ellenőrzés.
  A rendszer truststore-ja nem változik.
- Valódi Chromium → megfigyelt inventory → tartós Nuclei-job → evidence/riport
  lánc, külön CLI-processzek közti folytatással és explicit javított kontrollal.
  A restart nem jogosít ismételt hálózati végrehajtásra.
- Üres scanner-output csak minden elvárt URL teljes 2xx-válaszával lehet
  befejezett negatív check; TLS-/scope-/budget-/truncation-/401/403/429 hiba nem az.
  A scannerhit továbbra is candidate.
- Valódi HTTP(S) engine/Chromium E2E külön a mock scanner-, mock download- és
  subprocess fault-tesztektől. A saját marker nem valós CVE/RCE reprodukció.

Akkori nyitott tételek: production/távoli egress infrastruktúrahatára, további specialist adapterek,
a Kali release/CI-ellenőrzés és az eredeti RCE-fixture továbbra is nyitott.
A RedJohn név, meglévő integrációk és egyéni módosítások megmaradtak.

## 2026-10-17 — Tartós, bounded assessment core

- Új `redjohn assess` / `rj assess` és közvetlen Python-modulindítás;
  meglévő név, csomag, TUI, viewer, provider- és Caido-integráció megőrizve.
- Valódi Playwright/Chromium, izolált actor-context, explicit HTTP-fixture scope,
  bounded proxy/frontier/input/request és ellenőrzött cleanup.
- Tartós SQLite inventory/scheduler/attempt/evidence/finding/audit, fair
  családelosztás, dedup, lease/fencing, cancellation és explicit retest.
- Meglévő Nuclei-hunt megerősítése két külön lockkal, reviewed template subsettel,
  bounded supervisorral, partial/parser/error állapotokkal. Nincs második motor.
- Valós resource governor, byte-LRU/TTL/single-flight cache, recovery/circuit/rate
  limiter, technology/applicability/correlation/performance modulok.
- Felhasználói 35 skillből és 12 új domainfüggő skillből lazy, capability-aware
  RedJohn-kontraktusok. Unsupported adapterhez nincs végrehajtási ígéret.
- Helyi kontrollált reproducer, változatlan eredeti-RCE hiánystátusszal;
  unit/fault/valódi Chromium tesztek és reprodukálható mérések.

Az első core-átadáskor a Nuclei engine és a helyi HTTPS hiányzott; ezeket a fenti
folytatás implementálta. A teljes master prompt továbbra sem kész: production/
távoli egress, több specialist adapter, live cloud/Kubernetes, teljes legacy
agentpolicy és Kali releaseellenőrzés külön nyitott tétel.
