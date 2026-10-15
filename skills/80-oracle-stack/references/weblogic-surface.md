# WebLogic surface

Console and T3/IIOP procedure, version-disclosure path list, the
deserialization attack-class summary with the real well-known CVE names, and
the operator-gated WAR deployment path.

## 1. Port and protocol map

| Port | Protocol | Meaning |
|---|---|---|
| 7001 | HTTP + T3 (multiplexed by content) | default admin+app listener |
| 7002 | HTTPS + T3S | default SSL listener |
| same listener | IIOP (CORBA) | `weblogic.iiop` runtime; part of the deserialization surface |

T3 detection: a client handshake string (`t3 <version>`) to 7001 gets a
protocol response naming the server version (historically `HELO:12.x.x`
style). Reading the response is observation; sending serialized objects is
`45` territory.

## 2. Version-disclosure path list (GET only)

| Path | What it historically leaks |
|---|---|
| `/console` | redirect chain to the login form; redirect target itself is a finding |
| `/console/login/LoginForm.jsp` | login page; older releases print "WebLogic Server Version: x.y.z.w" in page footer or title |
| `/console/login/LoginForm.jsp` error states | error pages with version/build strings |
| arbitrary 404 | older releases return an error page naming "WebLogic Server" + version |
| `/wls-wsat/CoordinatorPortType` | WS-AT endpoint; GET may answer SOAP/HTTP method error revealing the module exists |
| `/_async/AsyncResponseService` | AsyncResponseService endpoint; confirms async web services subsystem reachability |
| `/management/tenant-monitoring/servers` | WebLogic REST Management API; unauthenticated access leaks domain/server topology |
| `/uddiexplorer/` , `/uddiexplorer/SearchUDI.jsp` | UDDI explorer (SSRF class history) |
| `/bea_wls_internal/` | internal apps family on older releases |

Every response goes to the evidence pair regardless of status: 404-with-version
is a disclosure, 403 marks a protected-but-present endpoint (P5 verb/encoding
candidate), 200 with login form is the console surface row.

## 3. Deserialization attack-class summary

The class: WebLogic's T3/IIOP protocol handlers and several HTTP decoders have
repeatedly accepted Java-serialized (or otherwise attacker-shaped) objects and
routed them into gadget chains -> RCE; separately, JNDI-lookup injection
classes let a crafted request make the server resolve an attacker-influenced
name. Well-known real advisories per family (each: verify against NVD/vendor
advisory at authoring time; applicability is only ever decided by `70` with
version proof):

T3/IIOP Java serialization family:

- CVE-2015-4852 — the classic T3 deserialization advisory.
- CVE-2017-3248 — T3 serialization gadget chain (January 2017 CPU).
- CVE-2018-2628 — T3 deserialization RCE (April 2018 CPU).
- CVE-2020-2883 — T3/IIOP, Coherence gadget chains (April 2020 CPU).

HTTP decoder family:

- CVE-2017-10271 — WLS WSAT component (`/wls-wsat`) deserialization.
- CVE-2019-2725 — `wls9_async`/async-response deserialization RCE; widely
  exploited in the wild at the time.
- CVE-2019-2729 — follow-up in the same async family.

Console path family:

- CVE-2020-14882 + CVE-2020-14883 — unauthenticated console path-traversal ->
  privileged console -> execution; chained, heavily exploited.

JNDI lookup family:

- CVE-2023-21839 — T3/IIOP JNDI injection (January 2023 CPU era; verify
  exact CPU month at authoring time).

SSRF class:

- CVE-2014-4210 — UDDI explorer (`/uddiexplorer`) server-side request
  forgery.

Usage rules:

1. This list names CLASSES for surface prioritization. It is never evidence of
   vulnerability — version proof -> `70` -> claim ladder.
2. PoC execution goes through `45` with RoE: documented PoC, disposable
   container, benign proof (canary echo / `id`), cleanup.
3. OOB callbacks (JNDI-class PoCs) pair with the `20` listener; `nuclei -ni`
   keeps its own Interactsh off.

## 4. Procedure (binding order)

1. Fingerprint: run the path list above + T3 banner read; capture pairs.
2. Version -> `70-exploit-intel` for CPU correlation (tier rules apply; bare
   console version without patch-level info caps at "version in range, impact
   unverified").
3. Only after `70` returns a correlated advisory: attempt the documented PoC
   via `45` within RoE.

## 5. Admin console access path — WAR deployment (operator-gated)

IF (and only if) operator-supplied credentials authenticate to `/console`:

1. Written operator approval on file for a deployment action; confirm the
   target is a non-production node or the engagement explicitly accepts it.
2. Build a minimal WAR whose only behavior is echoing the engagement canary
   (`rj-pt-<engagement>-<nonce>` marker string) — nothing else.
3. Console path: Deployments -> Install -> upload WAR -> target the admin
   server (or a dedicated managed server) -> Finish.
4. Verify by requesting the servlet URL; capture request+response as the RCE
   proof pair.
5. Cleanup: undeploy, re-list deployments to show removal, keep both evidence
   pairs.
6. Any further use of console access (datasource inspection, credential
   extraction from JDBC configs) is read-only, evidence-captured, and stays in
   the engagement namespace.

Without credentials: report the console as exposed attack surface with the
version disclosure and lockout policy observations (bounded attempts per `30`)
— no brute force from this skill.
