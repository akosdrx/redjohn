---
name: api_graphql_websockets
description: Use when the attack surface is an API beyond generic web - GraphQL introspection
  and field-level authorization, query depth and batching abuse, undocumented REST
  endpoints and versions, and WebSocket origin checks or message-level authorization
  gaps.
---

# API, GraphQL and WebSockets (P6)

API-shaped surfaces at their own granularity. The new granularities are
field-level (GraphQL), message-level (WebSockets) and version-skew (REST)
— don't re-test what `30`/`40`/`50` covered unless the framing changes
the check.

## The way

- Introspection off is not access control: field suggestions and
  JS-mined query documents rebuild the schema anyway. Treat a disabled
  introspection endpoint as a slower schema, not a closed one.
- Abusive queries are drafted offline and scored before anything is
  sent; one bounded probe per limit class, record the server's answer,
  stop. Never walk depth upward.
- Batching/aliasing = N operations per request: that's the rate-limit
  bypass shape and the brute-force amplifier. Bounded examples only.
- Field-level authz is `30`'s matrix at field granularity: same object
  id, same query, different roles, diff the returned fields.
- WebSockets repeat the matrix per *message type*, not per connection.
  Upgrade-Origin acceptance decides whether any web page can open the
  socket in a victim browser.
- GraphQL evidence is byte-exact: the full query document verbatim — a
  paraphrased query is not reproducible.

## Handoffs

Authz gaps -> `30` as new matrix rows; batching/mass-assignment ->
`58`; CSRF angles (persisted GET queries, cross-WS forgery) -> `55`;
framework versions -> `70`.

## Tools

`graphql_dump.py` (guarded), `graphql_depth_check.py` (offline),
agent_browser's WS console. Query templates and checklists in
`references/`.

---

## Reference Module: `graphql-attack-surface`

# GraphQL attack surface: queries verbatim, probes and templates

All queries are sent as POST with `Content-Type: application/json` and body
`{"query": "<document>"}` unless noted. Substitute the engagement endpoint.
Every probe is scope-guarded and produces an evidence pair.

## 1. Introspection

### 1.1 Minimal probe (existence + open state)

```json
{"query":"query IntrospectionProbe { __schema { queryType { name } } }"}
```

- 200 + `data.__schema` -> introspection open.
- Error naming "introspection"/"disabled"/"not allowed" -> endpoint exists,
  introspection blocked; continue with field suggestions (1.3).
- 404/HTML -> wrong path; try `/api/graphql`, `/v1/graphql`, `/graphql/v1`,
  `/graphiql`, `/playground` (from `10`'s probe list).

### 1.2 Full standard IntrospectionQuery (what graphql_dump.py sends)

```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { ...FullType }
    directives {
      name
      description
      locations
      args { ...InputValue }
    }
  }
}

fragment TypeRef on __Type {
  kind
  name
  ofType {
    kind
    name
    ofType {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType { kind name }
            }
          }
        }
      }
    }
  }
}

fragment InputValue on __InputValue {
  name
  description
  type { ...TypeRef }
  defaultValue
}

fragment FullType on __Type {
  kind
  name
  description
  fields(includeDeprecated: true) {
    name
    description
    args { ...InputValue }
    type { ...TypeRef }
    isDeprecated
    deprecationReason
  }
  inputFields { ...InputValue }
  interfaces { ...TypeRef }
  enumValues(includeDeprecated: true) {
    name
    description
    isDeprecated
    deprecationReason
  }
  possibleTypes { ...TypeRef }
}
```

Run via `scripts/graphql_dump.py` (saves the response, prints type/field
counts). Note `subscriptionType` — if present, the WS surface in the
websocket checklist applies to the subscription transport too.

## 2. Depth and complexity test documents

Score OFFLINE with `scripts/graphql_depth_check.py --query-file` first; the
RoE (master section 0) allows one bounded probe per limit class, never an
upward sweep.

### 2.1 Bounded nested depth (depth 5, complexity 5)

```graphql
query DepthProbe {
  viewer {
    friends(first: 1) {
      edges { node {
        friends(first: 1) {
          edges { node {
            friends(first: 1) {
              edges { node { id name }
            }
          }
        }
      }
    }
  }
} }
```

(Adjust field names to the dumped schema; keep `first: 1` on every
connection — bounds the result set, isolating the depth question from data
volume.)

### 2.2 Fragment-cycle amplification (the classic unbounded shape)

```graphql
query FragCycle {
  ...a
}
fragment a on Query {
  ...b
  __typename
}
fragment b on Query {
  ...a
  __typename
}
```

`graphql_depth_check.py` flags fragment cycles and reports the depth the
cycle would produce. A server without a depth limiter typically 500s/times
out on the expanded form — do NOT expand it by hand; one bounded expansion
(depth-limited rewrite, e.g. 10 levels) is the maximum probe.

### 2.3 What to record per probe

| Server answer | Meaning | Finding |
|---|---|---|
| 400 with `depth`/`complexity` error | limiter present | negative result, keep |
| 200 with partial data | no limiter, resolver bail-out | D1 depth finding |
| Timeout / 5xx | no limiter, cost paid server-side | D1 finding + RoE note, stop immediately |

## 3. Aliasing and batching patterns (bounded)

### 3.1 Aliased duplicates in one document (5 copies — the bound)

```graphql
query AliasProbe {
  a1: node(id: "4") { id secretField }
  a2: node(id: "4") { id secretField }
  a3: node(id: "4") { id secretField }
  a4: node(id: "4") { id secretField }
  a5: node(id: "4") { id secretField }
}
```

Use `node(id: "4")` per role token. If the rate limiter counts requests and
the server executed 5 operations, that is one request -> N operations —
record the limiter's visible counter before/after if the API exposes one.

### 3.2 Array batching (Apollo-style)

```json
[
  {"query":"query A { viewer { id } }"},
  {"query":"query B { viewer { email } }"}
]
```

Many gateways disable this; a 400 "batching not allowed" is a keepable
negative result.

### 3.3 Prohibition reminder

Aliasing/batching used for credential stuffing, token enumeration or any
high-volume guessing is resource-exhaustion-adjacent and requires written
authorization; the default engagement bound is the 5-alias single-shot demo
above. Anything beyond hands off to `58` with the authorization question.

## 4. Field-suggestion probing (introspection disabled)

GraphQL servers (GraphQL.js-style error suggestions, graphiql-backed
gateways) echo `Did you mean 'email'?` for near-miss names. Probe one
near-miss per field guess, serially:

```graphql
query Suggest { user(id: "4") { emaill } }
query Suggest2 { user(id: "4") { userEmaill } }
query Suggest3 { user(id: "4") { mailAddress } }
```

Each distinct "Did you mean X" adds field X to the reconstructed schema;
record every request/response pair. This proves "introspection disabled" is
not access control — pair it with a successful cross-role fetch of the
suggested field for a real finding.

## 5. Field-level authorization templates

### 5.1 Per-role identical document (token swap from `30`)

Send the SAME document under each role's token and diff responses:

```graphql
query AuthZField {
  user(id: "1042") {
    id
    email
    role
    internalNotes
    apiToken
    invoices(first: 5) { edges { node { id totalCents } } }
  }
}
```

Findings matrix: field x role -> visible/hidden/error/null-masked. A field
that returns data under a lower-privilege token than the UI ever shows that
role is the finding; null-masking vs error distinguishes design vs bug.

### 5.2 Mutation audit template

```graphql
mutation M1 { updateProfile(input: { id: "1042", role: "ADMIN" }) { ok } }
mutation M2 { changePassword(userId: "1042", newPassword: "...") { ok } }
mutation M3 { addMember(accountId: "7", userId: "1042", role: "OWNER") { ok } }
```

Check per mutation: missing validation (role accepts arbitrary strings),
id-based object references (operates on ANY id, not just the caller's),
cross-role writes. Mutations run against operator-created synthetic records
only; cleanup per master section 0.

## 6. Persisted queries / GET form (CSRF angle handoff)

```
GET /graphql?query={user(id:"1042"){email}} HTTP/1.1
```

or the APQ form:

```
GET /graphql?extensions={"persistedQuery":{"version":1,
  "sha256Hash":"<hash-of-registered-query>"}}&variables={"id":"1042"}
```

If a GET with a simple query string returns data without a custom header,
the response is readable cross-origin from any web page — capture the exact
GET form (request+response) and hand to `55-client-side-attacks` for the
browser-side proof; do not build the PoC page here.


---

## Reference Module: `rest-gap-checklist`

# REST gap checklist: methods, versions, errors, idempotency

Consumes the P1 surface inventory (schema rows from openapi discovery and
JS extraction). All requests serial, scope-guarded, evidence pairs per
probe. Substitute `https://target.example.com`.

## 1. Method acceptance map

For each resource endpoint, one request per verb, same auth context, empty
or minimal body; record the full matrix:

| Path | GET | POST | PUT | PATCH | DELETE | OPTIONS | HEAD |
|---|---|---|---|---|---|---|---|
| `/api/v1/orders` | 200 list | 201 | 405 | 405 | 405 | allow list | 200 |
| `/api/v1/orders/{id}` | 200 | 405 | 200 | 405 | 204 | - | - |

Interpretation rules:

- 405 vs 404: 405 proves the path exists under another verb; 404 can hide a
  verb-routed controller — retest discovered paths with all verbs once.
- "Silent" acceptance: 200 on a verb the documentation/schema does not list
  is an undocumented method finding — capture the body diff vs documented
  behavior.
- OPTIONS: read `Allow:`; compare against the observed map — server-claimed
  but never-tested verbs get one probe each.
- Method override: on a POST-only endpoint, send POST with
  `X-HTTP-Method-Override: DELETE`, `X-Method-Override: DELETE`, and body
  `_method=delete` (urlencoded). Any state change = bypass of the verb
  policy.
- TRACE: send once; a reflected body is a classic observation (usually
  proxied frameworks disable it — 405 is the normal keepable negative).

## 2. Version skew checks

For each resource present in more than one version prefix:

1. Same object id, same role token, both `/v1/` and `/v2/` (also `/api/v1`,
   `/api/v2`, unversioned `/api`): diff status, shape, field set — old
   versions leaking fields the new one filters is a common authz regression
   (pair with the field-diff from `30`'s matrix).
2. Validation strictness: send the SAME invalid payload (extra field, wrong
   type, negative amount) to both versions; a 400 in v2 and silent 200 in v1
  means the old surface never received the new validation.
3. Deprecated surfaces: look for `Deprecation`/`Sunset` headers; absence of
   deprecation markers on an older version is an observation, not a finding.
4. Undocumented intermediate versions: probe `/v0/`, `/v3/`, `/internal/`,
   `/private/`, `/mobile/`, `/legacy/` prefixes on 5-10 known resource
   paths — bounded, serial.
5. Changelog/JS diff: older client bundles (web archives, mobile captures
  if provided) referencing `/v1/` endpoints that the current schema dropped
  = shadow endpoints to retest.

## 3. Error verbosity triggers

One request each, capture the pair, classify:

| Trigger | Example | Leak class |
|---|---|---|
| Type error | `?id=abc` where `?id=1` works | stack trace, ORM error |
| Validation | negative quantity, overlong string | field list, framework signature |
| Duplicate | replay a unique-value create | SQL fragment (CWE-209) |
| Unknown field | extra JSON property on write | validation policy map |
| Malformed JSON | `{` | parser fingerprint (FastAPI/Express/Django shapes) |

Any stack trace -> `50-config-baseline` observation; framework signature ->
`70-exploit-intel` fingerprint row with version confidence.

## 4. Idempotency checks

Operator-created synthetic data only; never real user records.

1. POST create replay: send the identical POST twice (same token); second
   response 201 again (duplicate created) vs 409 (enforced) vs same id
   (idempotent).
2. Idempotency keys: if the API documents `Idempotency-Key`, replay the key
   with a DIFFERENT body — some implementations return the cached first
   response without checking body match (a cache-confusion finding).
3. PUT/PATCH replay: same PATCH twice; state must land on the same value —
   non-idempotent PATCH semantics produce drift (record the exact two
   states).
4. DELETE replay: first 204, second 204 vs 404; 404-after-204 is normal.
5. Concurrency depth (two parallel requests racing) belongs to
   `58-logic-concurrency`; capture the pair here and hand off.

## 5. Registration

Append rows to the surface inventory for every accepted-but-undocumented
method/version found:

```text
surface | method=PATCH | path=/api/v1/orders/{id} | source=method-map
  | auth=role:user-a | evidence=evidence/p6-api-rest-003.{req,resp}.txt
```

Then loop-back: new path -> `30` matrix row per role; new parameter ->
`40` input-surface row; error leak -> `50`; fingerprint -> `70`.


---

## Reference Module: `websocket-checklist`

# WebSocket checklist: upgrade validation, message authz, safe fuzzing

For every WS endpoint found in JS (`new WebSocket("wss://...")`), run the
three stages in order. Save the handshake pair and one transcript file per
connection (`C>` / `S>` direction markers, timestamps, auth-context label).

## 1. Upgrade validation checklist

Send the same upgrade request with varied Origin values and record 101 vs
403/400 per row:

| Variant | Request change | Expected (secure) | Insecure signal |
|---|---|---|---|
| Legit origin | `Origin: https://target.example.com` | 101 | 403 everywhere = misconfig note |
| Foreign origin | `Origin: https://attacker.example` | 403 | 101 = cross-site WS hijack possible |
| No Origin | omit the header | 403 (or 101 + no cookie auth) | 101 with cookie auth |
| Subdomain | `Origin: https://evilexample.target.example.com` if wildcard | 403 | 101 |
| Cross-scheme | `Origin: http://target.example.com` | 403 | 101 |

Also verify: `Sec-WebSocket-Version` handling (bogus version -> 400 with the
supported version echoed is normal), authentication BEFORE upgrade (401 on
upgrade) vs first-message auth, and whether cookies are even required.

Raw probe skeleton (curl, ws/wss upgrade handshake only — curl cannot speak
frames; use it for the handshake, use agent_browser WS console for frames):

```
curl -i -N --http1.1 \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: https://attacker.example" \
  https://target.example.com/ws
```

## 2. Auth token placement

- Token in query string: `wss://target.example.com/ws?token=...` — flag as
  logging/proxy-leak observation for `85`; test whether the token is
  validated at upgrade or lazily per message (send one message with a stale
  token after 101).
- Token in first message: confirm the server rejects data messages before
  the auth message (send `join` before `auth`).
- No token anywhere: check whether messages that mutate state work fully
  anonymously; that is the finding, not a chain.

## 3. Message-level authorization matrix

Template — one row per message type, filled per role:

| Message type | Role A (own id) | Role A (other id) | Anonymous | Note |
|---|---|---|---|---|
| `join {room}` | 200 ok | ? | ? | other id from role B's transcript |
| `subscribe {channel}` | events flow | ? | ? | |
| `send {room, text}` | delivered | ? | ? | |
| `history {room, limit}` | data | ? | ? | |
| `leave {room}` | ok | ? | ? | |

Procedure:

1. Capture both roles' legitimate transcripts first (operator-provided test
   accounts user-a@example.com / user-b@example.com).
2. Connected as role A, replay role B's room/channel ids verbatim — one
   message per id, serial (master pacing).
3. Sequential-id rooms: bounded enumeration only (a handful of adjacent ids
   around the operator-created room); never a sweep.
4. Subscription authz: subscribe to `user-updates:<id>` for the other role's
   user id; record whether events for that id arrive.
5. Record per cell: echoed ok / error text / silence + whether events
   actually flow (silence after ok is a gap of its own).

## 4. Cross-WebSocket-request forgery (concept)

If the upgrade answers a foreign Origin with 101 AND the socket authenticates
by cookies, a page at `https://attacker.example` can open the socket in the
victim's browser and issue state-changing messages with the victim's
identity. This skill captures the handshake evidence (section 1) plus one
message-level mutation transcript; the browser PoC page belongs to
`55-client-side-attacks`.

## 5. Safe JSON message fuzzing rules

- One mutation per message; keep every other field at its captured value.
- Mutation classes, in order: type confusion (`"limit": "5"` as string
  where number expected), missing required field (delete one), extra unknown
  field (acceptance = `58` mass-assignment lead), duplicate JSON key
  (`{"room":"a","room":"b"}` — parser-dependent), null vs empty string,
  deep nesting inside a JSON field (depth 3-5, not more).
- Rate: serial, with a pause between sends; never flood a shared channel.
- If the app has binary subprotocols (protobuf, msgpack), STOP — record the
  observation and note the protocol; binary fuzzing is out of RoE.
- Stop conditions (master section 6): three generations without a behavior
  difference -> log the negative result and move on; server error/5xx on a
  fuzzed message -> capture the pair, single replay for D2, stop that class.

## 6. Evidence expectations

- Handshake request + response verbatim (headers incl. `Sec-WebSocket-*`).
- Transcript per connection: `HH:MM:SS.mmm C> {"..."}` lines; label which
  auth context produced the connection.
- For authz findings: the same message shown under both roles' connections
  with the differing server answers.
- Negative results: foreign Origin refused; pre-auth messages rejected —
  these support the coverage statement in `90`.

