---
name: 60-api-graphql-websockets
description: Use when the attack surface is an API beyond generic web - GraphQL introspection and field-level authorization, query depth and batching abuse, undocumented REST endpoints and versions, and WebSocket origin checks or message-level authorization gaps.
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
