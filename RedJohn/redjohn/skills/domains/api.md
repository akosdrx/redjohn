---
name: api
description: REST, GraphQL, and WebSocket traps that generic web testing misses. Introspection and an extra HTTP method are leads, not findings.
---

# API

Treat the schema as the map and the authorization check as the thing under test. A documented endpoint you never called is an untested surface, not a vulnerability.

## REST

Methods the UI hides still exist: `PUT`, `PATCH`, `DELETE`, and method override via header or `_method`. Version prefixes (`/v1` vs `/v2`) often disagree about auth. Idempotency keys and replay of a signed request matter when repeating one request repeats a payment or an invite. Mass assignment lives here too when the body is JSON; that proof bar is in `logic`.

A 401 and a 404 for the same id, depending on whether the object exists, leaks the id. It is low unless those ids are the key to a further action you then perform.

## GraphQL

Introspection is a map. It is not a finding. The finding is a field or a mutation that returns or changes another user's data, a query whose cost you can show is unbounded, or batching/aliasing that runs an expensive resolver once per alias and walks past a rate limit.

Authorization is per field, not per endpoint. A query that fails at the top and a sibling field on the same type that succeeds is the test. Suggestions in an error (`Did you mean`) are a lead toward a field the schema hid.

## WebSocket

The upgrade can be authenticated and the messages not, or the reverse. Send the sensitive message with a second principal's id and with no cookie. Cross-site upgrade (a browser page opening the socket with ambient cookies) is CSRF-shaped: show the message the page was able to send.

## What to ignore

A missing `Content-Security-Policy` on a JSON API, verbose framework errors with no secret in them, and GraphQL introspection on an API that is already public documentation. Record them only when they hand you a secret or a bypass you then use.
