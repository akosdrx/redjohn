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
