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
