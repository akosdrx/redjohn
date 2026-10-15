---
name: waf_edge_posture
description: Use when assessing WAF, CDN and reverse proxy edge posture - discovering
  direct-to-origin exposure, testing edge-vs-origin path normalization discrepancies,
  auditing X-Forwarded-* header trust, or diffing pre/post-test response baselines
  to detect mid-engagement SOC virtual patching.
---

# WAF, CDN & edge posture auditing (P2/P3)

Non-destructive assessment of reverse proxy, CDN, and WAF edge layers.
Exposes direct origin exposure, normalization parsing gaps, header trust
flaws, and detects live SOC virtual patching.

## The way

- Audit configuration, never attack third-party anti-bot infrastructure:
  focus on server-side architecture, origin exposure, and proxy header trust.
- Direct-to-origin verification: confirm candidate origin IPs via TLS cert
  Subject Alternative Name (SAN) matching, body SHA256 match, and origin
  response headers before asserting an edge bypass.
- Benign path normalization matrices: probe harmless, read-only variant
  paths (semicolons, URL encoding, dot-segments: `/public;x=1`, `/%2e/public`)
  on existing public routes to find proxy vs backend parsing discrepancies.
- Header trust auditing: verify whether client-supplied `X-Forwarded-For`,
  `X-Real-IP`, or `X-Forwarded-Host` are stripped by the edge or blindly
  trusted upstream for IP allowlists and rate-limiting.
- Pre/post-test baseline delta discipline: capture pre-test fingerprint
  `(status, size, time, headers, waf_cookies)`. On lost reproduction of a
  finding, diff post-test fingerprint to distinguish SOC virtual patches
  from durable code fixes.
- Classify edge blocks as edge behavior: CDN 403/405/429 block pages with
  CDN branding indicate the request never reached origin; log as edge
  posture, not application findings.

## Handoffs

Recon inventory and origin leads from `10`/`05` -> `25`; direct origin and
normalization findings -> `20` (traffic manipulation), `30` (auth bypass),
`40` (injection), and `95` (finding verifier).

## Tools

`waf_edge_probe.py` (guarded prober, origin diff, normalization probe,
baseline diffing, and offline `--self-test`). Normalization matrices,
origin discovery vectors, and SOC IR posture in `references/`.

---

## Reference Module: `edge-normalization`

# Edge-vs-Origin Path Normalization & Delimiter Matrix

## 1. Architectural Discrepancy Overview

Reverse proxies, CDNs, and Web Application Firewalls (WAFs) parse incoming URI paths to apply cache rules, access restrictions, and security inspection policies. When the edge proxy normalizes or tokenizes a URI differently than the upstream application framework, security controls can be desynchronized:
- The edge considers the path non-sensitive or cached and skips inspection.
- The backend normalizes the path to an internal handler, bypassing access barriers.

---

## 2. Proxy vs Backend Parsing Discrepancy Matrix

| Probe Pattern | Edge Behavior (Cloudflare, CloudFront, Nginx, Envoy) | Backend Framework | Backend Interpretation | Security Impact |
|---|---|---|---|---|
| `/path;param=1` | Path treated as distinct resource or stripped of matrix params depending on proxy config. | **Apache Tomcat / Spring Boot** | Strips `;param=1` and routes to `/path`. | WAF rule targeting `/path` may fail to match if keyed on strict regex; cache poisoning if edge caches response. |
| `/path/..;/resource` | Semicolon prevents edge from resolving directory traversal (`..;` is not `..`). | **Tomcat / Spring MVC** | Strips `;` during URL normalization, resolving traversal to `/resource`. | Path traversal bypass around edge access rules. |
| `/%2e/path` or `/%2e%2e/path` | Edge does not decode dot-segments or treats them literally. | **Express / Nginx Upstream / Rails** | Decodes `%2e` to `.` and normalizes path. | Bypasses prefix-based proxy blocking rules (e.g. `/admin`). |
| `/path%2fsub` vs `/path/sub` | Edge does not decode `%2f` (forward slash); applies rules for a single path segment. | **Flask / Werkzeug / PHP** | Decodes `%2f` into a directory separator or passes raw to router. | Route mapping mismatch; WAF rule bypass. |
| `/path.` or `/path%20` | Edge treats as distinct path; does not match `/path` block rule. | **Microsoft IIS** | Strips trailing periods and spaces before mapping to handler. | Static file leak or authentication bypass on IIS. |
| `/PATH` vs `/path` | Case-sensitive proxy treats as distinct URI. | **IIS / Windows ASP.NET** | Case-insensitive file system matches same resource. | Bypasses case-sensitive proxy ACLs. |
| `/path%00` | Edge forwards query or rejects with 400. | **Legacy PHP / C CGI** | Null byte truncates string in native file operations. | Null-byte file extension bypass. |

---

## 3. Non-Destructive Verification Workflow

To verify normalization discrepancies safely without attacking or mutating backend state:

1. **Select a Known Public Endpoint**: Identify an existing public, read-only endpoint (e.g. `/api/v1/health`, `/about`, `/robots.txt`, `/static/style.css`).
2. **Execute Baseline Query**: Send benign GET request and record:
   - HTTP status code (e.g., `200 OK`).
   - Response Content-Length and body SHA256.
   - Cache headers: `CF-Cache-Status`, `X-Cache`, `Age`, `ETag`.
3. **Execute Benign Variant Queries**:
   - Semicolon matrix: `/robots.txt;param=test`
   - Encoded dot: `/%2e/robots.txt`
   - Encoded slash traversal: `/api%2fv1/health`
   - Trailing period: `/robots.txt.`
4. **Compare Differential Signatures**:
   - If the variant returns the identical body SHA256 and status 200 as the baseline, the backend resolved the route.
   - If the edge cache status switches from `HIT` to `MISS` or WAF inspection is bypassed, record an **Edge-Origin Parsing Discrepancy**.


---

## Reference Module: `origin-discovery`

# Direct-to-Origin Exposure & Verification Protocol

## 1. Threat Model: Bypassing the Edge

Web Application Firewalls (WAFs), DDoS mitigation, and edge rate-limiting are only effective if **all** incoming traffic is forced through the edge provider. If the origin server or load balancer is directly reachable over the public internet on ports 80/443 without firewall restrictions or **Authenticated Origin Pulls (mTLS)**, an attacker can bypass all edge defenses by sending requests directly to the origin IP with the target `Host:` header.

---

## 2. Origin Discovery Vectors

Candidate origin IP addresses are discovered passively through authorized reconnaissance:

| Discovery Vector | Description & Methodology |
|---|---|
| **Historical DNS Records** | Pre-CDN `A` and `AAAA` records preserved in passive DNS databases (e.g. SecurityTrails, DNSDB) before migration to Cloudflare/CloudFront. |
| **SSL/TLS SAN Matching** | Scanning authorized cloud IP ranges (AWS, GCP, Azure, Hetzner, DigitalOcean) for TLS certificates matching the target domain's Subject Alternative Names (SANs). |
| **Outbound Connection Callbacks** | Inspecting client-triggered callbacks (SSRF canaries, webhook pings, password reset email headers, favicon requests) where the server communicates directly with external listeners without proxying egress. |
| **Subdomain IP Clustering** | Identifying related non-CDN subdomains (e.g. `mail.example.com`, `direct.example.com`, `vpn.example.com`, `origin.example.com`) sharing the same Autonomous System (AS) or IP block. |

---

## 3. Four-Step Origin Validation Protocol

When a candidate origin IP is identified, execute the following protocol to confirm exposure:

### Step 1: Direct TLS Handshake & Certificate Verification
Connect directly to `https://<candidate-ip>/` specifying `Server Name Indication (SNI)` matching the target domain:
- **Pass**: The server presents a valid TLS certificate issued to the target domain or wildcard.
- **Fail**: The server presents an unrelated default certificate (e.g. `TRAEFIK DEFAULT CERT`, self-signed, or cloud provider hostname) without matching SANs.

### Step 2: Virtual Host Replay (`Host:` Header Injection)
Send an HTTP GET request to `https://<candidate-ip>/` with the header `Host: target.example.com`.
- Verify whether the web server returns the application rather than a default "404 Virtual Host Not Found" page.

### Step 3: Edge vs Origin Header Comparison
Compare response headers between the public CDN URL and the direct origin IP:
- **Origin Indicators**: Presence of direct server headers (`Server: Apache/2.4`, `X-Powered-By: PHP/8.2`, `Set-Cookie` with application session).
- **Missing Edge Headers**: Absence of edge tracing headers (`CF-RAY`, `cf-cache-status`, `x-amz-cf-id`, `x-akamai-transformed`, `x-cdn`).

### Step 4: Body Fingerprint Alignment
Compute SHA256 of the response body from the candidate IP and compare against the public CDN response:
- If the body hashes or DOM structures match ($\ge 90\%$ similarity excluding volatile timestamps/nonces), direct origin exposure is **confirmed**.

---

## 4. Authenticated Origin Pulls (mTLS) & Firewall Posture

A properly secured origin implementation must enforce either:
1. **Network-Layer Ingress Filtering**: Origin firewall/security group permits TCP 80/443 traffic **strictly** from the CDN provider's published IP ranges. Direct connection attempts from other IPs must time out or be dropped (`TCP RST` / connection refused).
2. **Authenticated Origin Pulls (mTLS)**: Origin server requires a valid client TLS certificate signed by the CDN's private CA during the TLS handshake. Direct connections without the CDN client certificate fail at TLS handshake with `SSL_ERROR_HANDSHAKE_FAILURE_NO_CLIENT_CERT` (HTTP 495/496).


---

## Reference Module: `waf-ir-posture`

# WAF Posture & Incident Response (IR) Baseline Delta Tracking

## 1. The Mid-Engagement IR Phenomenon

During active security testing, an organization's Security Operations Center (SOC) or managed detection provider may detect testing traffic and deploy **emergency edge mitigations** (WAF rules, virtual patches, IP blocks) while testing is ongoing.

When a previously verified finding suddenly stops reproducing:
- **Did the engineering team ship a durable source-code patch?**
- **Or did the SOC deploy a brittle WAF regex rule that only blocks the specific payload string?**

Distinguishing between these two states is critical for accurate reporting and risk evaluation.

---

## 2. Pre-Test vs Post-Test Baseline Fingerprinting

Before testing high-impact vulnerability classes, capture a baseline signature of the target:

### Pre-Test Baseline Tuple: `fingerprint_pre.json`
- `timestamp`: UTC timestamp of baseline capture.
- `latency_ms`: Median round-trip time over $N=5$ requests.
- `status_code`: Normal response status (e.g. `200 OK`).
- `content_length`: Body byte length.
- `body_sha256`: Hash of sanitized response body.
- `headers`: Map of normalized response headers.
- `waf_cookies`: Set of detected security/bot cookies (`__cf_bm`, `awselb`, `reese84`, `incap_ses`, `datadome`).

### Post-Test Differential Signals
When a reproduction fails, immediately capture `fingerprint_post.json` and compare:

| Observed Delta | Interpretation | Evidence Indicator |
|---|---|---|
| **Sub-Millisecond Rejection** ($< 20\text{ ms}$ vs normal $150\text{ ms}$) | **Edge WAF Block**. Request was dropped or rejected at the edge without reaching the backend. | Status 403, zero backend processing time. |
| **New Edge Headers** | **WAF Rule Triggered**. Edge provider injected block metadata headers. | `CF-Mitigated: challenge`, `X-WAF-Block: true`, `X-Deny-Reason`, `X-Ibm-Waf-Action`. |
| **New Bot / Session Cookies** | **Elevated Threat Tier**. Target edge elevated the testing IP into an anti-bot challenge tier. | Presence of `__cf_bm`, `cf_clearance`, `datadome`, or `reese84`. |
| **Normal Latency + Sanitized Response** ($\approx 150\text{ ms}$) | **Durable Code Fix**. Backend application received the request, processed it through application logic, and rejected/sanitized safely. | Status 400/422 with application JSON schema, unchanged server headers. |

---

## 3. Assessing Mitigation Depth (Virtual Patch vs Durable Fix)

If an edge mitigation is suspected, execute bounded variant probing to assess fix durability:

1. **Alternate Encoding**: If single quotes `'` were blocked, test URL encoding `%27`, double encoding `%2527`, or hex encoding.
2. **Method Swap**: If `POST` with `Content-Type: application/x-www-form-urlencoded` is blocked, test `POST` with `Content-Type: application/json` or `multipart/form-data`.
3. **Delimiter Insertion**: Test inserting SQL comments (`/**/`), whitespace variations, or inline parameter separators.

### Classification:
- **Brittle Virtual Patch**: If an alternate encoding or content-type bypasses the block and re-triggers the underlying vulnerability.
- **Durable Remediation**: If all variations fail because the backend uses parameterized queries or server-side input validation.

---

## 4. Reporting Guidance

When a live WAF virtual patch is detected during an engagement:
- Commend the client's Incident Response (IR) team for active monitoring and rapid response capabilities.
- Clearly document that the virtual patch is a temporary defense-in-depth shield rather than a permanent code-level fix, and provide the permanent source-code remediation guidance.

