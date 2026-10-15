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
