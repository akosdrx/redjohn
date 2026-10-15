---
name: edge_normalization
description: Edge-vs-Origin Path Normalization & Delimiter Matrix (from waf_edge_posture
  specialist reference library)
---

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

