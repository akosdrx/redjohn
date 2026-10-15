---
name: origin_discovery
description: Direct-to-Origin Exposure & Verification Protocol (from waf_edge_posture
  specialist reference library)
---

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

