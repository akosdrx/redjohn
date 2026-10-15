---
name: zero_trust_gateway_headers
description: Zero-Trust Gateway Header Stripping & Downstream Identity Forgery (from
  auth_access_control_matrix specialist reference library)
---

# Zero-Trust Gateway Header Stripping & Downstream Identity Forgery

Architectural guide and non-destructive verification procedures for Zero-Trust
reverse proxy edge gateways and downstream microservice identity trust boundaries.

## 1. Threat Model & Architecture

In modern microservice architectures, an edge API Gateway (Kong, Envoy, Nginx,
Traefik, AWS API Gateway, Apigee) acts as the single public-facing entry point.
The gateway terminates TLS, authenticates the client (validates session cookies,
mTLS, or OAuth access tokens), and injects trusted identity headers before
forwarding the request upstream:

```text
[ Client ] 
    │ (Public Internet)
    ▼
[ Edge API Gateway ] ──── Strips incoming X-User-* ────► Injects verified context:
    │                                                    • X-User-Id: 1042
    │ (Internal VPC / Service Mesh)                      • X-User-Role: user
    ▼                                                    • X-Authenticated-User: alice
[ Upstream Microservice ] ◄── Trusts X-User-* headers blindly
```

### The Vulnerability: Missing Ingress Header Sanitization
If the edge reverse proxy or gateway fails to sanitize, overwrite, or strip
client-supplied `X-User-*` headers, an external untrusted attacker can inject
arbitrary identity and authorization claims:
- `X-User-Id`: Impersonate any user ID (BOLA / IDOR bypass).
- `X-User-Role` / `X-User-Roles`: Escalate privileges to `admin`, `system`, or `internal`.
- `X-Authenticated-User` / `X-User-Email`: Override the downstream user principal.
- `X-Tenant-Id` / `X-Org-Id`: Break cross-tenant multi-tenancy isolation.

Because upstream microservices treat the internal network as a trusted perimeter
and do not re-verify credentials, the injected header values take immediate
effect.

## 2. Typical Vulnerable Header Conventions

| Header Name | Typical Purpose in Microservices | Exploitation Impact |
|---|---|---|
| `X-User-Id` | Database foreign key / user entity identifier | Direct IDOR / Horizontal privilege escalation |
| `X-User-Role`, `X-User-Roles` | Comma-separated RBAC roles (`admin`, `support`) | Vertical privilege escalation |
| `X-Authenticated-User` | Username or email of authenticated subject | Account impersonation in audit logs / actions |
| `X-Tenant-Id`, `X-Account-Id` | Multi-tenant organization partition key | Cross-tenant data exfiltration / breach |
| `X-Auth-Scope` | OAuth scope list granted to token | Scope expansion / unauthorized API calls |

## 3. Non-Destructive Verification Procedure

All tests must be conducted non-destructively using operator-sanctioned canary
identifiers:

### Step 1: Capture Baseline Negative Control
Send a request to a protected endpoint without any custom identity headers:
```bash
curl -s -i "https://target.example/api/v1/profile" \
  -H "Authorization: Bearer <low-priv-token>"
```
Observe the returned `user_id`, `role`, or status (e.g. `{"user_id": 1042, "role": "member"}`).

### Step 2: Inject Benign Canary Identity Headers
Re-send the request injecting distinct, observable canary values:
```bash
curl -s -i "https://target.example/api/v1/profile" \
  -H "Authorization: Bearer <low-priv-token>" \
  -H "X-User-Id: rj-pt-canary-999999" \
  -H "X-User-Role: rj-pt-canary-admin" \
  -H "X-Authenticated-User: canary-admin@example.com"
```

### Step 3: Test Unauthenticated Header Injection
Send the same canary headers to an internal or protected route without any
`Authorization` header or session cookie:
```bash
curl -s -i "https://target.example/api/v1/admin/status" \
  -H "X-User-Id: 1" \
  -H "X-User-Role: admin"
```

### Step 4: Differential Analysis & Gate Check
Compare Step 1, Step 2, and Step 3 responses:
1. **Positive Verdict (Vulnerability Proven):**
   - The response in Step 2 reflects the injected canary user ID or grants
     admin functionality.
   - The response in Step 3 returns `200 OK` or privileged data instead of
     `401 Unauthorized` / `403 Forbidden`.
2. **False Positive Guard (Layer-Ordering Trap):**
   - If the endpoint returns `400 Bad Request` or `422 Unprocessable Entity`
     citing "Unknown header" or schema validation error, do NOT claim auth
     bypass.
   - Verify that the response is not a generic header reflection (e.g. debug
     page echoing all received headers without semantic processing).

## 4. Remediation & Zero-Trust Best Practices

1. **Unconditional Edge Ingress Stripping:**
   Configure the edge reverse proxy / API gateway to strip all `X-User-*`,
   `X-Tenant-*`, and internal routing headers from incoming client requests
   *before* any routing or plugin processing:
   - Nginx: `proxy_set_header X-User-Id "";`
   - Envoy: Use `request_headers_to_remove: ["x-user-id", "x-user-role", "x-authenticated-user"]`
   - Kong: Enable `pre-function` or header transformation plugins on all public routes.
2. **Cryptographic Identity Propagation (Zero-Trust):**
   Do not pass raw unauthenticated HTTP headers between services. Instead, the
   gateway should issue a short-lived (e.g. 30–60 second) asymmetric internal JWT
   signed by the gateway's private key and verified by upstream microservices via
   JWKS. Upstream services must validate signature, `exp`, and `aud`.
3. **Mutual TLS (mTLS):**
   Enforce mTLS between the gateway and upstream services to prevent lateral
   movement from bypassing the edge gateway.

