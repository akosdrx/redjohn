---
name: sast_dast_blindspots
description: SAST and DAST Blind-Spot Analysis (from zeroday_patch_research specialist
  reference library)
---

# SAST and DAST Blind-Spot Analysis

Automated scanners (Static Application Security Testing and Dynamic Application
Security Testing) provide broad baseline coverage but reliably miss critical
vulnerability classes due to fundamental architectural limitations. This guide
documents these blind spots so the zero-day and n-day research path focuses
investigation where scanners fail.

---

## 1. SAST (Static Analysis) Blind Spots

SAST analyzers parse ASTs and construct control-flow/data-flow taint graphs from
source code without a runtime environment. They fail in specific architectural patterns:

1. **Microservice & Asynchronous Boundaries:**
   - Static taint graphs terminate when data crosses process boundaries.
   - An untrusted input written to a message bus (Kafka, RabbitMQ, SQS) or sent
     via internal RPC (gRPC, internal HTTP REST) disappears from the caller's
     taint graph.
   - Downstream microservices ingesting from the queue or RPC endpoint are
     frequently treated as trusted sources by SAST, missing critical injection
     or deserialization sinks.

2. **Dynamic Reflection, Class Loading & Dependency Injection:**
   - Framework-level dynamic invocation (Java `Class.forName()`, Spring Bean
     factories, Python `getattr()`, PHP dynamic class instantiation, Node.js
     dynamic `require()`) breaks static call graph construction.
   - Annotation-driven routing (`@RestController`, `@MessageMapping`) and
     custom aspect-oriented programming (AOP) decorators obscure source-to-sink
     execution order.

3. **Runtime Configuration & Environmental Disconnect:**
   - SAST analyzes code in isolation from runtime settings (`application.yml`,
     `.env`, Kubernetes ConfigMaps, feature flags, Vault secrets).
   - A sink that appears sanitized in code may execute with sanitization disabled
     due to an active debug flag (`DEBUG=true`, `security.strict-parsing=false`)
     at runtime.

---

## 2. DAST (Dynamic Analysis) Blind Spots

DAST scanners crawl endpoints and inject test payloads from the outside without
internal application state visibility. They fail on complex stateful surfaces:

1. **Multi-Step Stateful Business Workflows:**
   - DAST crawlers operate on single-request/single-response loops.
   - Stateful multi-phase workflows (e.g., Cart Creation -> Address Validation ->
     Discount Coupon -> Payment Gateway Handshake -> Order Fulfillment) cannot
     be traversed automatically.
   - Parameter manipulation or state-machine skips inside step 3 of a 5-step
     checkout are missed completely.

2. **Strict Anti-Automation & Ephemeral Nonces:**
   - Modern defenses (rotating single-use anti-CSRF tokens, cryptographic
     request signatures, ephemeral Proof-of-Work nonces, CAPTCHAs, TLS
     fingerprinting) block automated DAST spiders on first contact.
   - An aggressive scan payload that triggers an account lockout or session
     invalidation blinds the DAST scanner for all subsequent requests in that
     context.

3. **Unlinked, Deprecated & Shadow API Routes:**
   - DAST tools discover endpoints primarily by crawling links, HTML forms, and
     public client-side JavaScript bundles.
   - Legacy API endpoints (e.g., `/api/v1/user/export` left active after
     `/api/v2/user/export` was patched), internal debug routes, and administrative
     endpoints are never hyperlinked and remain invisible to dynamic spiders.

---

## 3. Patch-Gap & N-Day Regression Heuristics

When an upstream vendor or project publishes a security patch, automated tooling
frequently reports the vulnerability as resolved. However, patches are often incomplete:

1. **Point-Fix Syndrome:**
   - Developers frequently apply a quick check (e.g. checking `if (param != null)`)
     only on the specific parameter or controller path named in the original bug report.
   - The underlying core sink (database query helper, XML parser, template evaluator)
     remains accessible via alternate controllers, sibling routes, or alternate HTTP methods.

2. **HTTP Verb & Content-Type Polymorphism:**
   - A patch may validate input in the `POST` handler while leaving `PUT`, `PATCH`,
     or `GET` unvalidated if the framework router dispatches to the same business logic.
   - A controller configured for JSON parsing may accept `application/xml` or
     `application/x-yaml` via content negotiation without applying the same parameter sanitizers.

3. **Methodology for Patch-Gap Auditing:**
   - Use `secdiff.py` to identify the sink-adjacent diff in the patch.
   - Search the repository for all other callers of the modified sink or helper function.
   - Test whether alternate routes or unlinked legacy endpoints share the vulnerable sink.
   - Verify with the version-discriminating PoC discipline (pre-patch vs post-patch).

