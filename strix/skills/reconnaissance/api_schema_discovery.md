---
name: api_schema_discovery
description: 'API schema discovery: probe list and verification (from recon_endpoint_mapping
  specialist reference library)'
---

# API schema discovery: probe list and verification

Concrete probes for exposed API definitions. All requests are serial,
scope-guarded GETs/POSTs against the in-scope origin; substitute
`https://target.example.com` with the engagement target.

## OpenAPI / Swagger probe list

| Path | Method | Positive signal |
|---|---|---|
| `/openapi.json` | GET | 200 + JSON with `openapi` or `swagger` top-level key |
| `/openapi.yaml` | GET | 200 + YAML with `openapi:` key |
| `/swagger.json` | GET | 200 + JSON with `swagger: "2.0"` or `openapi` key |
| `/swagger/v1/swagger.json` | GET | ASP.NET Core default swagger location |
| `/api/swagger.json` | GET | Common when API is mounted under `/api` |
| `/api/docs/swagger.json` | GET | NestJS-style docs mount |
| `/v2/api-docs` | GET | Springfox (Swagger 2) default |
| `/v3/api-docs` | GET | Springdoc (OpenAPI 3) default |
| `/v3/api-docs/swagger-config` | GET | Springdoc UI config; lists doc URLs |
| `/api-docs` | GET | Generic mount |
| `/api-docs/swagger.json` | GET | Generic mount variant |
| `/swagger-ui.html` | GET | Swagger UI redirect (302 to `/swagger-ui/index.html`) |
| `/swagger-ui/index.html` | GET | Swagger UI page (fetch its `url:` config) |
| `/swagger-ui/` | GET | Directory UI without `.html` |
| `/doc` , `/docs` | GET | Many frameworks mount docs UI here |
| `/actuator/mappings` | GET | Spring Boot endpoint map (may need actuator exposure) |
| `/api.raml` | GET | RAML definition |
| `/apidoc` , `/api/apidoc` | GET | apiDoc-style generated docs |

## Verification rules (before calling it exposed)

1. 200 alone proves nothing: confirm `Content-Type` is `application/json`
   (or YAML/text for YAML) and the body parses with a top-level
   `openapi`/`swagger`/`paths`/`definitions` key.
2. HTML login pages returned with 200 on these paths = soft-404; discard.
3. `swagger-config` responses count only when they list a reachable doc URL.
4. Check whether the schema is intentionally public (linked from `/docs` or
   marketing site) before drafting a finding; intentional exposure is an
   information-disclosure observation at most.

## GraphQL probes

Endpoints to try, in order: `/graphql`, `/api/graphql`, `/v1/graphql`,
`/graphql/v1`, `/graphiql`, `/altair`, `/playground`.

Minimal introspection query (POST with
`Content-Type: application/json`):

```json
{"query":"query IntrospectionProbe { __schema { queryType { name } } }"}
```

- 200 + `data.__schema` -> introspection open; record evidence pair.
- Error mentioning "introspection" / "disabled" -> endpoint exists,
  introspection blocked; register surface for `60`.
- 404/HTML -> move to the next path.
- Full schema dump is `60-api-graphql-websockets` work (depth limits,
  field-level authorization); P1 only proves the endpoint and open/closed
  introspection state.

## WSDL / SOAP probes

| Probe | Notes |
|---|---|
| `GET /Service.asmx?WSDL` | ASP.NET SOAP |
| `GET <endpoint>?wsdl` on every `/services/*` path found in the crawl | Java/Axis/CXF style |
| `GET /wsdl` | Generic mount |
| `GET /api/soap?wsdl` | SOAP under an API mount |
| `GET /soap` and `/soap/` | Generic SOAP gateway |

Positive signal: 200 + `Content-Type: text/xml` + root element
`<wsdl:definitions` or `<definitions`. Register operations; WSDL testing
(XML payloads, XXE, SOAPAction abuse) belongs to `40`/`60`.

## Registration

For every confirmed schema:

```text
schema | type=openapi3 | url=https://target.example.com/v3/api-docs |
  operations=<count> | auth=none | evidence=evidence/p1-api-schema-001.{req,resp}.txt
```

Then register each operation as an inventory row (method, path, params,
declared auth). No testing beyond the discovery request(s) at P1; the
operation list is consumed by `30` (role matrix), `40` (input surfaces),
`58`/`60` (API-specific checks).

