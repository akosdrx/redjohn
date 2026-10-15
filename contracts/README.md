# RedJohn contracts

Canonical, versioned contracts shared by rj-cli, rj-desktop and rj-cloud.

| File | Content | Consumers |
|---|---|---|
| `openapi.yaml` | RedJohn API v1 (local engine; cloud extends in `cloud-ext.openapi.yaml`) | FastAPI implementations, TS client codegen |
| `run-event.schema.json` | RunEvent envelope, `schema_version=1` | engine outbox, WS clients, CLI `--format ndjson` |
| `ts-client/` | generated TypeScript client (do not edit by hand) | rj-desktop, rj-cloud web |

Rules:

1. The Pydantic models in `rj-cli/packages/core/src/redjohn_core/models.py` and
   `events.py` are the anchor. `openapi.yaml` and the JSON Schema are exported
   from them (`python -m redjohn_core.contracts_export`) and diffed in CI.
2. Contract bumps: patch = additive optional fields/routes; minor = new required
   request fields or new event types; major = removed/renamed anything. The
   integration lead owns merges; regenerate the TS client after every bump.
3. Frontend mocks, when needed, are generated from these files and must carry a
   visible "demo" marker in the UI.
4. Cloud-only routes (auth, workspaces, billing, usage, audit) live in
   `cloud-ext.openapi.yaml` and never leak Stripe types into shared models.
5. WebSocket auth: CLI sends `Authorization: Bearer <token>`; browser renderers
   (cannot set WS headers) offer the token as a `rj-auth-<base64url(token)>`
   subprotocol, which the server echoes on accept. `?token=` query auth is
   forbidden (URLs leak into logs).
6. v0.1.1 additions: `Run.ref` human reference (RJ-024), `GET /evidence?run_id=`,
   `GET /reports?run_id=`, `Report` model anchored in models.py.
