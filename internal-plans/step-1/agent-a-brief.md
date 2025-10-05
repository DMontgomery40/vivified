# Agent A Brief — Integrations Service (Node + Mongo)

Owner scope: Build a self‑hosted integrator service that exposes the internal API specified in `internal-plans/step-1/contracts.md` and manages OAuth for HubSpot using Frigg modules. No public exposure. All endpoints must require `X-Internal-Token`.

## Deliverables
1) `integrations/` Node project:
   - Node 20.x, TypeScript optional (JS acceptable). Scripts: `dev`, `start`, `lint`.
   - Pinned deps:
     - `@friggframework/api-module-hubspot@^1.1.7`
     - `express@^4`, `mongoose@^7`, `axios@^1` (or `node-fetch@^3`), `dotenv@^16`
   - Middleware: internal token check on all routes
2) Endpoints (all white‑labeled, never mention vendor names):
   - GET `/health` → `{ ok: true }` (Mongo ready)
   - GET `/oauth_url/{provider}?userId=...` → `{ url }`
   - POST `/oauth_cb/{provider}` `{ userId, code, state? }` → `{ ok: true, entity: { provider, account_name?, external_id? } }`
   - GET `/status/{provider}?userId=...` → `{ connected, details? }`
   - POST `/revoke/{provider}` `{ userId }` → `{ ok: true }`
3) Mongo DB persistence: credentials/entities
4) Docker Compose service + `mongo` service with healthchecks (no published ports for the integrator)
5) `.env.example` with exact keys: `MONGO_URI`, `INTERNAL_TOKEN`, `REDIRECT_URI`, `HUBSPOT_CLIENT_ID|SECRET|SCOPE`
6) `integrations/README.md` with copy‑paste commands; notes for HubSpot app registration (scopes; redirect)

## Non‑Goals
- Do not expose the service on host ports; internal Docker network only.
- Do not print tokens or PII in logs; keep logs at warn/error in prod.

## Acceptance Criteria
- `docker compose up` brings `frigg` (this service) + `mongo` healthy; `/health` returns `{ ok: true }`
- `/oauth_url/hubspot` returns a valid URL containing `client_id`, `redirect_uri`, and requested scopes
- `POST /oauth_cb/hubspot` exchanges a code for tokens and creates an entity (in test mode, `code=TEST_CODE` simulates success with no external calls)
- `/status/hubspot` flips to `connected: true` after callback; `/revoke` flips back to false
- All routes enforce `X-Internal-Token`; errors return `{ error: { code, message } }`

## Timeline & Dependencies
- Start immediately (Phase 1). Target: 1–1.5 days.
- Contracts frozen in `internal-plans/step-1/contracts.md` — coordinate with Lead on any drift before implementation.

## Notes
- OAuth State: Accept `state` field and include it in URL if passed from Vivified; do not enforce in service (Vivified validates state).
- User Identity: Treat `userId` as opaque string; do not assume ObjectId.
- Testing: Implement `NODE_ENV=test` and `code===TEST_CODE` bypass to simulate a successful OAuth exchange for CI.

