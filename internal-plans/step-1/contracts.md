# Step 1 Contracts — Vivified ↔ Integrations Bridge

This document freezes the external/public and internal/private API contracts, error taxonomy, HIPAA policy, logging guarantees, and configuration keys for the Step 1 bridge. All agents must adhere to these without deviation.

## Provider Catalog and HIPAA Policy
- Catalog (initial):
  - `hubspot`: name "HubSpot CRM" (default: not HIPAA‑allowed)
- HIPAA mode behavior:
  - When `INTEGRATIONS_HIPAA_MODE=true`, only providers listed in `INTEGRATIONS_HIPAA_ALLOWED` (comma‑sep) are operable. All others return 403 with code `integration.not_allowed` and are audited.

## Internal Integrator Service API (private, Docker network only)
- Security: Require header `X-Internal-Token: ${INTERNAL_TOKEN}` on all routes.
- GET `/health`
  - 200 → `{ ok: true }` when server and Mongo are ready
- GET `/oauth_url/{provider}?userId=...`
  - 200 → `{ url: string }`
- POST `/oauth_cb/{provider}`
  - Body: `{ userId: string, code: string, state?: string }`
  - 200 → `{ ok: true, entity: { provider: string, account_name?: string, external_id?: string } }`
- GET `/status/{provider}?userId=...`
  - 200 → `{ connected: boolean, details?: { account_name?: string } }`
- POST `/revoke/{provider}`
  - Body: `{ userId: string }`
  - 200 → `{ ok: true }`
- Error envelope (never mentions vendors): `{ error: { code: string, message: string } }`
  - Examples: `oauth.exchange_failed`, `entity.not_found`, `credential.delete_failed`, `service.unavailable`

## Vivified Public API (FastAPI)
- All endpoints white‑labeled and trait‑gated by `admin` OR `integration_manager` (Lead will add trait; fall back to `plugin_manager` if instructed).
- GET `/integrations`
  - 200 → `{ items: [ { provider: string, name: string, connected: boolean, details?: { account_name?: string } } ] }`
- POST `/integrations/{provider}/connect`
  - 200 → `{ url: string }`
- GET `/integrations/{provider}/callback`
  - 302 → Redirect to Admin UI Providers view (or 200 small confirmation page)
- GET `/integrations/{provider}/status`
  - 200 → `{ connected: boolean, details?: { account_name?: string } }`
- POST `/integrations/{provider}/revoke`
  - 200 → `{ ok: true }`

## Error Taxonomy (public)
- `integration.unavailable` (503): integrator down/unreachable/timeout
- `integration.not_allowed` (403): HIPAA/compliance gate
- `integration.oauth_failed` (400/502): provider or token exchange failure
- `integration.revoke_failed` (502): failed revoke/cleanup
- `integration.bad_request` (400): malformed inputs/state

Mapping (internal → public):
- `service.unavailable|mongo.unavailable|health.unready` → `integration.unavailable`
- `oauth.exchange_failed|oauth.invalid_code|oauth.state_mismatch` → `integration.oauth_failed`
- `entity.not_found|credential.not_found` → `integration.bad_request`
- `credential.delete_failed` → `integration.revoke_failed`

## Pydantic Models (public, reference spec)
- `IntegrationItem`: `{ provider: str, name: str, connected: bool, details: Optional[dict] }`
- `IntegrationsList`: `{ items: List[IntegrationItem] }`
- `ConnectResponse`: `{ url: str }`
- `StatusResponse`: `{ connected: bool, details: Optional[dict] }`
- `RevokeResponse`: `{ ok: bool }`
- `ErrorResponse`: `{ error: { code: str, message: str } }`

## Logging & Audit Guarantees
- No tokens, OAuth codes, emails, phone numbers, SSNs, addresses, or free‑text payloads in logs.
- Audit events (minimal, safe `details`):
  - `integration_connect_initiated|completed|failed`
  - `integration_status_checked`
  - `integration_revoke`
  - `integration_blocked`
- Each includes: `user_id`, `provider`, `result`, and allow‑listed `details` (counts or display names), never secrets.

## OAuth State & Redirect
- Vivified generates `state` and stores short‑lived value (per user) to verify on callback.
- `REDIRECT_URI` for the integrator must route back to Vivified callback: `http://vivified-core:8000/integrations/{provider}/callback` in Docker; localhost equivalent for dev.
- Admin UI opens the provider URL in a new window/tab; callback returns to Providers view.

## Configuration Keys
- Vivified Core
  - `INTEGRATIONS_BASE_URL` (default `http://frigg:3001` inside Docker)
  - `INTEGRATIONS_INTERNAL_TOKEN`
  - `INTEGRATIONS_HIPAA_MODE` (`true|false`)
  - `INTEGRATIONS_HIPAA_ALLOWED` (comma‑sep providers)
- Integrator (Node)
  - `MONGO_URI` (e.g., `mongodb://mongo:27017/frigg`)
  - `INTERNAL_TOKEN`
  - `REDIRECT_URI` (base, provider appended if needed)
  - `HUBSPOT_CLIENT_ID`, `HUBSPOT_CLIENT_SECRET`, `HUBSPOT_SCOPE`

## Module Selection (initial)
- Node: 20.x (LTS)
- HubSpot connector: `@friggframework/api-module-hubspot@^1.1.7` (latest as of this plan)
- Server libs: `express@^4`, `mongoose@^7`, HTTP client (`axios` or `node-fetch`), validation (optional: `zod`)

