# Integrations API (Public)

Trait-gated endpoints to manage external integrations via a secure sidecar.

- Base path: `/integrations`
- Access: `admin` OR `integration_manager`
- White-labeled: No vendor names in API or errors
- Audited: All actions emit minimal, PHI-safe audit events

## Endpoints

- GET `/integrations`
  - 200 → `{ items: [ { provider, name, connected, details? } ] }`
  - Notes: Aggregates known providers and per-user status

- POST `/integrations/{provider}/connect`
  - 200 → `{ url }` (Open in a new tab)
  - Behavior: Core generates a short‑lived `state` (10 min TTL) and passes it to the sidecar. Callback must return the same state.

- GET `/integrations/{provider}/callback?code=&state=`
  - 302 → Redirects to Admin Console (Providers panel)
  - Validates `state` (exact match + single-use) and forwards the code to the sidecar

- GET `/integrations/{provider}/status`
  - 200 → `{ connected, details? }`
  - Notes: Details may include `{ account_name }`

- POST `/integrations/{provider}/revoke`
  - 200 → `{ ok: true }`

## Error Taxonomy (Public)

- `integration.unavailable` (503): sidecar down/unreachable/timeouts
- `integration.not_allowed` (403): Compliance/HIPAA block
- `integration.oauth_failed` (400/502): token exchange or URL generation failed
- `integration.revoke_failed` (502): revoke failed at sidecar
- `integration.bad_request` (400): malformed input or missing entity

Internal → Public:
- `service.unavailable|mongo.unavailable|health.unready` → `integration.unavailable`
- `oauth.exchange_failed|oauth.invalid_code|oauth.state_mismatch|oauth.url_generation_failed` → `integration.oauth_failed`
- `entity.not_found|credential.not_found` → `integration.bad_request`
- `credential.delete_failed` → `integration.revoke_failed`

## Compliance (HIPAA)

- When `INTEGRATIONS_HIPAA_MODE=true`, only providers in `INTEGRATIONS_HIPAA_ALLOWED` (comma‑sep) are operable
- Others return 403 `{ error: { code: 'integration.not_allowed' } }`
- Audit event: `integration_blocked`

## Configuration

Set these in Core:

- `INTEGRATIONS_BASE_URL` (default `http://frigg:3001`)
- `INTEGRATIONS_INTERNAL_TOKEN` (must match sidecar `INTERNAL_TOKEN`)
- `INTEGRATIONS_HIPAA_MODE` (`true|false`)
- `INTEGRATIONS_HIPAA_ALLOWED` (comma‑separated providers)

## Internal Auth (Sidecar)

Core calls the sidecar with both headers (back‑compat):

- `X-Internal-Auth: ${INTEGRATIONS_INTERNAL_TOKEN}`
- `X-Internal-Token: ${INTEGRATIONS_INTERNAL_TOKEN}`

Sidecar must reject requests without a valid token (skip `/health`).

## OAuth State

- Core generates and stores a short‑lived `state` per user+provider
- Sidecar must accept and echo `state` in the provider URL; do not mutate
- Callback validates exact match (single-use), then redirects back to the Admin Console

## Audits (minimal, PHI-safe)

- `integration_connect_initiated|completed|failed`
- `integration_status_checked`
- `integration_revoke`
- `integration_blocked`

Includes: `user_id`, `provider`, `result`, and allowlisted details (e.g., `account_name`).
