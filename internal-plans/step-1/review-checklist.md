# Lead PR Review Checklist — Step 1 Bridge

Use this to review Agent A and Agent B PRs before merge.

## Agent A — Integrations Service (Node + Mongo)
- Security
  - [ ] All routes require `X-Internal-Token` and reject on mismatch
  - [ ] Service not exposed on host ports; internal Docker network only
  - [ ] Logs set to warn/error in prod; no tokens/PII in logs
- Health & DB
  - [ ] `/health` returns `{ ok: true }` only when Mongo is connected
  - [ ] Docker healthcheck configured and passing
- OAuth & Endpoints
  - [ ] `/oauth_url/{provider}?userId=...` returns a valid provider URL with correct `redirect_uri` and scopes
  - [ ] `/oauth_cb/{provider}` exchanges `code` (or simulates when `NODE_ENV=test` and `code=TEST_CODE`)
  - [ ] `/status/{provider}` reflects connection state; `/revoke` cleans up credentials/entities
  - [ ] Error envelope is `{ error: { code, message } }` (no vendor names)
- Config & Docs
  - [ ] `.env.example` includes all required keys; README has exact commands
  - [ ] Docker Compose service entries (integrator + mongo) added with healthchecks

## Agent B — Vivified Core + Admin UI
- Gating & HIPAA
  - [ ] `/integrations/*` endpoints exist and are trait‑gated (`admin` or `integration_manager`)
  - [ ] HIPAA mode enforced via env/config; disallowed providers return 403 `integration.not_allowed` and audited
- Error Mapping
  - [ ] Internal errors mapped to public taxonomy; 503 for unavailability; no vendor names leak
- Audits & Logging
  - [ ] Audit events on connect initiate/complete/fail, status checks, revoke, blocked
  - [ ] No PHI/PII/tokens in logs; leverage redactor; tests include regex/snapshot
- Contracts & Types
  - [ ] Pydantic models match `contracts.md`
  - [ ] Query/body shapes align with internal service
- Admin UI (Settings → Providers)
  - [ ] Providers panel present, trait‑gated, lists connectors and statuses
  - [ ] Connect launches new tab/window; callback returns to panel; Revoke works; HIPAA disabled state is clear
  - [ ] UI smoke test present (renders with traits, calls endpoints)

## End‑to‑End Acceptance
- [ ] `docker compose up` → core + integrator + mongo healthy
- [ ] GET `/integrations` returns list sourced from integrator
- [ ] POST `/integrations/hubspot/connect` → returns real OAuth URL; callback sets connected
- [ ] GET `/integrations/hubspot/status` shows connected; POST `/revoke` disconnects
- [ ] HIPAA=true blocks with deterministic error and audit
- [ ] Tests pass locally; logs are PHI‑safe

