# Step 1 — Vivified ↔ Integrations (Frigg) Bridge

Lead-owned execution plan with parallelized TODOs for two junior agents. This plan ensures UI parity, HIPAA gating, audit/PHI safety, white‑labeling, and a Dockerized local stack. The Lead is accountable for architecture, contracts, reviews, and acceptance.

## Guardrails & Non‑Goals
- Keep Vivified Core (FastAPI) as-is; no Node refactor of core.
- White‑label: never surface "Frigg" in API/UI/logs.
- HIPAA mode (toggle) blocks disallowed providers deterministically; audited.
- PHI/PII never logged; audit uses allow‑list meta only.
- Self-host integrator + Mongo; integrator not exposed publicly.
- Deliver working endpoints + Admin Console surface in the same PR (UI parity mandate).

## Roles
- Lead (you): architecture, contracts, HIPAA policy, error taxonomy, audits, reviews, CI orchestration, final docs.
- Agent A (Node/Integrations Service): Frigg-based service + Mongo, OAuth routes, health, internal auth, Compose, envs.
- Agent B (Vivified Core + Admin UI): FastAPI router `/integrations/*`, HIPAA gate, Pydantic contracts, error mapping, audit hooks, Admin UI panel + client wiring, tests.

## High-Level Sequence (avoid stepping)
1) Lead → Contracts & policy freeze (Phase 0)
2) Agent A → Implement integrator service (Phase 1)
3) Lead → Review A and freeze service contracts (Phase 1.5)
4) Agent B → Implement Python router + UI + tests (Phase 2)
5) Lead → Final integration tests, redaction checks, docs (Phase 2.5–3)

---

## API Contracts (frozen at end of Phase 0)

### Internal service (Agent A, private, Docker network only)
- All routes require header: `X-Internal-Token: ${INTERNAL_TOKEN}` (401/403 on mismatch)
- GET `/health` → `{ ok: true }` when server + Mongo connected
- GET `/oauth_url/{provider}?userId=...` → `{ url: string }`
- POST `/oauth_cb/{provider}` body `{ userId: string, code: string, state?: string }` → `{ ok: true, entity: { provider: string, account_name?: string, external_id?: string } }`
- GET `/status/{provider}?userId=...` → `{ connected: boolean, details?: { account_name?: string } }`
- POST `/revoke/{provider}` body `{ userId: string }` → `{ ok: true }`

Error envelope (internal): `{ error: { code: string, message: string } }` (never mentions "Frigg")

### Vivified public API (Agent B)
- GET `/integrations` → `{ items: [ { provider: string, name: string, connected: boolean, details?: { account_name?: string } } ] }`
- POST `/integrations/{provider}/connect` → `{ url: string }`
- GET `/integrations/{provider}/callback` → 302 to Admin UI (Integrations tab) or 200 confirmation page
- GET `/integrations/{provider}/status` → `{ connected: boolean, details?: { account_name?: string } }`
- POST `/integrations/{provider}/revoke` → `{ ok: true }`

Error taxonomy (public):
- `integration.unavailable` (503) — integrator down/unhealthy/timeouts
- `integration.not_allowed` (403) — HIPAA/compliance block (deterministic)
- `integration.oauth_failed` (400/502) — provider/token exchange failure
- `integration.revoke_failed` (502) — failed revoke/cleanup
- `integration.bad_request` (400) — malformed inputs/state

Audit events (Lead to define keys; Agent B to emit):
- `integration_connect_initiated|completed|failed`
- `integration_status_checked`
- `integration_revoke`
- `integration_blocked`
All with `user_id`, `provider`, `result`, and safe `details` only.

HIPAA mode (public): env/config driven. Default deny unless allow‑listed.

---

## Lead — TODOs (Owner: Lead)
1) Define provider catalog (display name/copy) and HIPAA allow‑list policy
   - `PROVIDERS = { hubspot: { name: "HubSpot CRM" } }`
   - `HIPAA_MODE` env + `HIPAA_ALLOWED_PROVIDERS` (comma-separated)
2) Finalize error codes/messages and mapping table (internal→public)
3) Specify Pydantic models for public endpoints
4) Specify log redaction/allow‑list fields; confirm audit service coverage
5) Choose Node deps with versions (Frigg core + hubspot module), Node 20 LTS
6) Draft `.env.example` keys for both services (no secrets checked in)
7) Draft Docker Compose service stanzas and healthchecks; internal networking plan
8) Draft RUN.md outline and HubSpot dev app registration steps
9) Create risk register structure (token rotation, drift, rate limits, identity mapping)
10) Reviews: Phase 1 (Agent A) and Phase 2 (Agent B), with change requests if contracts drift
11) Final CI/test gating: ensure pytest passes; UI smoke built
12) Final docs: RUN.md, HIPAA policy, audit/logging guarantees; file reports in `/internal-plans/step-1/`

Exit criteria for Lead:
- Contracts frozen and implemented identically by A and B
- HIPAA gating enforced; tests prove deterministic block + audit
- Logs prove PHI safety via snapshot/regex tests
- Docker up: core+integrator+mongo green; acceptance scenarios pass

---

## Agent A — TODOs (Node/Integrations Service)
Scope: Self‑hosted integrator behind Vivified, backed by MongoDB; no public exposure.

1) Scaffold Node service under `integrations/` (Express or Koa)
   - `@friggframework` packages pinned (HubSpot first)
   - Node 20.x, `npm ci`, scripts: `dev`, `start`, `lint`
2) Env/config
   - `.env.example`: `MONGO_URI`, `INTERNAL_TOKEN`, `REDIRECT_URI`, `HUBSPOT_CLIENT_ID|SECRET|SCOPE`
   - Respect `NODE_ENV` and `LOG_LEVEL` (prod warns only)
3) Mongo connection + health
   - `/health` returns `{ ok: true }` only when `readyState` ok
4) Internal auth
   - Middleware validates `X-Internal-Token`
5) OAuth endpoints
   - GET `/oauth_url/{provider}?userId=...` → build URL via module manager
   - POST `/oauth_cb/{provider}` → exchange code, persist credential/entity, return entity summary
   - Optional test mode: if `NODE_ENV=test` and `code===TEST_CODE`, simulate success (no external calls)
6) Status + revoke
   - GET `/status/{provider}?userId=...` → connected + minimal details
   - POST `/revoke/{provider}` → remove credentials/entities (and provider revoke if supported)
7) White‑label errors
   - Return `{ error: { code, message } }` with no vendor names
8) Docker Compose integration
   - Add `frigg` service (no published ports) and `mongo` service; healthchecks
9) Docs
   - `integrations/README.md` with exact run commands; envs; scopes; redirect URI

Handover to Lead (Phase 1.5): PR with endpoints + contracts; sample `.env.example`; Compose patch; evidence of local run.

---

## Agent B — TODOs (Vivified Core + Admin UI)
Scope: Public endpoints, trait/HIPAA gating, error mapping, audits, UI panel, tests.

Backend (FastAPI):
1) New router `core/api/integrations.py` (prefix `/integrations`)
   - Dependencies: `require_auth(["admin", "integration_manager"])` (Lead may add trait; fallback to `plugin_manager` if instructed)
2) Routes
   - GET `/integrations` → call internal service across providers; compile list
   - POST `/integrations/{provider}/connect` → call internal `/oauth_url/{provider}`; return URL
   - GET `/integrations/{provider}/callback` → accept `code` (and `state`), call internal `/oauth_cb/{provider}`; then redirect to Admin UI
   - GET `/integrations/{provider}/status` → call internal `/status/{provider}`
   - POST `/integrations/{provider}/revoke` → call internal `/revoke/{provider}`
3) HIPAA enforcement
   - If `HIPAA_MODE=true` and provider not in allow‑list → 403 `integration.not_allowed` + audit `integration_blocked`
4) Error mapping
   - Map internal `{error:{code}}` to public taxonomy; 503 on integrator unavailability
5) Audit events
   - Emit events for initiate/complete/fail/revoke/status
6) Contracts
   - Pydantic models for all responses; strict types
7) Logging
   - No token/PII; safe field allow‑list only

Admin UI (Settings → Providers):
1) Add Providers tab/panel
   - List connectors; show status; Connect/Revoke buttons; trait‑gated
2) API client additions
   - Methods that call public `/integrations/*` endpoints
3) OAuth UX
   - Connect opens URL in new window/tab; callback returns user to the Providers panel (redirect)
4) HIPAA UX
   - Disabled actions with clear, deterministic message; reflect server responses
5) UI smoke test
   - Render with admin+integration_manager traits; ensure list/status actions work

Tests (pytest):
1) Trait gating: 403 for insufficient traits; 200 for admin
2) OAuth URL issuance: validate shape
3) Callback success (test mode): status flips to connected
4) Revoke → status flips to disconnected
5) HIPAA mode: disallowed provider returns 403 + audit event
6) PHI redaction: capture logs and assert no sensitive patterns

Handover to Lead (Phase 2.5): PR with router, UI, tests, docs; green pytest.

---

## Timing & Coordination
- Phase 0 (Lead, 0.5d): finalize contracts, policy, env keys, Compose draft
- Phase 1 (Agent A, 1–1.5d): build integrator service + Compose + health
- Phase 1.5 (Lead, 0.25d): review A; freeze internal contracts
- Phase 2 (Agent B, 1.5–2d): implement FastAPI + UI + tests
- Phase 2.5–3 (Lead, 0.5d): E2E tests, redaction test, RUN.md, risk/docs

Dependencies & Hand‑offs:
- Agent B blocks on Phase 1.5 contract freeze; can stub against explicit internal spec but must re‑run after A merges
- Lead reviews block merges; Lead owns error taxonomy stability

---

## Configuration & Env Keys (initial set)
- Vivified Core:
  - `JWT_SECRET`, `DEV_MODE=true`, `INTEGRATIONS_HIPAA_MODE`, `INTEGRATIONS_HIPAA_ALLOWED` (comma)
  - `INTEGRATIONS_INTERNAL_TOKEN`, `INTEGRATIONS_BASE_URL=http://frigg:3001`
- Integrator (Node):
  - `MONGO_URI`, `INTERNAL_TOKEN`, `REDIRECT_URI=http://vivified-core:8000/integrations/{provider}/callback`
  - `HUBSPOT_CLIENT_ID|SECRET|SCOPE`

---

## Risks & Mitigations (to expand in risk register)
- Token expiry/refresh: rely on module; add `testAuth` on status or lazy refresh
- OAuth state/CSRF: generate/store/verify `state` in Vivified
- Identity mapping: use Vivified `user.id` string; if ObjectId required, create mapping
- Rate limits: minimal in Step 1; document; backoff in future
- Connector drift: pin versions; review matrix; plan upgrade cadence
- Log leakage: enforce redaction, run snapshot tests
- Service availability: return 503 with friendly messages; Compose auto‑restart; healthchecks

---

## Acceptance Checklist (Lead to sign)
- `docker compose up` → core + integrator + mongo healthy
- GET `/integrations` → real list from internal service
- POST `/integrations/hubspot/connect` → real OAuth URL; callback → connected
- GET `/integrations/hubspot/status` reflects true state; POST `/revoke` removes connection
- HIPAA=true blocks disallowed provider with deterministic error; audited
- Logs contain no PHI; tests pass locally; UI surface present and gated

