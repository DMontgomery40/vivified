# Agent B Brief — Vivified Core (FastAPI) + Admin UI

Owner scope: Implement the public, white‑labeled `/integrations/*` endpoints in Vivified with trait/HIPAA gating, error mapping, audits, and an Admin Console Providers panel. Follow contracts in `internal-plans/step-1/contracts.md`.

## Backend (FastAPI)
1) New router: `core/api/integrations.py` (prefix `/integrations`)
   - Dependency: `require_auth(["admin", "integration_manager"])` (Lead may add `integration_manager`; use `plugin_manager` temporarily only if instructed)
2) Endpoints:
   - GET `/integrations` → aggregate list across providers with `name`, `connected`, `details.account_name?`
   - POST `/integrations/{provider}/connect` → return `{ url }` from internal `/oauth_url/{provider}`
   - GET `/integrations/{provider}/callback` → accept `code` (and `state`), call internal `/oauth_cb/{provider}`, then redirect to Admin UI Providers panel
   - GET `/integrations/{provider}/status` → map internal `/status/{provider}`
   - POST `/integrations/{provider}/revoke` → map internal `/revoke/{provider}`
3) HIPAA enforcement:
   - If `INTEGRATIONS_HIPAA_MODE=true` and provider not in `INTEGRATIONS_HIPAA_ALLOWED`, return 403 `{ error: { code: "integration.not_allowed", message: "This integration is disabled in compliance mode" } }` and emit `integration_blocked` audit
4) Error mapping:
   - Map internal `{ error: { code } }` to public taxonomy; return 503 on unavailability/timeouts
5) Audit events:
   - Emit events: `integration_connect_initiated|completed|failed`, `integration_revoke`, `integration_status_checked`, `integration_blocked`
6) Contracts:
   - Implement Pydantic models from the contract doc; keep responses strictly typed
7) Logging:
   - No tokens/PII in logs; only allow‑listed fields; rely on existing audit redactor

## Admin UI (Settings → Providers)
1) Add Providers tab/panel (trait‑gated)
   - List known providers; show status; Connect/Revoke buttons; reflect HIPAA disabled state deterministically
2) API client additions
   - Methods for new `/integrations/*` endpoints
3) OAuth UX
   - Connect opens URL in a new tab; callback redirects back to Providers panel
4) UI smoke
   - Render with admin + integration_manager traits; list/status actions work (mocked or live)

## Tests (pytest)
1) Trait gating: 403 for insufficient traits; 200 for admin
2) Connect URL issuance: validate structure
3) Callback success (test mode): status flips to connected
4) Revoke → status flips to disconnected
5) HIPAA mode: disallowed provider → 403 + audited denial
6) PHI redaction: capture logs; assert no sensitive patterns

## Deliverables
- Router file + wiring in `core/main.py`
- Admin UI Providers panel + client wiring
- Tests under `tests/` with fixtures
- No mention of vendor names in API/UI/errors/logs

## Timeline & Dependencies
- Start after Phase 1.5 (Lead review of Agent A’s service contracts)
- Target: 1.5–2 days

