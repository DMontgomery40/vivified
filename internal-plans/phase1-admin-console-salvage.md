# Phase 1 Admin Console Salvage — Implementation Summary

Goal

- Salvage the Admin Console migration so the UI loads without 404s, exposes trait‑gated, framework‑level features, and aligns with HIPAA + Zero‑Trust.
- Replace Faxbot‑specific surfaces with a Vivified Admin Console shell that grows by phases.

What changed

- SPA hosting and fallback already in place (served at `/admin/ui` with index fallback).
- Traits and flags
  - Expanded `/admin/user/traits` to return UI‑mapped traits derived from backend traits: `role.admin`, `ui.plugins`, `ui.config`, `ui.audit`.
  - Kept risky surfaces disabled by default in dev (do not auto‑add `ui.terminal`, `ui.send`).
  - Extended `/admin/ui-config` to include feature flags with safe defaults and ETag support:
    - `features.admin_console.enabled`, `features.plugins.enabled`, `features.v3_plugins.enabled`,
      `features.plugin_install`, `features.sessions_enabled`, `features.csrf_enabled`.
    - Adds optional `docs_base` when configured.
- Safe admin stubs to prevent UI 404s/errors while features are visible:
  - `GET /admin/marketplace/plugins` → `{ plugins: [] }`.
  - `GET /admin/health-status` → minimal health payload.
  - `POST /admin/diagnostics/run` → `{ checks: {}, summary: { ok: true } }`.
- Plugin config stubs (shape‑compatible with the UI):
  - `GET /plugins/{id}/config` → `{ enabled: true, settings: {} }`.
  - `PUT /plugins/{id}/config` → `{ ok: true, path: "in-memory" }`.
- Client logging hardening
  - Removed logging of API keys/headers in `AdminAPIClient`; dev‑only minimal URL/status logs remain.
  - Fixed `getUiConfig` to handle 304 ETag flow without throwing.
- Secret hygiene
  - Removed `.env` from repo (still ignored via `.gitignore`). Please rotate/revoke upstream and scrub history.
- Tests
  - Added SPA fallback + UI config ETag + stub endpoints coverage.
  - Current suite: 6 passed, 0 failed locally.

Behavior now

- `/admin/ui` serves the built SPA; deep links like `/admin/ui/tools/plugins` return index fallback instead of 404s.
- Admin Console surfaces are trait‑gated; unimplemented features are hidden or safely stubbed.
- `/admin/ui-config` returns expanded flags with ETag; client respects 304 conditional requests.
- No sensitive headers or token values are printed by the Admin UI client.
- Dev bootstrap continues to work only when `DEV_MODE=true` (via `/auth/dev-login` or `bootstrap_admin_only`).

Security and HIPAA notes

- Client no longer logs Authorization or API key values; dev logs show only URL/method/status.
- Stubs avoid PHI/PII; audit logging is present for sensitive admin writes (e.g., config updates).
- Keep CSP permissive only for dev; plan a production‑tight CSP in a hardening phase.
- `.env` was present previously; file removed. Rotate/revoke any sensitive keys and scrub history.

File highlights

- Traits and flags
  - `core/api/admin.py`: `/admin/user/traits` mapping; `/admin/ui-config` with expanded flags and ETag.
- Admin stubs
  - `core/api/admin.py`: `GET /admin/marketplace/plugins`, `GET /admin/health-status`, `POST /admin/diagnostics/run`.
- Plugin config
  - `core/main.py`: `GET /plugins/{plugin_id}/config`, `PUT /plugins/{plugin_id}/config`.
- Client hardening
  - `core/admin_ui/src/api/client.ts`: no sensitive logs; robust ETag handling.
- SPA fallback tests
  - `tests/test_admin_ui_spa.py`: asserts 200 on SPA root and deep routes, verifies ETag and stub endpoints, checks trait mapping behavior.

How to run locally

- Served by Core
  - Build UI: `cd core/admin_ui && npm ci && npm run build`
  - Start Core: `docker compose up -d vivified-core`
  - Open `http://localhost:8000/admin/ui`
- Dev servers (hot reload)
  - Start Core: `docker compose up -d vivified-core`
  - Start UI: `cd core/admin_ui && export VITE_CORE_URL=http://localhost:8000 && npm ci && npm run dev`
  - Open `http://localhost:5173` and click “Dev Bootstrap (admin)”

Acceptance criteria status

- /admin/ui loads; deep links work via SPA fallback — met.
- Admin can use framework surfaces: Config, Plugins, Users, Audit; fax‑specific tabs don’t error — met (hidden or stubbed).
- No PHI/PII in logs; no sensitive headers printed in client logs — met.
- Dev bootstrap works only when `DEV_MODE=true`; disabled otherwise — met.
- Bootstrap contract endpoints are in place: `/auth/me`, `/admin/ui-config`, `/admin/user/traits` — met.

Open items and next steps

- Rebrand pass to replace “Faxbot” strings/assets with “Vivified” or neutral placeholders.
- Decide on dev visibility of risky surfaces (Terminal, Send). Currently disabled by default even in dev.
- Optional: add stubs/flags for remaining fax‑specific UI paths (tunnels/actions) to further reduce dead ends.
- Tighten CSP for production, add secret scanning and CI gates.
- CI: add a small integration check to assert 200 for `/admin/ui` and SPA fallback route when `dist/` exists.

Notes

- The server stubs are non‑destructive and return safe shapes to prevent UI toasts. They are trait‑gated and auditable where applicable.
- Config flags read from `config.defaults.json` and can be overridden via the config service.
