# Admin Console Access – Developer Quick Start

This guide shows how to open the Admin Console quickly in development and staging, without terminal-only steps.

Audience: Developer (dyslexic-friendly, visual-first). All features must be trait-gated in the UI with no CLI-only flows.

## Dev Mode (fastest path)

Prereqs
- Core running locally on http://localhost:8000
- DEV_MODE enabled on backend (default in this repo)

Steps
1) Start the UI dev server:
   - `cd core/admin_ui`
   - `export VITE_CORE_URL=http://localhost:8000`
   - `npm ci && npm run dev`
   - Open http://localhost:5173
2) Click "Dev Bootstrap (admin)" on the login form. This uses the special development key `bootstrap_admin_only` to log in as an admin (DEV only).
3) The console renders by traits. Admin sees all surfaces. Use UI to configure settings, users, and plugins.

Notes
- No terminal token copy/paste is required in dev.
- If CORS blocks requests, set backend env `ALLOWED_ORIGINS=http://localhost:5173`.

## Production-like Preview (served build)

1) Build UI:
   - `cd core/admin_ui && npm run build`
   - `npx serve -s dist -l 5173`
2) Ensure backend allows the origin:
   - `export ALLOWED_ORIGINS=http://localhost:5173` (or set in compose env)
3) Open http://localhost:5173
4) In dev/staging, you may still use `bootstrap_admin_only`. In production, use `/auth/login` and your MFA-enabled account.

## Feature Flags & Traits

- UI flags: `/admin/ui-config` exposes feature gating (e.g., `admin_console`, `plugins`).
  - Enable via UI: Admin → Config → Set `ui.admin_console.enabled = true`, `ui.plugins.enabled = true`.
- Traits: The UI calls `/admin/user/traits` to decide what to render. Admin maps to `role.admin` in the UI.

## Policy: UI Parity Mandate

Everything operable via CLI MUST be operable in the Admin Console. When adding new capabilities:
- Add trait-mapped UI surfaces and server endpoints.
- Update `/admin/user/traits` mapping if new UI feature flags are introduced.
- Update runbooks and AGENTS.md UI Parity checklist.

## Troubleshooting

- 403/401 on admin endpoints: Missing traits; ensure you used Dev Bootstrap in dev or logged in as admin.
- CORS errors: Set `ALLOWED_ORIGINS=http://localhost:5173` on the backend.
- Plugins page empty: Ensure feature flag `ui.plugins.enabled=true`.
- UI build warnings about chunk size: Safe to ignore for dev; consider code-splitting in production hardening.

