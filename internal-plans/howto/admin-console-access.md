# Admin Console Access – Developer Quick Start

This guide shows how to open the Admin Console quickly in development and staging, with Docker as the default path.

Audience: Developer (dyslexic-friendly, visual-first). All features must be trait-gated in the UI with no CLI-only flows.

## Default: Docker (recommended)

Prereqs
- Docker + Docker Compose installed

Steps
1) Start the stack:
   - `docker compose up -d`
2) Open the Admin Console served by Core:
   - http://localhost:8000/admin/ui
3) Use Dev Bootstrap on the login form (DEV only):
   - Click "Dev Bootstrap (admin)". Backend maps `bootstrap_admin_only` to an admin JWT when `DEV_MODE=true`.

Notes
- UI is bundled into the Core image during build (multi-stage Node→Vite→static copy). No separate UI container is required.
- CORS: Not needed for the default path because UI is same-origin under `/admin/ui`.

### Docker Vite (hot reload)
- Start only Core and the UI dev server:
  - `docker compose up -d vivified-core admin-ui-dev`
- Open http://localhost:5173 (Vite dev server)
- The dev server proxies directly to Core via absolute base `VITE_CORE_URL=http://localhost:8000`.
- Watch logs (first run installs deps):
  - `docker logs -f vivified-admin-ui-dev-1`

## Dev Mode (hot reload / Vite)

Prereqs
- Core running locally on http://localhost:8000 (or via `docker compose up -d`)
- DEV_MODE enabled on backend (default in this repo)
- Node 18+ and npm 9+ (Vite requires modern Node)

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

Option A — Served by Core (recommended)
1) Build UI: `cd core/admin_ui && npm ci && npm run build`
2) Start Core: `docker compose up -d vivified-core` (or `uvicorn core.main:app`)
3) Open http://localhost:8000/admin/ui
4) In dev/staging, you may still use `bootstrap_admin_only`. In production, use `/auth/login` and your MFA-enabled account.

Option B — Standalone static server
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
- npm ERESOLVE mentions `react-scripts@5.x` or TypeScript `^3||^4` conflict:
  - You are on an old Create React App install. The Admin Console now uses Vite.
  - Verify you’re in `core/admin_ui` and that `package.json` contains `"dev": "vite"` (no `react-scripts`).
  - Clean reinstall: `rm -rf node_modules package-lock.json && npm ci`.
  - If you still see `react-scripts`, pull latest from the repo or reset local changes in `core/admin_ui`.
- Docker Core fails to start complaining about `psycopg2`:
  - Ensure `docker-compose.yml` uses `DATABASE_URL=postgresql+asyncpg://...` (async driver), not `postgresql://`.
- 404 on `/admin/ui` inside Docker:
  - Rebuild images: `docker compose build vivified-core && docker compose up -d` (ensures the UI was bundled into the image).
