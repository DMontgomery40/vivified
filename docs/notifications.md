Vivified Notification Plugins

Overview
- Apprise Notifier: Multi‑provider fan‑out using Apprise (POC, dry‑run by default)
- Pushover Notifier: Direct push notifications via Pushover API (proxied via Gateway)

Admin Console
- Plugins appear under Tools → Plugins when enabled.
- Configure required settings from plugin manifests:
  - Apprise: `APPRISE_TARGET_URLS` (comma‑separated Apprise URLs)
  - Pushover: `PUSHOVER_API_TOKEN`, `PUSHOVER_USER_KEY`

Gateway Allowlist (Pushover)
- Add `api.pushover.net` to the Gateway allowlist for `pushover-notifier` with method `POST` and path `/1/messages.json`.
- Admin UI → Settings → Gateway Allowlist.

Operator Endpoints
- Apprise: `POST /send { title?, body, targets? }` (dry‑run default)
- Pushover: `POST /send { message, title? }`

Canonical Events
- Plugins publish `NotificationSent` to `/messaging/events` with delivery details.

Security Notes
- External calls should route through the core Gateway service.
- Plugins declare traits `handles_notifications`, `requires_config`, and `external_service`.

