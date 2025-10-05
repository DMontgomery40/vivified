# Admin UI — Providers Panel Spec

Placement: Settings → Providers

## Gating
- Visible only if user has `admin` or `integration_manager` trait.

## UI Elements
- Provider list:
  - Name (from catalog), status chip (Connected / Not connected / Disabled by policy)
  - Actions: Connect (primary), Revoke (danger)
- HIPAA mode banner (when enabled):
  - Text: "Compliance mode is ON. Some providers are disabled by policy."

## Flows
- Connect:
  - Button opens URL from POST `/integrations/{provider}/connect` in a new tab.
  - After OAuth, callback in Vivified redirects back to Providers panel.
  - Panel auto‑refreshes status (poll or manual refresh)
- Revoke:
  - Confirmation dialog → POST `/integrations/{provider}/revoke` → refresh

## States
- Connected: show `account_name` if available
- Not connected: show "Not connected"
- Disabled (HIPAA): disable buttons and show tooltip/message; server returns `integration.not_allowed` if called

## API Client Additions
- Methods for:
  - `listIntegrations()` → GET `/integrations`
  - `connectIntegration(provider)` → POST `/integrations/{provider}/connect`
  - `statusIntegration(provider)` → GET `/integrations/{provider}/status`
  - `revokeIntegration(provider)` → POST `/integrations/{provider}/revoke`

## Accessibility
- Buttons labeled; status represented by icon+text; tooltips for disabled actions

