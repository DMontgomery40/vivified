# Admin Console — Providers Panel

Manage external integrations in Settings → Providers. The panel is trait‑gated by `admin` OR `integration_manager`.

- Lists known providers and connection status per user
- Actions: Connect (opens the provider’s URL in a new tab) and Revoke
- Compliance banner when HIPAA mode is ON and providers are disabled by policy

## Flow

1) Click Connect → a new tab opens to the provider’s auth URL (short‑lived `state` embedded)
2) After granting access, the provider redirects to the Core callback
3) Core validates `state`, finalizes with the sidecar, and redirects back to the Providers panel
4) Panel refreshes status automatically

## Errors & Compliance

- If the sidecar is unavailable, a banner shows “Integration service unavailable”
- When `INTEGRATIONS_HIPAA_MODE=true` and the provider is not allowed, actions are disabled and API returns `integration.not_allowed`

## Requirements

- Core env vars:
  - `INTEGRATIONS_BASE_URL`, `INTEGRATIONS_INTERNAL_TOKEN`, `INTEGRATIONS_HIPAA_MODE`, `INTEGRATIONS_HIPAA_ALLOWED`
- Sidecar env vars:
  - `INTERNAL_TOKEN`, `MONGO_URI`, provider credentials as needed

## Accessibility

- Action buttons are labeled; status is visible via text+icons
- Disabled actions provide tooltips with the reason (policy)
