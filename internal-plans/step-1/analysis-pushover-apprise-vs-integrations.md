Pushover/Apprise vs Discord/Gmail — Wiring Analysis (Vivified Phase 8)

1) Pushover/Apprise wiring (correct model)

- Plugin manifests and implementations
  - plugins/pushover_notifier/main.py:1 — FastAPI plugin container with MANIFEST and endpoints
  - plugins/apprise_notifier/main.py:1 — FastAPI plugin container with MANIFEST and endpoints

- Registration and policy
  - Each container registers with Core via POST /plugins/register (core/main.py:13,492)
  - core/plugin_manager/registry.py:34 — stores manifest, issues JWT plugin token
  - Allowed egress domains declared in manifest (e.g., api.pushover.net) are synced to Gateway (core/main.py:17–33)

- Egress and Gateway/Proxy lane
  - Pushover sends via Core Gateway proxy: plugins/pushover_notifier/main.py:145–171
    - POST /gateway/proxy with plugin_id, url=https://api.pushover.net/… (allowed by Gateway allowlist)
    - Fallback to dry-run when blocked by policy
  - Audit-safe: no PHI/PII in logs; notification payloads limited to metadata

- Canonical lane (eventing)
  - Both plugins publish NotificationSent events back to Core: 
    - plugins/pushover_notifier/main.py:179–205
    - plugins/apprise_notifier/main.py:154–183

- Traits/policy mapping
  - contracts include CommunicationPlugin and traits like handles_notifications, external_service
  - Plugin traits are validated by core/plugin_manager/validator.py

- Summary flow
  - Plugin container → Core /plugins/register → Core Gateway proxy (egress allowlist) → External API
  - All cross-service calls mediated by Core lanes; audit emitted; allowlist enforced.

2) Discord/Gmail wiring (current state)

- Admin UI calls bespoke endpoints
  - UI component: core/admin_ui/src/components/Providers.tsx:26–44,79–98 
    - Uses AdminAPIClient.getIntegrationProviders(), connectIntegration(), statusIntegration(), revokeIntegration()
  - Client hits Core bespoke endpoints under /integrations (core/admin_ui/src/api/client.ts:15–34)

- Core FastAPI layer (bypasses plugin registry)
  - core/api/integrations.py:
    - Providers list: GET /integrations/providers (lines 41–61)
    - List/status/connect/revoke per provider (lines ~102–408)
    - Internal token headers and correlation: _client_headers() (169–180)
    - OAuth state store (in-memory): 208–219, 220–236
    - Audit via core/audit/service:get_audit_service (142–165)
  - These endpoints forward to a Node sidecar instead of a registered plugin

- Node sidecar (Frigg/Adapters)
  - integrations/src/server.js
    - Internal auth middleware: X-Internal-Auth/X-Internal-Token (23–38)
    - Mongo persistence, credential models (64–78)
    - Health check (182–197)
    - OAuth URL, callback, status, revoke for hubspot/gmail/discord (202–279, 280–355)
    - Egress enforcement for HubSpot when ENFORCE_EGRESS=true (96–110, 112–128)
  - Env/config glue: integrations/env.example, Dockerfile

- Gaps vs Vivified model
  - Bypasses plugin registry/contract — no manifest for Discord/Gmail/HubSpot inside Core plugin system
  - Bypasses Gateway allowlist path for these providers (egress enforced in sidecar only, not Core Gateway)
  - Admin UI relies on bespoke /integrations/* instead of plugin contract routes

3) Conclusion

- Pushover/Apprise follow Vivified architecture: plugin manifests, Core mediation, Gateway allowlist, canonical events.
- Discord/Gmail (plus HubSpot) should be “pluginized”: exposed via Integration plugin contract and plugin registry; UI should use /plugins/integration/{key}/… routes.
- Keep Node sidecar as the implementation detail; Core provides the policy/trait/audit boundaries and entrypoints.

