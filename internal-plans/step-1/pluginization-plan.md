Pluginization Plan — HubSpot/Gmail/Discord

Scope
- Add Integration plugin contract and ExternalPluginClient to bridge Core → Node sidecar.
- Add plugin shims for hubspot/gmail/discord with manifests and impls delegating to sidecar.
- Expose plugin-backed routes under /plugins/integration/{key}/… with trait+HIPAA gates and audits.
- Keep legacy /integrations/* for compatibility (Deprecation header) until UI migrates fully.

Contract and Adapter
- core/plugins/contracts/integration.py: Pydantic models (ConnectURL, IntegrationStatus, Result), IntegrationManifest, and IntegrationPluginBase interface.
- core/plugins/external_host.py: ExternalPluginClient(host, provider) with internal auth headers, correlation ID, and error mapping to:
  - integration.unavailable, integration.oauth_failed, integration.revoke_failed, integration.bad_request.

Plugins (shims)
- plugins/integration-hubspot/manifest.json + impl.py
- plugins/integration-gmail/manifest.json + impl.py
- plugins/integration-discord/manifest.json + impl.py
  - Read INTEGRATIONS_BASE_URL; call ExternalPluginClient for oauth_url/status/revoke flows.

Registry and API
- core/plugins/manager.py: IntegrationPluginRegistry discovers manifests and loads impls.
- core/api/integration_plugins.py:
  - GET /plugins/integration/providers — list plugin providers with allowed flag (HIPAA gate).
  - POST /plugins/integration/{key}/connect — state generation + audit + redirect URL.
  - POST /plugins/integration/{key}/callback — state verify + audit + exchange code.
  - GET /plugins/integration/{key}/status — trait/HIPAA gates + audit + status.
  - POST /plugins/integration/{key}/revoke — trait/HIPAA gates + audit + revoke.
- core/main.py: include integration_plugins_router and extend GET /plugins to support ?type=integration.

Policy/HIPAA
- Traits: integration_manager already exists (core/policy/traits.py).
- HIPAA enforcement:
  - INTEGRATIONS_HIPAA_MODE=true → allow only keys in INTEGRATIONS_HIPAA_ALLOWED and manifest.hipaaEligible.
  - For this step, all three providers have hipaaEligible=false → blocked in HIPAA mode.

UI Migration
- core/admin_ui/src/api/client.ts routes adjusted to prefer plugin paths first, fallback to /integrations/*.
- Providers.tsx behavior unchanged (connect/revoke/status UI stays the same).

Compatibility
- core/api/integrations.py: legacy endpoints return Deprecation header; unchanged behavior otherwise.

Tests
- tests/test_integration_plugins.py: provider listing and HIPAA mode blocking behavior.

