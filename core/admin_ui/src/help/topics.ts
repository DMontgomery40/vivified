export type HelpVariant = {
  // Show this variant when ANY of these traits are present
  whenAnyTrait?: string[];
  // Or when ALL of these are present
  whenAllTraits?: string[];
  eli5?: string;
  dev?: string[];
};

export type HelpTopic = {
  id: string;
  title: string;
  eli5: string;
  dev: string[];
  docSlug?: string; // appended to docsBase when present
  variants?: HelpVariant[];
};

export const helpTopics: Record<string, HelpTopic> = {
  diagnostics: {
    id: 'diagnostics',
    title: 'Diagnostics',
    eli5:
      'What this does: Diagnostics runs a guided set of checks against core services (API, storage, providers, security) and summarizes health with clear guidance.\n\nHow to use: Click “Run Diagnostics.” If a section is red, expand it to see the failing key and actionable steps. Use available buttons (e.g., Restart API) when offered.\n\nHow it works: The UI calls /admin/health-status and related APIs, then annotates results with context (e.g., why Ghostscript matters or how callback URLs are formed). No PHI is shown; only safe metadata.',
    dev: [
      'API: GET /admin/health-status → high-level JSON health summary.',
      'Provider checks: match configured outbound/inbound backends; surface trait hints.',
      'If storage fails: verify encryption key and list permissions.',
      'If inbound verify fails: ensure PUBLIC_API_URL and callbacks are set; check rate limits.',
      'Use Scripts & Tests for deeper smoke/QA runs; changes are audited.',
    ],
    docSlug: 'diagnostics',
    variants: [
      {
        whenAnyTrait: ['role.admin', 'ui.monitoring'],
        dev: [
          'Drill-down: correlate failing health keys to settings under /admin/settings.',
          'Restart API safely from Diagnostics; check audit trail for restart entries.',
          'Export env from Setup Wizard; keep secrets in env, not logs.',
        ],
      },
      {
        whenAnyTrait: ['viewer', 'intern'],
        eli5:
          'If something is red, click it to see a plain-language fix. If you can’t change settings, ask an admin to help with the listed steps.',
      },
    ],
  },
  plugins: {
    id: 'plugins',
    title: 'Plugins',
    eli5: 'What this does: Shows installed plugins and registry entries, and lets you configure/enable them.\n\nHow to use: Browse providers, configure credentials, and use Manifest Editor + Register to onboard custom plugins entirely from the UI.\n\nHow it works: Registered manifests live in config/registry; plugin tokens are issued per plugin and audited. Operator/Gateway policies restrict cross-calls and outbound egress.',
    dev: [
      'List: GET /plugins (Admin).',
      'Register: POST /plugins/register with a validated manifest.',
      'Config: GET/PUT /plugins/{id}/config; persist via ConfigService.',
      'Security: audit plugin lifecycle; least privilege enforced by policies.',
    ],
    docSlug: 'plugins',
  },
  'manifest-editor': {
    id: 'manifest-editor',
    title: 'Manifest Editor',
    eli5:
      'What this does: Validates a plugin manifest for correctness and safety, then helps you apply the required policies (Gateway allowlist + Operator rules) before registering.\n\nHow to use: Paste the manifest and Validate. Fix any errors. Click “Apply Suggested Allowlist” to add outbound hosts/paths, and “Generate Operator Allowlist” for specific operations. Finally, click Register Plugin.\n\nHow it works: The server validates JSON against its schema. Suggestions are derived from endpoint URLs and allowed_domains. Policies persist to ConfigService and are enforced by Gateway/Operator lanes.',
    dev: [
      'Validate: POST /admin/plugins/validate-manifest → { ok, errors[], suggestions{ operations[], allowlist, invalid_domains[] } }.',
      'Allowlist: PUT /admin/gateway/allowlist { plugin_id, allowlist } (merge as needed).',
      'Operator: PUT /admin/operator/allowlist { caller, target, operations[] }.',
      'Register: POST /plugins/register; tokens issued per plugin; audited.',
      'Compliance: avoid IP literals; tag data_classification; everything audited.',
    ],
    docSlug: 'plugins/manifest-editor',
    variants: [
      {
        whenAnyTrait: ['plugin_manager', 'role.admin'],
        dev: [
          'Splunk HEC: Authorization header is "Splunk <token>" — docs: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector',
          'QuickBooks scopes: https://developer.intuit.com/app/developer/qbo/docs/develop/authentication-and-authorization/scopes',
          'Salesforce OAuth 2.0 flows: https://help.salesforce.com/s/articleView?id=sf.remoteaccess_oauth_flows.htm&type=5',
          'eBay OAuth scopes: https://developer.ebay.com/api-docs/static/oauth-scopes.html',
          'JSON Schema (2020-12): https://json-schema.org/ — validation keywords and formats.',
        ],
      },
      {
        whenAnyTrait: ['viewer', 'intern'],
        eli5:
          'You can paste a manifest and click Validate. If you’re not sure about errors, use the suggestions to fix hosts and operations, then ask a maintainer to Register the plugin.',
      },
    ],
  },
  'plugin-dev': {
    id: 'plugin-dev',
    title: 'Plugin Development',
    eli5: 'What this does: Guides you from manifest → schema/transform alignment → policies → testing, all in UI.\n\nHow to use: Validate manifests; apply allowlist/operator rules; scaffold code; preview canonical transforms; run smoke tests.',
    dev: [
      'Validate: /admin/plugins/validate-manifest; Apply allowlist/operator rules.',
      'Transforms: /admin/canonical/transforms; preview Normalize endpoints.',
      'Scaffold: /admin/plugins/scaffold; Register: /plugins/register.',
      'Audit & compliance: tag data traits; avoid PHI in logs; gated by traits.',
    ],
    docSlug: 'runbooks/phase-7-plugin-development',
  },
  marketplace: {
    id: 'marketplace',
    title: 'Plugin Marketplace',
    eli5: 'Browse available plugins from a curated registry (when enabled).',
    dev: [
      'Enable marketplace via ADMIN_MARKETPLACE_ENABLED=true.',
      'Fetch catalog via GET /admin/marketplace/plugins.',
    ],
    docSlug: 'admin/marketplace',
  },
  gateway: {
    id: 'gateway',
    title: 'Gateway & Proxy',
    eli5: 'What this does: Makes outbound HTTP requests on behalf of plugins through a strict allowlist and rate policy.\n\nHow to use: Use the HTTP Proxy Tester after adding the host/path to the allowlist. Adjust global/per-plugin rate limits as needed.',
    dev: [
      'Proxy: POST /gateway/proxy { plugin_id, method, url, headers?, body?, timeout? }.',
      'Allowlist: gateway.allowlist.<plugin_id> → { allowed_methods[], allowed_paths[] }.',
      'Rate policy: gateway.rate.* and gateway.rate.<plugin>.* (rpm, burst).',
      'Block IP literals/localhost; audit on allow/deny.',
    ],
    docSlug: 'gateway',
    variants: [
      {
        whenAnyTrait: ['role.admin', 'plugin_manager'],
        dev: [
          'Splunk HEC doc: https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector',
          'HTTP 429 rate limiting semantics: respect Retry-After if present.',
          'Header hygiene: avoid PHI in headers/URLs; prefer IDs/opaque tokens.',
        ],
      },
    ],
  },
  'operator-policy': {
    id: 'operator-policy',
    title: 'Operator Policy',
    eli5:
      'What this does: Explicitly allows which operations one plugin may invoke on another via the Operator Lane. Think of it as a per-operation firewall for internal RPC.\n\nHow to use: Enter Caller and Target plugin IDs, then paste allowed operations (e.g., invoice.create). Save. You can auto-generate operations from a manifest in the Manifest Editor.',
    dev: [
      'Keys: operator.allow.<caller->target> → ["invoice.create", "customer.list", ...].',
      'Operations map to manifest endpoints by convention.',
      'API: GET/PUT /admin/operator/allowlist; audit every change.',
      'Least-privilege; deny-by-default; block on policy evaluation errors.',
    ],
    docSlug: 'policy/operator-allowlist',
    variants: [
      {
        whenAnyTrait: ['role.admin', 'plugin_manager', 'ui.policy'],
        dev: [
          'Derive operations from manifest endpoints; support categories carefully (e.g., invoice.*).',
          'Audit review: periodically diff operator rules; limit blast radius.',
        ],
      },
      {
        whenAnyTrait: ['viewer', 'intern'],
        eli5: 'Operator rules are like a checklist of what’s allowed between plugins. If you’re unsure, don’t add broad rules.',
      },
    ],
  },
  messaging: {
    id: 'messaging',
    title: 'Messaging / Event Bus',
    eli5: 'Publish and subscribe to events so parts of the system can react asynchronously.',
    dev: [
      'Publish: POST /messaging/events { event_type, payload, source_plugin, data_traits?, metadata? }.',
      'Stats: GET /messaging/stats.',
      'Prefer canonical payloads; tag PHI via data_traits; audited.',
    ],
    docSlug: 'messaging',
  },
  canonical: {
    id: 'canonical',
    title: 'Canonical Model',
    eli5: 'What this does: Provides common shapes (User, Message, Event, and domain entities) so integrations interoperate reliably.\n\nHow it works: Transform mappings align provider fields to canonical (and back). Canonical Schemas define strict JSON shapes; validation ensures payloads match the active version.',
    dev: [
      'Normalize: /canonical/normalize/* with source/target plugin IDs.',
      'Transforms: dot-path → dot-path; audit transformation history.',
      'Schemas: /schemas (upsert/activate/validate); pin majors in prod.',
    ],
    docSlug: 'canonical',
    variants: [
      {
        whenAnyTrait: ['role.admin', 'ui.canonical'],
        dev: [
          'Model your domain entities and keep transforms schema-aligned; validate in CI.',
          'Prefer additive changes on minors; use majors for breaking changes.',
        ],
      },
    ],
  },
  'canonical-transforms': {
    id: 'canonical-transforms',
    title: 'Canonical Transforms',
    eli5:
      'What this does: Converts provider-specific payloads to a shared canonical shape (and back), enabling cross-plugin compatibility.\n\nHow to use: Select source/target, edit mappings (dot-path → dot-path), run Preview on a sample payload. Keep mappings in sync with active canonical schema.',
    dev: [
      'Key: canonical.transforms.<source->target> → mapping.',
      'Supported keys: user_to_canonical, message_to_canonical, event_to_canonical, and *_from_canonical.',
      'Normalize via /canonical/normalize/*; audit logs record transformations.',
      'Pitfalls: missing paths → null; align with schema versions.',
    ],
    docSlug: 'canonical/transforms',
  },
  'canonical-schemas': {
    id: 'canonical-schemas',
    title: 'Canonical Schemas',
    eli5:
      'What this does: Defines strict JSON shapes for canonical entities (e.g., LogEvent, Person) and lets you validate payloads before rollout.\n\nHow to use: Upsert a schema version, Activate its major, then Validate sample payloads. Use semantic versions and pin majors for consistency.',
    dev: [
      'Upsert: POST /schemas { name, major, minor, patch, schema_data }.',
      'Activate: POST /schemas/activate { name, major, minor, patch }.',
      'Validate: POST /schemas/{name}/validate { payload, major? or version? }.',
      'Built-ins: core/canonical/schemas/<ns>/<entity>/<ver>.json; loaded at startup.',
    ],
    docSlug: 'canonical/schemas',
    variants: [
      {
        whenAnyTrait: ['role.admin', 'ui.canonical'],
        dev: [
          'Draft 2020-12 validation keywords: https://json-schema.org/draft/2020-12/json-schema-validation.html',
          'Use enums, formats, and required to tighten contracts; avoid over-broad anyOf.',
        ],
      },
    ],
  },
  policy: {
    id: 'policy',
    title: 'Policy & Traits',
    eli5: 'Traits enable or hide features. Policies control what actions are allowed.',
    dev: [
      'UI traits: /admin/user/traits drive gating; least privilege by default.',
      'Decisions: evaluate with policy engine; block on error (fail-safe).',
      'Operator rules: see operator-policy; Outbound rules: see gateway-allowlist.',
      'Audit all PHI/PII and configuration access decisions.',
    ],
    docSlug: 'policy',
  },
  logs: {
    id: 'logs',
    title: 'Logs',
    eli5: 'Logs show what the system is doing. Use filters to find events.',
    dev: [
      'Query application logs; avoid PHI in messages.',
      'Enable audit logging in security settings for sensitive events.',
      'Support ring buffer vs file tail; control size and wrap/follow.',
      '12‑Factor logging: https://12factor.net/logs',
    ],
    docSlug: 'logs',
    variants: [
      {
        whenAnyTrait: ['role.admin'],
        dev: [
          'Centralize logs; ship to SIEM when required; redact PHI/PII at source.',
          'Set log level via env; avoid DEBUG in production; monitor error rate.',
        ],
      },
    ],
  },
  audit: {
    id: 'audit',
    title: 'Audit Trail',
    eli5: 'Shows security-relevant actions for compliance and forensics.',
    dev: [
      'List via GET /admin/audit with pagination.',
      'Every sensitive operation should produce an audit entry.',
      'Retention and export should meet compliance requirements.',
    ],
    docSlug: 'audit',
    variants: [
      {
        whenAnyTrait: ['role.admin', 'security_admin'],
        dev: [
          'Retention policy: 7 years (HIPAA); export securely; verify integrity.',
          'Correlate audit entries with config changes and operator calls.',
        ],
      },
    ],
  },
  configuration: {
    id: 'configuration',
    title: 'Configuration Manager',
    eli5: 'View and change settings, with overrides per scope when allowed.',
    dev: [
      'Get effective config via GET /admin/config (current) or v4 endpoints when available.',
      'Track edits with reasons; mask secrets by default.',
      'Flush caches after changes when needed.',
    ],
    docSlug: 'config',
    variants: [
      {
        whenAnyTrait: ['role.admin'],
        dev: [
          'Avoid storing secrets in logs; use env or secure backend; audit edits.',
          'Flush cache after writing settings that affect routing/policies.',
        ],
      },
    ],
  },
  users: {
    id: 'users',
    title: 'User Management',
    eli5: 'Create users and manage their roles. Roles grant traits that unlock features.',
    dev: [
      'Create user via POST /admin/users; set roles via PUT /admin/users/{id}/roles.',
      'Require MFA and short-lived tokens for admins.',
      'Never display or log credentials or PHI.',
    ],
    docSlug: 'users',
    variants: [
      {
        whenAnyTrait: ['role.admin'],
        dev: [
          'Require MFA for admin users; short‑lived tokens; rotate API keys regularly.',
          'Grant least‑privilege traits; review access quarterly.',
        ],
      },
    ],
  },
  settings: {
    id: 'settings',
    title: 'Settings',
    eli5:
      'Settings is where you choose your providers, turn security features on, and set storage options. Use the Setup wizard if you’re unsure.',
    dev: [
      'Backends: backend.type (legacy), hybrid.outbound_backend/inbound_backend.',
      'Security: security.require_api_key, security.enforce_https, audit_log_enabled.',
      'Inbound: enable flag, callback URLs (PUBLIC_API_URL), retention/rate limits.',
      'Export/persist: /admin/settings/export and /admin/settings/persist.',
    ],
    docSlug: 'settings',
    variants: [
      {
        whenAnyTrait: ['role.admin'],
        dev: [
          'Change management: export → commit → apply; avoid editing live secrets from logs.',
          'Rolling restarts: apply changes during low-traffic windows; audit every config write.',
        ],
      },
    ],
  },
  'api-keys': {
    id: 'api-keys',
    title: 'API Keys',
    eli5:
      'API keys let tools talk to the Admin API. Treat them like passwords. You can create a key here and copy it once.',
    dev: [
      'Create via POST /admin/api-keys; token returned once.',
      'Rotate with POST /admin/api-keys/{id}/rotate.',
      'Revoke with DELETE /admin/api-keys/{id}.',
    ],
    docSlug: 'security/api-keys',
    variants: [
      {
        whenAnyTrait: ['role.admin', 'security_admin'],
        dev: [
          'Scope keys narrowly; rotate regularly; disable unused keys; audit usage.',
          'Never paste tokens in chat or tickets; use secure secret storage.',
        ],
      },
    ],
  },
  tunnel: {
    id: 'tunnel',
    title: 'Tunnels',
    eli5:
      'A tunnel exposes the local service securely so webhooks and external tools can reach it. If it won’t connect, check your internet and try again.',
    dev: [
      'Ensure PUBLIC_API_URL is set correctly for callbacks.',
      'Check firewall rules; allow egress for the tunnel process.',
      'WireGuard: https://www.wireguard.com/ — configuration and keys.',
    ],
    docSlug: 'tunnels',
  },
  providers: {
    id: 'providers',
    title: 'Providers',
    eli5:
      'Providers are the backends that actually do the work. Pick one for outbound and optionally a different one for inbound.',
    dev: [
      'Enable via POST /admin/providers/enable with direction.',
      'Health info is summarized in Diagnostics and Settings.',
    ],
    docSlug: 'providers',
    variants: [
      {
        whenAnyTrait: ['role.admin'],
        dev: [
          'Keep provider credentials rotated; validate scopes/permissions; prefer OAuth2 over Basic when available.',
        ],
      },
    ],
  },
  storage: {
    id: 'storage',
    title: 'Storage',
    eli5:
      'Storage is where files live. For sensitive data, use encrypted storage and follow retention rules.',
    dev: [
      'Use Storage Browser (read-only) to inspect objects.',
      'Configure S3/KMS or local storage under Settings.',
      'AWS S3 KMS: https://docs.aws.amazon.com/AmazonS3/latest/userguide/UsingKMSEncryption.html',
    ],
    docSlug: 'storage',
    variants: [
      {
        whenAnyTrait: ['role.admin', 'security_admin'],
        dev: [
          'Enable at‑rest encryption; use KMS; enforce retention; verify access logs.',
        ],
      },
    ],
  },
  notifications: {
    id: 'notifications',
    title: 'Notifications',
    eli5:
      'Send alerts across channels (email, Pushover, Slack, etc.). Use Send for one‑offs or Rules to react to events automatically. Audience can target all users with specific traits (e.g., “sales”) without maintaining lists.',
    dev: [
      'Ad‑hoc: POST /admin/notifications/send { title?, body, targets?, metadata.audience? }',
      'Event‑driven: define rules; on matching events, service emits NotificationRequest for plugins to deliver.',
      'Audience: { mode: "traits", traits: ["sales"], scope: "tenant" } — plugin resolves recipients with trait.',
      'Inbox shows NotificationSent events; dry_run makes previewing easy during development.',
      'Pushover API: https://pushover.net/api — token/user and message formats.',
      'Slack Webhooks: https://api.slack.com/messaging/webhooks — JSON payload and auth.',
    ],
    docSlug: 'notifications',
    variants: [
      {
        whenAnyTrait: ['role.admin'],
        dev: [
          'Use dry_run in development; template messages; avoid PHI in titles/bodies.',
        ],
      },
    ],
  },
  'notifications-rules': {
    id: 'notifications-rules',
    title: 'Notifications Rules',
    eli5:
      'Rules map events like “FaxReceived” to outbound notifications. Choose a channel and audience; the platform will emit notifications when events occur.',
    dev: [
      'Rule shape: { id?, enabled, event_type, channel?, template:{title,body}, audience:{ mode:"traits", traits:[...], scope:"tenant"|"org" } }',
      'Manage via /admin/notifications/rules (GET/PUT/DELETE).',
      'Plugins fan‑out to recipients based on audience; keep PHI out of titles/bodies where possible.',
      'Security: audit entries on request/ingest; use dry_run until channels are validated.',
    ],
    docSlug: 'notifications/rules',
    variants: [
      {
        whenAnyTrait: ['role.admin'],
        dev: [
          'Start disabled; test with dev recipients; restrict blast radius via audience traits.',
        ],
      },
    ],
  },
  automations: {
    id: 'automations',
    title: 'Automations',
    eli5:
      'Automations (rules & flows) let you react to events with actions like updating user roles. Build flows visually; no CLI scripts needed.',
    dev: [
      'Rule: { event_type, action: { type: "set_user_roles", roles: ["viewer"] }, enabled }',
      'Manage via /admin/automation/rules (GET/PUT/DELETE).',
      'Events: CRM or HR plugins can emit EmployeeTerminated; use it to restrict roles.',
      'All actions audited; changes go through IdentityService.',
    ],
    docSlug: 'automations',
  },
  'gateway-allowlist': {
    id: 'gateway-allowlist',
    title: 'Gateway Allowlist',
    eli5:
      'What this does: Restricts outbound HTTP egress by domain, method, and path per plugin.\n\nHow to use: Choose a plugin, add the domain (no IPs), set allowed methods (e.g., GET,POST), and add specific paths (/api/v1/*). Save to persist policy.\n\nHow it works: Requests from that plugin are allowed only when host/method match and path matches a configured prefix. Localhost and IP literals are blocked by design.',
    dev: [
      'Key: gateway.allowlist.<plugin_id> → { domain → { allowed_methods[], allowed_paths[] } }.',
      'IP literals and localhost never pass even if misconfigured.',
      'Seed from Manifest Editor suggestions; audited on allow/deny.',
    ],
    docSlug: 'gateway/allowlist',
  },
  jobs: {
    id: 'jobs',
    title: 'Jobs',
    eli5: 'Jobs show work items in progress and their status.',
    dev: [
      'List via GET /admin/fax-jobs; refresh with POST /admin/fax-jobs/{id}/refresh.',
      'Download job artifacts via GET /admin/fax-jobs/{id}/pdf (if available).',
    ],
    docSlug: 'jobs',
  },
  inbound: {
    id: 'inbound',
    title: 'Inbound',
    eli5: 'What this does: Configures inbound webhooks to receive events (e.g., status updates) from providers.\n\nHow to use: In Settings choose backend(s), ensure PUBLIC_API_URL is set, and verify an inbound event using the tester.\n\nHow it works: Core exposes stable callback paths; inbound handlers authenticate/sanitize payloads and forward normalized events.',
    dev: [
      'Simulate via POST /admin/inbound/simulate for quick testing.',
      'See configured callbacks at GET /admin/inbound/callbacks.',
    ],
    docSlug: 'inbound',
  },
  'qa-tests': {
    id: 'qa-tests',
    title: 'QA Test Suites',
    eli5:
      'Run quick, safe tests to verify the system: smoke, policy, security, PHI encryption, and more. Results appear below with clear pass/fail lines.',
    dev: [
      'Smoke: basic flows (list users, audit, gateway policy).',
      'Policy: engine decisions for PHI/PII access.',
      'Security: encryption and TLS status.',
      'Compliance: store PHI and verify encryption + minimal listings.',
      'Integration: user onboarding with audit verification.',
      'OWASP: injection inputs must return 401/403, never 500.',
      'Performance: latency percentiles for a representative call.',
      'Chaos: disable/enable a temp plugin; core remains healthy.',
    ],
    docSlug: 'qa/tests',
    variants: [
      {
        whenAnyTrait: ['role.admin'],
        dev: [
          'Automate in CI; compare before/after results on PRs; fail on regressions.',
        ],
      },
    ],
  },
  'qa-env': {
    id: 'qa-env',
    title: 'QA Environment (Docker)',
    eli5:
      'Starts a test environment with containers (if Docker is installed). Use this for deeper end‑to‑end tests.',
    dev: [
      'Status: GET /admin/tests/env/status (detects Docker, lists running containers).',
      'Start: POST /admin/tests/env/start { compose_file?, project? }.',
      'Stop: POST /admin/tests/env/stop { compose_file?, project? }.',
      'Requires Docker/Podman. All actions are audited. Use on non‑production hosts.',
    ],
    docSlug: 'qa/environment',
  },
  terminal: {
    id: 'terminal',
    title: 'Admin Terminal',
    eli5:
      'What this does: Gives you direct shell access to the running container. Useful for quick inspections and diagnostics without leaving the UI.\n\nHow to use: Click Reconnect if disconnected; use Clear/Copy/Fullscreen for workflow. Use cautiously — actions here are powerful and immediate.',
    dev: [
      'Transport: secured WebSocket into container shell; audit connection lifecycle.',
      'Best practice: prefer Scripts & Tests for repeatable flows.',
      'Avoid storing secrets in shell history; do not paste PHI/PII.',
    ],
    docSlug: 'terminal',
  },
  setup: {
    id: 'setup',
    title: 'Setup Wizard',
    eli5:
      'What this does: Walks you through choosing providers, adding credentials, enabling security, and exporting a ready-to-use configuration.\n\nHow to use: Follow the steps, validate settings, then “Apply & Export.” Optional inbound verification checks your webhook path receives events.',
    dev: [
      'Providers: pick outbound/inbound; traits guide available options.',
      'Security: require API key, enforce HTTPS, enable audit logging.',
      'Export/persist: /admin/settings/export and /admin/settings/persist.',
      'Inbound verify: poll logs for inbound_received; requires PUBLIC_API_URL.',
    ],
    docSlug: 'setup',
  },
  mfa: {
    id: 'mfa',
    title: 'MFA & Passkeys',
    eli5:
      'What this does: Adds a second factor (TOTP) or passkey (WebAuthn) to protect admin accounts.\n\nHow to use: Click Setup TOTP, scan the QR in your authenticator app, then enter the code and Enable. Store backup codes securely.',
    dev: [
      'TOTP endpoints exposed on Admin API; ensure short-lived tokens for admins.',
      'Passkeys (WebAuthn) planned for the UI; backend stubs exist.',
      'Audit enable/disable; enforce MFA for admin roles in policy.',
    ],
    docSlug: 'security/mfa',
  },
  mcp: {
    id: 'mcp',
    title: 'Model Context Protocol (MCP)',
    eli5:
      'What this does: Connects AI assistants to platform tools via MCP.\n\nHow to use: Enable MCP, choose tools, and verify connectivity in Scripts & Tests. Gate usage by trait and audit interactions.',
    dev: [
      'Expose tools safely; redact sensitive content; enforce rate limits.',
      'Use signed requests and structured results; audit every call.',
    ],
    docSlug: 'ai/mcp',
  },
  register: {
    id: 'register',
    title: 'Register Plugin',
    eli5:
      'What this does: Registers a plugin manifest into Core so it can receive tokens and be called.\n\nHow to use: Validate in Manifest Editor, then Register to persist and activate it.',
    dev: [
      'API: POST /plugins/register { manifest }; registry stores manifest and token.',
      'Security: audit registration; sync allowlist from allowed_domains when present.',
    ],
    docSlug: 'plugins/register',
  },
};

export function resolveDocHref(docsBase: string | undefined, topicId: string): string | undefined {
  if (!docsBase) return undefined;
  const t = helpTopics[topicId];
  const slug = t?.docSlug || topicId;
  return `${docsBase.replace(/\/$/, '')}/${slug}`;
}
