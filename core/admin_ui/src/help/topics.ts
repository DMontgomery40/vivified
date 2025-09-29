export type HelpTopic = {
  id: string;
  title: string;
  eli5: string;
  dev: string[];
  docSlug?: string; // appended to docsBase when present
};

export const helpTopics: Record<string, HelpTopic> = {
  diagnostics: {
    id: 'diagnostics',
    title: 'Diagnostics',
    eli5:
      'Diagnostics gives you a quick status check of the system and providers. If something is red, click into it to see what it means and what to try next.',
    dev: [
      'Check /admin/health-status for backend health JSON.',
      'Verify provider selection under Settings → Backend Configuration.',
      'Use the Scripts & Tests tab for end-to-end smoke tests.',
    ],
    docSlug: 'diagnostics',
  },
  plugins: {
    id: 'plugins',
    title: 'Plugins',
    eli5: 'Plugins extend the platform with new capabilities. You can install and configure them here when enabled.',
    dev: [
      'List installed plugins via GET /plugins.',
      'Load curated registry via marketplace endpoint when enabled.',
      'Update plugin config via /plugins/{id}/config (persist to config).',
    ],
    docSlug: 'plugins',
  },
  'manifest-editor': {
    id: 'manifest-editor',
    title: 'Manifest Editor',
    eli5:
      'Paste your plugin manifest, validate it against the required schema, and apply suggested safety policies (allowlist and operator rules) with one click.',
    dev: [
      'Validate: POST /admin/plugins/validate-manifest returns errors and suggestions.',
      'Apply Gateway Allowlist: PUT /admin/gateway/allowlist with suggested domains/paths.',
      'Generate Operator Allowlist: PUT /admin/operator/allowlist using endpoint keys as operations.',
      'Register Plugin: POST /plugins/register to make it available to Core.',
      'Avoid IP literals; use hostnames. All actions are audited.',
    ],
    docSlug: 'plugins/manifest-editor',
  },
  'plugin-dev': {
    id: 'plugin-dev',
    title: 'Plugin Development',
    eli5: 'Build and test plugins safely with traits, policies, and the canonical model.',
    dev: [
      'Use the Plugin Dev Guide to scaffold and validate plugins.',
      'Tag PHI/PII data and enforce traits in policies.',
      'Smoke test locally and verify CI passes before rollout.',
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
    eli5: 'The gateway safely makes outbound HTTP calls on behalf of the system through an allowlist.',
    dev: [
      'Proxy endpoint: POST /gateway/proxy with method, url, headers, body.',
      'Enforce outbound domains + paths via gateway allowlist per plugin.',
      'Audit all proxy requests; avoid PHI in URLs/headers.',
    ],
    docSlug: 'gateway',
  },
  'operator-policy': {
    id: 'operator-policy',
    title: 'Operator Policy',
    eli5:
      'Controls which plugin is allowed to call which operations on another plugin. This prevents accidental or unsafe cross-calls.',
    dev: [
      'Rules live under config key pattern operator.allow.<caller->target>.',
      'Operations typically match manifest endpoint keys (e.g., invoice.create).',
      'Set via PUT /admin/operator/allowlist with { caller, target, operations[] }.',
      'Prefer least privilege. Review with security/audit regularly.',
    ],
    docSlug: 'policy/operator-allowlist',
  },
  messaging: {
    id: 'messaging',
    title: 'Messaging / Event Bus',
    eli5: 'Publish and subscribe to events so parts of the system can react asynchronously.',
    dev: [
      'Publish via POST /messaging/events { event_type, payload, source_plugin }.',
      'Stats via GET /messaging/stats.',
      'Avoid PHI in event payloads unless strictly required and tagged.',
    ],
    docSlug: 'messaging',
  },
  canonical: {
    id: 'canonical',
    title: 'Canonical Model',
    eli5: 'A common shape for data so different plugins can understand each other.',
    dev: [
      'Normalize user: POST /canonical/normalize/user with source/target plugins.',
      'Stats via GET /canonical/stats.',
      'Maintain canonical schemas; validate in CI.',
    ],
    docSlug: 'canonical',
  },
  'canonical-transforms': {
    id: 'canonical-transforms',
    title: 'Canonical Transforms',
    eli5:
      'Map provider-specific fields to the canonical model (and back) so different systems can talk the same language.',
    dev: [
      'Mappings reside under canonical.transforms.<source->target> in config.',
      'Keys: user_to_canonical, message_to_canonical, event_to_canonical, and *_from_canonical.',
      'Preview with Normalize endpoints; audit logs record transformations.',
      'Keep mappings aligned with active canonical schemas.',
    ],
    docSlug: 'canonical/transforms',
  },
  'canonical-schemas': {
    id: 'canonical-schemas',
    title: 'Canonical Schemas',
    eli5:
      'Schemas define the expected shape of canonical entities (like LogEvent or Person). Validate payloads before rollout.',
    dev: [
      'Manage versions: POST /schemas (upsert) and /schemas/activate.',
      'Validate payloads: POST /schemas/{name}/validate with major or version.',
      'Built-ins load at startup from core/canonical/schemas/* and auto-activate per major.',
      'Pin majors in production; use semver for compatibility.',
    ],
    docSlug: 'canonical/schemas',
  },
  policy: {
    id: 'policy',
    title: 'Policy & Traits',
    eli5: 'Traits enable or hide features. Policies control what actions are allowed.',
    dev: [
      'User traits returned by /admin/user/traits drive UI gating.',
      'Backends should check traits/policies server-side for access control.',
      'Log decisions to the audit trail.',
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
    ],
    docSlug: 'logs',
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
  },
  settings: {
    id: 'settings',
    title: 'Settings',
    eli5:
      'Settings is where you choose your providers, turn security features on, and set storage options. Use the Setup wizard if you’re unsure.',
    dev: [
      'Core keys: backend.type, hybrid.outbound_backend, hybrid.inbound_backend.',
      'Security: security.require_api_key, security.enforce_https.',
      'Inbound: inbound.enabled, retention and rate limits.',
    ],
    docSlug: 'settings',
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
  },
  tunnel: {
    id: 'tunnel',
    title: 'Tunnels',
    eli5:
      'A tunnel exposes the local service securely so webhooks and external tools can reach it. If it won’t connect, check your internet and try again.',
    dev: [
      'Ensure PUBLIC_API_URL is set correctly for callbacks.',
      'Check firewall rules; allow egress for the tunnel process.',
      'If using WireGuard, verify the config file and keys.',
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
  },
  storage: {
    id: 'storage',
    title: 'Storage',
    eli5:
      'Storage is where files live. For sensitive data, use encrypted storage and follow retention rules.',
    dev: [
      'Use Storage Browser (read-only) to inspect objects.',
      'Configure S3/KMS or local storage under Settings.',
    ],
    docSlug: 'storage',
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
    ],
    docSlug: 'notifications',
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
  },
  'gateway-allowlist': {
    id: 'gateway-allowlist',
    title: 'Gateway Allowlist',
    eli5:
      'The allowlist controls which domains the system is allowed to call, and which methods and paths are permitted. It’s a safety net.',
    dev: [
      'Config key pattern: gateway.allowlist.<plugin_id>.',
      'Each domain has allowed_methods and allowed_paths arrays.',
      'Changes persist via /admin/gateway/allowlist (PUT).',
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
    eli5: 'Inbound handles incoming events or webhooks from providers.',
    dev: [
      'Simulate via POST /admin/inbound/simulate for quick testing.',
      'See configured callbacks at GET /admin/inbound/callbacks.',
    ],
    docSlug: 'inbound',
  },
};

export function resolveDocHref(docsBase: string | undefined, topicId: string): string | undefined {
  if (!docsBase) return undefined;
  const t = helpTopics[topicId];
  const slug = t?.docSlug || topicId;
  return `${docsBase.replace(/\/$/, '')}/${slug}`;
}
