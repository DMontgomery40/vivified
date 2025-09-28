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

