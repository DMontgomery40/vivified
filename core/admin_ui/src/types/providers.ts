export interface ProviderInfo {
  key: string;
  name: string;
  icon: string; // material icon name
  category: 'crm' | 'comm' | 'storage' | 'other';
  hipaa_allowed: boolean;
  outbound_domains: string[];
  env_vars: string[];
}

export type ProviderRegistry = Record<string, ProviderInfo>;

// Step-2: source of truth mirrored from backend
export const PROVIDER_REGISTRY: ProviderRegistry = {
  hubspot: {
    key: 'hubspot',
    name: 'HubSpot CRM',
    icon: 'hub',
    category: 'crm',
    hipaa_allowed: false,
    outbound_domains: ['api.hubapi.com', 'app.hubspot.com'],
    env_vars: ['HUBSPOT_CLIENT_ID', 'HUBSPOT_CLIENT_SECRET', 'HUBSPOT_SCOPE'],
  },
};

