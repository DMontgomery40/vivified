import type {
  HealthStatus,
  FaxJob,
  ApiKey,
  Settings,
  DiagnosticsResult,
  ValidationResult,
  InboundFax,
  ProvidersInfo
} from './types';

export class AdminAPIClient {
  private baseURL: string;
  private apiKey: string;
  private uiConfigEtag?: string;

  constructor(apiKey: string) {
    const envBase = (import.meta as any)?.env?.VITE_CORE_URL;
    // Fallback to localhost:8000 if env variable is not set (for development)
    this.baseURL = envBase || 'http://localhost:8000';
    this.apiKey = apiKey;
    if ((import.meta as any)?.env?.DEV) {
      // Dev-only: do not log secrets
      console.debug('AdminAPIClient initialized', { baseURL: this.baseURL });
    }
  }

  private async fetch(path: string, options: RequestInit = {}): Promise<Response> {
    const url = `${this.baseURL}${path}`;
    if ((import.meta as any)?.env?.DEV) {
      console.debug('AdminAPIClient fetch', { url, method: options?.method || 'GET' });
    }
    
    const response = await fetch(url, {
      ...options,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'X-API-Key': this.apiKey,
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });
    if ((import.meta as any)?.env?.DEV) {
      console.debug('AdminAPIClient response', { url, status: response.status, statusText: response.statusText });
    }
    
    if (!response.ok) {
      throw new Error(`API Error: ${response.status} ${response.statusText}`);
    }

    return response;
  }

  // Configuration
  async getConfig(): Promise<any> {
    const res = await this.fetch('/admin/config');
    return res.json();
  }

  // Messaging
  async getMessagingStats(): Promise<any> {
    const res = await this.fetch('/messaging/stats');
    return res.json();
  }

  async publishEvent(payload: {
    event_type: string;
    data: Record<string, any>;
    source_plugin: string;
    data_traits?: string[];
    metadata?: Record<string, string>;
  }): Promise<{ event_id: string; status: string }> {
    const res = await this.fetch('/messaging/events', {
      method: 'POST',
      body: JSON.stringify({
        event_type: payload.event_type,
        payload: payload.data,
        source_plugin: payload.source_plugin,
        data_traits: payload.data_traits || [],
        metadata: payload.metadata || {},
      }),
    });
    return res.json();
  }

  // Gateway
  async getGatewayStats(): Promise<any> {
    const res = await this.fetch('/gateway/stats');
    return res.json();
  }

  async proxyRequest(payload: {
    plugin_id: string;
    method: string;
    url: string;
    headers?: Record<string, string>;
    body?: string;
    timeout?: number;
  }): Promise<any> {
    const res = await this.fetch('/gateway/proxy', {
      method: 'POST',
      body: JSON.stringify({
        plugin_id: payload.plugin_id,
        method: payload.method,
        url: payload.url,
        headers: payload.headers || {},
        body: payload.body ? new TextEncoder().encode(payload.body) : undefined,
        timeout: payload.timeout ?? 30,
      }),
    });
    return res.json();
  }

  async getGatewayAllowlist(pluginId: string): Promise<{ plugin_id: string; items: Record<string, { allowed_methods: string[]; allowed_paths: string[] }> }>{
    const res = await this.fetch(`/admin/gateway/allowlist?plugin_id=${encodeURIComponent(pluginId)}`);
    return res.json();
  }

  async setGatewayAllowlist(payload: { plugin_id: string; allowlist: Record<string, { allowed_methods: string[]; allowed_paths: string[] }> }): Promise<{ ok: boolean; plugin_id: string }>{
    const res = await this.fetch('/admin/gateway/allowlist', {
      method: 'PUT',
      body: JSON.stringify(payload),
    });
    return res.json();
  }

  // Canonical
  async getCanonicalStats(): Promise<any> {
    const res = await this.fetch('/canonical/stats');
    return res.json();
  }

  async normalizeUser(payload: {
    user_data: Record<string, any>;
    source_plugin: string;
    target_plugin: string;
  }): Promise<any> {
    const res = await this.fetch('/canonical/normalize/user', {
      method: 'POST',
      body: JSON.stringify({
        user_data: payload.user_data,
        source_plugin: payload.source_plugin,
        target_plugin: payload.target_plugin,
      }),
    });
    return res.json();
  }

  // Core plugin registration
  async registerPlugin(manifest: Record<string, any>): Promise<any> {
    const res = await this.fetch('/plugins/register', {
      method: 'POST',
      body: JSON.stringify(manifest),
    });
    return res.json();
  }

  async importEnv(prefixes?: string[]): Promise<{ ok: boolean; discovered: number; prefixes: string[] }>{
    const body = prefixes && prefixes.length ? { prefixes } : {};
    const res = await this.fetch('/admin/config/import-env', {
      method: 'POST',
      body: JSON.stringify(body)
    });
    return res.json();
  }

  async getSettings(): Promise<Settings> {
    const res = await this.fetch('/admin/settings');
    return res.json();
  }

  async validateSettings(settings: any): Promise<ValidationResult> {
    const res = await this.fetch('/admin/settings/validate', {
      method: 'POST',
      body: JSON.stringify(settings),
    });
    return res.json();
  }

  async exportSettings(): Promise<{ env_content: string; requires_restart: boolean; note: string }> {
    const res = await this.fetch('/admin/settings/export');
    return res.json();
  }

  async persistSettings(content?: string, path?: string): Promise<{ ok: boolean; path: string }> {
    const res = await this.fetch('/admin/settings/persist', {
      method: 'POST',
      body: JSON.stringify({ content, path }),
    });
    return res.json();
  }

  async updateSettings(settings: any): Promise<any> {
    const res = await this.fetch('/admin/settings', {
      method: 'PUT',
      body: JSON.stringify(settings),
    });
    return res.json();
  }

  async reloadSettings(): Promise<any> {
    const res = await this.fetch('/admin/settings/reload', { method: 'POST' });
    return res.json();
  }

  async restart(): Promise<any> {
    const res = await this.fetch('/admin/restart', { method: 'POST' });
    return res.json();
  }

  // Diagnostics
  async runDiagnostics(): Promise<DiagnosticsResult> {
    const res = await this.fetch('/admin/diagnostics/run', {
      method: 'POST',
    });
    return res.json();
  }

  // Hierarchical Configuration (v4)
  async getEffectiveConfig(): Promise<{ values: Record<string, any>; cache_stats?: any }> {
    const res = await this.fetch('/admin/config/v4/effective');
    return res.json();
  }

  async getConfigHierarchy(key: string): Promise<{ key: string; layers: any[] }> {
    const res = await this.fetch(`/admin/config/v4/hierarchy?key=${encodeURIComponent(key)}`);
    return res.json();
  }

  async getSafeEditKeys(): Promise<Record<string, any>> {
    const res = await this.fetch('/admin/config/v4/safe-keys');
    return res.json();
  }

  async setConfigValue(
    key: string,
    value: any,
    level: string,
    levelId?: string,
    reason?: string,
    encrypt?: boolean
  ): Promise<{ success: boolean }> {
    const formData = new FormData();
    formData.append('key', key);
    formData.append('value', typeof value === 'string' ? value : JSON.stringify(value));
    formData.append('level', level);
    if (levelId) formData.append('level_id', levelId);
    if (reason) formData.append('reason', reason);
    if (encrypt !== undefined) formData.append('encrypt', encrypt.toString());

    const res = await this.fetch('/admin/config/v4/set', {
      method: 'POST',
      body: formData,
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        // Don't set Content-Type, let browser set it for FormData
      },
    });
    return res.json();
  }

  async flushConfigCache(scope?: string): Promise<{ success: boolean }> {
    const res = await this.fetch('/admin/config/v4/flush-cache', {
      method: 'POST',
      body: JSON.stringify(scope ? { scope } : {}),
    });
    return res.json();
  }

  // UI Config (ETag-cached on server)
  async getUiConfig(): Promise<{ schema_version: number; features: any; endpoints: any; docs_base?: string }>{
    const headers: Record<string, string> = {
      'Authorization': `Bearer ${this.apiKey}`,
      'X-API-Key': this.apiKey,
    };
    if (this.uiConfigEtag) headers['If-None-Match'] = this.uiConfigEtag;
    const url = `${this.baseURL}/admin/ui-config`;
    const res = await fetch(url, { headers });
    // Capture ETag for conditional requests
    const et = res.headers.get('ETag') || res.headers.get('etag') || undefined;
    if (et) this.uiConfigEtag = et.trim();
    if (res.status === 304) {
      // No change; return a minimal stub to signal no-update
      return { schema_version: 1, features: {}, endpoints: {} } as any;
    }
    if (!res.ok) {
      throw new Error(`API Error: ${res.status} ${res.statusText}`);
    }
    return res.json();
  }

  // v4 Config (read-only baseline)
  async v4GetEffective(payload: { keys?: string[]; user_id?: string; tenant_id?: string; department?: string; groups?: string[] } = {}): Promise<{ schema_version: number; items: Record<string, any> }>{
    const res = await this.fetch('/admin/config/v4/effective', {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    });
    return res.json();
  }

  async v4GetHierarchy(payload: { key: string; user_id?: string; tenant_id?: string; department?: string; groups?: string[] }): Promise<any>{
    const res = await this.fetch('/admin/config/v4/hierarchy', {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    });
    return res.json();
  }

  async v4GetSafeKeys(): Promise<Record<string, any>>{
    const res = await this.fetch('/admin/config/v4/safe-keys');
    return res.json();
  }

  async v4FlushCache(scope: string = '*'): Promise<{ ok: boolean; deleted?: number | null; scope: string; backend?: string }>{
    const res = await this.fetch(`/admin/config/v4/flush-cache?scope=${encodeURIComponent(scope)}`, {
      method: 'POST',
    });
    return res.json();
  }

  // Vivified: plugin operations
  async enablePlugin(pluginId: string): Promise<{ status: string; plugin_id: string }>{
    const res = await this.fetch(`/admin/plugins/${encodeURIComponent(pluginId)}/enable`, { method: 'POST' });
    return res.json();
  }

  // Storage
  async storageList(limit = 50, offset = 0, classification?: string): Promise<{ items: Array<any>; limit: number; offset: number }>{
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (classification) params.set('classification', classification);
    const res = await this.fetch(`/admin/storage/objects?${params.toString()}`);
    return res.json();
  }

  async storageMetadata(objectKey: string): Promise<any> {
    const res = await this.fetch(`/admin/storage/objects/${encodeURIComponent(objectKey)}`);
    return res.json();
  }

  async storageDownload(objectKey: string): Promise<Blob> {
    const url = `${this.baseURL}/admin/storage/objects/${encodeURIComponent(objectKey)}/download`;
    const res = await fetch(url, {
      headers: {
        'Authorization': `Bearer ${this.apiKey}`,
        'X-API-Key': this.apiKey,
      },
    });
    if (!res.ok) throw new Error(`Download failed: ${res.status}`);
    return res.blob();
  }

  async disablePlugin(pluginId: string, reason: string = ''): Promise<{ status: string; plugin_id: string }>{
    const res = await this.fetch(`/admin/plugins/${encodeURIComponent(pluginId)}/disable`, { method: 'POST', body: JSON.stringify({ reason }) });
    return res.json();
  }

  

  // User traits (admin-only)
  async getUserTraits(): Promise<{ schema_version: number; user: { id: string }; traits: string[]; backend_traits?: string[] }>{
    const res = await this.fetch('/admin/user/traits');
    return res.json();
  }

  // Provider traits & active backends
  async getProviders(): Promise<ProvidersInfo> {
    let res = await this.fetch('/admin/integrations').catch(() => null as any);
    if (!res || !res.ok) {
      res = await this.fetch('/admin/providers');
    }
    return res.json();
  }

  // Admin Users
  async listUsers(): Promise<{ users: Array<{ id: string; username: string; display_name?: string; email?: string; is_active: boolean; created_at?: string }> }> {
    const res = await this.fetch('/admin/users');
    return res.json();
  }

  async createUser(payload: { username: string; password: string; display_name?: string; email?: string }): Promise<any> {
    const res = await this.fetch('/admin/users', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    return res.json();
  }

  async patchUser(id: string, payload: { display_name?: string; email?: string; is_active?: boolean }): Promise<any> {
    const res = await this.fetch(`/admin/users/${encodeURIComponent(id)}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    });
    return res.json();
  }

  async getHealthStatus(): Promise<HealthStatus> {
    const res = await this.fetch('/admin/health-status');
    return res.json();
  }

  // MCP
  async getMcpConfig(): Promise<any> {
    const res = await this.fetch('/admin/config');
    return res.json();
  }

  async getMcpHealth(path: string = '/mcp/sse/health'): Promise<any> {
    const res = await fetch(`${this.baseURL}${path}`);
    if (!res.ok) throw new Error(`MCP not healthy (${res.status})`);
    return res.json();
  }

  // Logs
  async getLogs(params: { q?: string; event?: string; since?: string; limit?: number } = {}): Promise<{ items: any[]; count: number }>{
    const search = new URLSearchParams();
    for (const [k,v] of Object.entries(params)) {
      if (v !== undefined && v !== null && String(v).length > 0) search.append(k, String(v));
    }
    const res = await this.fetch(`/admin/logs?${search.toString()}`);
    return res.json();
  }

  async tailLogs(params: { q?: string; event?: string; lines?: number } = {}): Promise<{ items: any[]; count: number; source?: string }>{
    const search = new URLSearchParams();
    for (const [k,v] of Object.entries(params)) {
      if (v !== undefined && v !== null && String(v).length > 0) search.append(k, String(v));
    }
    const res = await this.fetch(`/admin/logs/tail?${search.toString()}`);
    return res.json();
  }

  // Events & Diagnostics
  async getRecentEvents(params: {
    limit?: number;
    provider_id?: string;
    event_type?: string;
    from_db?: boolean
  } = {}): Promise<{ events: any[]; total: number; source: string }> {
    const search = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        search.append(key, String(value));
      }
    });
    const res = await this.fetch(`/admin/diagnostics/events/recent?${search}`);
    return res.json();
  }

  async getEventTypes(): Promise<{ event_types: Array<{ value: string; label: string }> }> {
    const res = await this.fetch('/admin/diagnostics/events/types');
    return res.json();
  }

  createEventSSE(): EventSource {
    // Note: EventSource doesn't support custom headers directly
    // Pass API key as query parameter for authentication
    const params = new URLSearchParams();
    params.append('X-API-Key', this.apiKey);
    return new EventSource(`${this.baseURL}/admin/diagnostics/events/sse?${params.toString()}`);
  }

  // Provider Health Management
  async getProviderHealthStatus(): Promise<{
    provider_statuses: Record<string, any>;
    total_providers: number;
    healthy_count: number;
    degraded_count: number;
    circuit_open_count: number;
    disabled_count: number;
  }> {
    let res = await this.fetch('/admin/integrations/health').catch(() => null as any);
    if (!res || !res.ok) {
      res = await this.fetch('/admin/providers/health');
    }
    return res.json();
  }

  // Vivified: roles and audit
  async getRoles(): Promise<{ roles: Array<{ id: string; name: string; description?: string; traits: string[] }> }>{
    const res = await this.fetch('/admin/roles');
    return res.json();
  }

  async setUserRoles(id: string, roles: string[]): Promise<{ ok: boolean }>{
    const res = await this.fetch(`/admin/users/${encodeURIComponent(id)}/roles`, { method: 'PUT', body: JSON.stringify({ roles }) });
    return res.json();
  }

  async getAudit(limit: number = 100, offset: number = 0): Promise<{ items: any[]; total: number }>{
    const res = await this.fetch(`/admin/audit?limit=${encodeURIComponent(String(limit))}&offset=${encodeURIComponent(String(offset))}`);
    return res.json();
  }

  async enableProvider(providerId: string): Promise<{
    success: boolean;
    provider_id: string;
    new_status: string;
    message?: string;
  }> {
    let res = await this.fetch('/admin/integrations/enable', { method: 'POST', body: JSON.stringify({ provider_id: providerId }) }).catch(() => null as any);
    if (!res || !res.ok) {
      res = await this.fetch('/admin/providers/enable', { method: 'POST', body: JSON.stringify({ provider_id: providerId }) });
    }
    return res.json();
  }

  async disableProvider(providerId: string): Promise<{
    success: boolean;
    provider_id: string;
    new_status: string;
    message?: string;
  }> {
    let res = await this.fetch('/admin/integrations/disable', { method: 'POST', body: JSON.stringify({ provider_id: providerId }) }).catch(() => null as any);
    if (!res || !res.ok) {
      res = await this.fetch('/admin/providers/disable', { method: 'POST', body: JSON.stringify({ provider_id: providerId }) });
    }
    return res.json();
  }

  async shouldAllowRequests(providerId: string): Promise<{
    provider_id: string;
    allowed: boolean;
    reason: string;
  }> {
    const res = await this.fetch(`/admin/providers/circuit-breaker/${encodeURIComponent(providerId)}/should-allow`);
    return res.json();
  }

  // Jobs
  async listJobs(params: { 
    status?: string; 
    backend?: string; 
    limit?: number; 
    offset?: number 
  } = {}): Promise<{ total: number; jobs: FaxJob[] }> {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined) {
        query.append(key, String(value));
      }
    });
    const res = await this.fetch(`/admin/fax-jobs?${query}`);
    return res.json();
  }

  async getJob(id: string): Promise<FaxJob> {
    const res = await this.fetch(`/admin/fax-jobs/${id}`);
    return res.json();
  }

  async downloadJobPdf(id: string): Promise<Blob> {
    const res = await fetch(`${this.baseURL}/admin/fax-jobs/${encodeURIComponent(id)}/pdf`, {
      headers: {
        'X-API-Key': this.apiKey,
      },
    });
    if (!res.ok) {
      throw new Error(`Download failed: ${res.status}`);
    }
    return res.blob();
  }

  // API Keys
  async createApiKey(data: { 
    name?: string; 
    owner?: string; 
    scopes?: string[] 
  }): Promise<{ key_id: string; token: string }> {
    const res = await this.fetch('/admin/api-keys', {
      method: 'POST',
      body: JSON.stringify(data),
    });
    return res.json();
  }

  async listApiKeys(): Promise<ApiKey[]> {
    const res = await this.fetch('/admin/api-keys');
    return res.json();
  }

  async revokeApiKey(keyId: string): Promise<void> {
    await this.fetch(`/admin/api-keys/${keyId}`, {
      method: 'DELETE',
    });
  }

  async rotateApiKey(keyId: string): Promise<{ token: string }> {
    const res = await this.fetch(`/admin/api-keys/${keyId}/rotate`, {
      method: 'POST',
    });
    return res.json();
  }

  // Inbound
  async listInbound(): Promise<InboundFax[]> {
    const res = await this.fetch('/inbound');
    return res.json();
  }

  async downloadInboundPdf(id: string): Promise<Blob> {
    const res = await fetch(`${this.baseURL}/inbound/${encodeURIComponent(id)}/pdf`, {
      headers: {
        'X-API-Key': this.apiKey,
      },
    });
    
    if (!res.ok) {
      throw new Error(`Download failed: ${res.status}`);
    }
    
    return res.blob();
  }

  // Inbound helpers
  async getInboundCallbacks(): Promise<any> {
    const res = await this.fetch('/admin/inbound/callbacks');
    return res.json();
  }

  async purgeInboundBySid(providerSid: string): Promise<{ ok: boolean; deleted_faxes: number; deleted_events: number }>{
    const res = await this.fetch('/admin/inbound/purge-by-sid', {
      method: 'DELETE',
      body: JSON.stringify({ provider_sid: providerSid })
    });
    return res.json();
  }

  async simulateInbound(opts: { backend?: string; fr?: string; to?: string; pages?: number; status?: string } = {}): Promise<{ id: string; status: string }> {
    const res = await this.fetch('/admin/inbound/simulate', {
      method: 'POST',
      body: JSON.stringify(opts),
    });
    return res.json();
  }

  // Admin actions (container exec — allowlisted)
  async listActions(): Promise<{ enabled: boolean; items: Array<{ id: string; label: string; backend?: string[] }> }> {
    const res = await this.fetch('/admin/actions');
    return res.json();
  }

  async runAction(id: string): Promise<{ ok: boolean; id: string; code?: number; stdout?: string; stderr?: string }> {
    const res = await this.fetch('/admin/actions/run', {
      method: 'POST',
      body: JSON.stringify({ id }),
    });
    return res.json();
  }

  // Tunnel (admin-only)
  async getTunnelStatus(): Promise<any> {
    const res = await this.fetch('/admin/tunnel/status');
    return res.json();
  }

  async setTunnelConfig(payload: any): Promise<any> {
    const res = await this.fetch('/admin/tunnel/config', {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    });
    return res.json();
  }

  async testTunnel(): Promise<{ ok: boolean; message?: string; target?: string }> {
    const res = await this.fetch('/admin/tunnel/test', { method: 'POST' });
    return res.json();
  }

  async createTunnelPairing(): Promise<{ code: string; expires_at: string }> {
    const res = await this.fetch('/admin/tunnel/pair', { method: 'POST' });
    return res.json();
  }

  async registerSinchWebhook(): Promise<{ success: boolean; webhook_url?: string; error?: string; provider_response?: any }>{
    const res = await this.fetch('/admin/tunnel/register-sinch', { method: 'POST' });
    return res.json();
  }

  // Cloudflared logs (admin-only)
  async getTunnelCloudflaredLogs(lines: number = 50): Promise<{ items: string[]; path?: string }>{
    const res = await this.fetch(`/admin/tunnel/cloudflared/logs?lines=${encodeURIComponent(String(lines))}`);
    return res.json();
  }

  // WireGuard config + QR
  async wgImportConfFile(file: File): Promise<{ ok: boolean; path?: string }>{
    const form = new FormData();
    form.append('file', file);
    const res = await fetch(`${this.baseURL}/admin/tunnel/wg/import`, {
      method: 'POST',
      headers: { 'X-API-Key': this.apiKey },
      body: form,
    });
    if (!res.ok) throw new Error(`Import failed: ${res.status}`);
    return res.json();
  }

  async wgImportConfText(content: string): Promise<{ ok: boolean; path?: string }>{
    const res = await this.fetch('/admin/tunnel/wg/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content }),
    });
    return res.json();
  }

  async wgDownloadConf(): Promise<Blob> {
    const res = await fetch(`${this.baseURL}/admin/tunnel/wg/conf`, {
      headers: { 'X-API-Key': this.apiKey },
    });
    if (!res.ok) throw new Error(`Download failed: ${res.status}`);
    return res.blob();
  }

  async wgDeleteConf(): Promise<{ ok: boolean }>{
    const res = await this.fetch('/admin/tunnel/wg/conf', { method: 'DELETE' });
    return res.json();
  }

  async wgGetQr(): Promise<{ png_base64?: string; svg_base64?: string }>{
    const res = await this.fetch('/admin/tunnel/wg/qr', { method: 'POST' });
    return res.json();
  }

  // Send test fax
  async sendFax(to: string, file: File): Promise<{ id: string; status: string }> {
    const formData = new FormData();
    formData.append('to', to);
    formData.append('file', file);

    const res = await fetch(`${this.baseURL}/fax`, {
      method: 'POST',
      headers: {
        'X-API-Key': this.apiKey,
      },
      body: formData,
    });

    if (!res.ok) {
      throw new Error(`Send failed: ${res.status}`);
    }

    return res.json();
  }

  // v3 Plugins (feature-gated)
  async listPlugins(): Promise<{ items: any[] }> {
    const res = await this.fetch('/admin/plugins');
    const data = await res.json();
    // Vivified returns { plugins: [...] }
    const items = Array.isArray(data?.plugins) ? data.plugins : (data?.items || []);
    return { items } as any;
  }

  async getPluginConfig(pluginId: string): Promise<{ enabled: boolean; settings: any }> {
    const res = await this.fetch(`/plugins/${encodeURIComponent(pluginId)}/config`);
    return res.json();
  }

  async updatePluginConfig(pluginId: string, payload: { enabled?: boolean; settings?: Record<string, any> }): Promise<{ ok: boolean; path: string }> {
    const res = await this.fetch(`/plugins/${encodeURIComponent(pluginId)}/config`, {
      method: 'PUT',
      body: JSON.stringify(payload || {}),
    });
    return res.json();
  }

  async getPluginRegistry(): Promise<{ items: any[] }> {
    // Vivified: curated registry not implemented yet
    return { items: [] };
  }

  // Manifest providers (admin-only)
  async validateHttpManifest(payload: { manifest: any; credentials?: any; settings?: any; to?: string; file_url?: string; from_number?: string; render_only?: boolean }): Promise<any> {
    const res = await this.fetch('/admin/plugins/http/validate', {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    });
    return res.json();
  }

  async installHttpManifest(payload: { manifest: any }): Promise<{ ok: boolean; id: string; path: string }> {
    const res = await this.fetch('/admin/plugins/http/install', {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    });
    return res.json();
  }

  // Jobs admin helpers
  async refreshJob(jobId: string): Promise<FaxJob> {
    const res = await this.fetch(`/admin/fax-jobs/${encodeURIComponent(jobId)}/refresh`, { method: 'POST' });
    return res.json();
  }

  async importHttpManifests(payload: { items?: any[]; markdown?: string }): Promise<{ ok: boolean; imported: any[]; errors: any[] }>{
    const res = await this.fetch('/admin/plugins/http/import-manifests', {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    });
    return res.json();
  }

  // Polling helper
  startPolling(onUpdate: (data: HealthStatus) => void, intervalMs: number = 5000): () => void {
    let running = true;
    
    const poll = async () => {
      if (!running) return;
      try {
        const data = await this.getHealthStatus();
        onUpdate(data);
      } catch (e) {
        console.error('Polling error:', e);
      }
      if (running) {
        setTimeout(poll, intervalMs);
      }
    };
    
    poll(); // Start immediately
    
    // Return cleanup function
    return () => { running = false; };
  }
}

export default AdminAPIClient;
