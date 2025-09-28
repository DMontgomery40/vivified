import axios, { AxiosInstance } from 'axios';

export class VivifiedClient {
  private client: AxiosInstance;

  constructor(baseUrl: string = process.env.VIVIFIED_BASE_URL || 'http://localhost:8000', token?: string) {
    this.client = axios.create({
      baseURL: baseUrl,
      headers: token ? { Authorization: `Bearer ${token}` } : undefined,
    });
  }

  async publish_event(event_type: string, payload: Record<string, unknown>, source_plugin: string, data_traits: string[] = []) {
    const body = { event_type, payload, source_plugin, data_traits };
    const r = await this.client.post('/messaging/events', body);
    return r.data;
  }

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  async subscribe(_event_type: string, _handler: (e: Record<string, unknown>) => void): Promise<void> {
    return;
  }

  async call_plugin(target_plugin: string, operation: string, payload: Record<string, unknown>) {
    const r = await this.client.post(`/gateway/${target_plugin}/${operation}`, payload);
    return r.data;
  }

  async call_external(plugin_id: string, url: string, method: string = 'GET', headers: Record<string, string> = {}, body?: unknown) {
    const req = { plugin_id, url, method, headers, body };
    const r = await this.client.post('/gateway/proxy', req);
    return r.data;
  }

  async get_config() {
    const r = await this.client.get('/admin/config');
    return r.data;
  }

  async set_config(key: string, value: unknown, is_sensitive: boolean = false, reason?: string) {
    const r = await this.client.put('/admin/config', { key, value, is_sensitive, reason });
    return r.data;
  }
}

export default VivifiedClient;

