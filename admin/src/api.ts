import axios from "axios";

export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8787";

export const api = axios.create({
  baseURL: API_BASE,
  timeout: 15000,
});

export async function fetchPlugins(): Promise<string[]> {
  const { data } = await api.get("/plugins");
  return data.plugins || [];
}

export async function health(): Promise<boolean> {
  const { data } = await api.get("/health");
  return !!data?.ok;
}

export async function runPlugin(name: string, args: string[] = []): Promise<number> {
  const { data } = await api.post("/run", { plugin: name, args });
  return data.code ?? 0;
}

