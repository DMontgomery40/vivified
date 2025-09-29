# LLM OSS Plugin (Local/Ollama/GPT‑OSS)

This guide shows how to build and wire a custom LLM plugin that runs on‑prem (e.g., Ollama or a GPT‑OSS server). It covers manifest design, allowlists, operator endpoints, and Admin Console setup.

## Goals
- Provider isolation: your plugin talks to your LLM, Core mediates everything.
- TBAC and audit: all calls logged and policy‑enforced.
- Easy UI: pick `local` provider, select models via `/admin/ai/models` when reachable.

## Manifest

```json
{
  "id": "llm-oss",
  "name": "LLM OSS (Local)",
  "version": "0.1.0",
  "contracts": ["llm", "embeddings"],
  "traits": ["plugin_manager"],
  "allowed_domains": [],
  "endpoints": {
    "chat": "/chat",
    "embeddings": "/embeddings"
  },
  "security": {"scopes": ["llm:chat", "llm:embeddings"]},
  "compliance": {"hipaa_controls": ["164.312(a)"]}
}
```

- `endpoints.chat` and `endpoints.embeddings` are relative paths exposed by your container on port 8080 by default (configurable via `host`/`port` in manifest).

## Endpoints

- POST `/chat`
  - Body: `{ "messages": [...], "tools?": [...], "model": "name", "max_tokens?": 1024 }`
  - Return: `{ "text": "...", "tool_calls?": [{"name":"...","arguments":{...}}] }`
- POST `/embeddings`
  - Body: `{ "input": "text or list", "model": "name" }`
  - Return: `{ "data": [{ "embedding": [float, ...] }] }`

Your plugin translates these to your backend (Ollama, GPT‑OSS) and returns normalized results.

## Registration + Allowlist

1. Admin Console → Plugins → Register → paste manifest → Register.
2. Admin Console → Plugins → Policies → Apply Suggested Allowlist (if your plugin calls external hosts; most local setups won’t).
3. Admin Console → Tools → AI Studio → Provider = `local`.
4. Models dropdown auto‑loads from `http://localhost:11434/api/tags` (if reachable) via `/admin/ai/models`.

## Operator Calls (optional)

If other plugins (or Core) must call your plugin synchronously, implement additional `endpoints` and allow them via `PUT /admin/operator/allowlist` (GUI: Plugin Dev Guide → Generate Operator Allowlist). Core exposes:

- `POST /gateway/{target_plugin}/{operation}` → forwards JSON payload to the plugin endpoint.
- Policy and operator allowlist are enforced; every call audited.

## Security
- All secrets live in ConfigService. Never hardcode keys.
- Gateway deny‑lists unsafe hosts and IP literals; only allowed domains pass.
- Logs redact PHI/PII.

## Testing
- Use `make smoke-ai` to validate RAG and embeddings end‑to‑end.
- Use Admin Console ChatBot and AI Studio to verify chat responses and tool calls.

```
# Example local run
docker compose up -d vivified-core redis postgres admin-ui-dev
```

