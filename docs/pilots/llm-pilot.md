# Enterprise Pilot Guide: LLM + RAG

This hands-on guide walks a pilot team through plugging in your own LLM and (optionally) your own RAG database backend. It focuses on functionality and time-to-first-demo.

## 1) Start the stack

```
docker compose up -d postgres redis vivified-core admin-ui-dev
```

- Core API: http://localhost:8000
- Admin UI (dev): http://localhost:5173

## 2) Dev login (pilot)

- Admin UI → click Dev Login (DEV_MODE=true). This issues an admin token locally; do not use for production.

## 3) Pick your provider

- Admin → Tools → AI Studio → LLM Configuration
  - Provider: openai | claude | local
  - Model: dropdown auto-loads from provider (or type manually)
  - Base URL: defaults are filled; adjust for your setup
  - Embeddings Model: defaults to text-embedding-3-small
  - Save

Tips:
- OpenAI: paste API key and use `gpt-4o-mini` (fast/cheap) for demos.
- Claude: paste x-api-key; e.g., `claude-3.5-sonnet-20240620`.
- Local: choose `local`, set Connectors allowlist, and pick `llama3.1:8b` (Ollama). No PHI/PII recommended in alpha.

## 4) Allowlists (egress)

- Admin → Tools → AI Studio → Connectors → “Apply Default AI Allowlist”
- Verifies gateway allowlist for api.openai.com / api.anthropic.com / local base.

## 5) Train RAG

- Admin → Tools → AI Studio → “Train Everything (.)”
  - Respects `.ragignore` and `.gitignore`.
  - Redis-backed RAG persists; vectors stored per chunk.

Optional RAG tuning:
- Ingestion Rules → RAG Settings → adjust Chunk Size and Overlap.
- Backend = Plugin to delegate storage/search to your own DB plugin (see RAG DB Plugin guide).

## 6) Smoke test

```
export API_KEY=bootstrap_admin_only
export AI_API_URL=http://localhost:8000
export OPENAI_API_KEY=sk-...
make smoke-ai
```

- Checks `/admin/ai/status`, trains (optional), and queries RAG.

## 7) Your plugins

### LLM OSS plugin
- Build a plugin with `/chat` and `/embeddings` and register it via Admin → Plugins → Register.
- Set Provider=local in AI Studio; models load from your server.
- See: Plugins → LLM OSS (Local)

### RAG DB plugin
- Implement `rag_index` and `rag_query` (+ manifest endpoints) and register.
- Operator allowlist: Admin → Plugin Dev Guide → Generate Operator Allowlist (caller `ai-core` → your plugin: `rag_index`, `rag_query`).
- In AI Studio → RAG Settings, set Backend=Plugin and your Plugin ID.
- See: Plugins → RAG DB Plugin

## 8) Demo workflow

- Train → Query RAG (shows top matches, TBAC filtered)
- Agent Run: ask “Summarize Vivified core and how plugins integrate”
- Show TBAC chips (“Your Traits”, “Required Traits”, “Blocked”) for transparency
- Show Connectors and Allowlist view to confirm egress controls

## 9) What’s next

- Add metrics panels in Admin → Monitoring
- Add your own tool(s) to the agent (HTTP fetch via proxy, storage ops)
- Optional: switch to Redis Stack (6380) or your DB plugin for ANN vector search

