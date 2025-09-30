# AI & Agents (RAG + LLM)

This page documents Vivified’s internal AI features: repository‑wide RAG (indexing your code and docs), a trait‑aware query path, semantic retrieval with embeddings, and an agent that can call an LLM through the Core gateway with strict allowlists. RAG prefers Redis as the default backend when available, with graceful fallback to in‑memory storage.

Important: This is an internal/developer feature set. Customer‑facing docs will be derived from this page later.

## Features

- Repository‑wide RAG (Redis‑backed by default) with embeddings
  - Indexes the entire repo (`.`) by default and respects `.ragignore` first, then `.gitignore`.
  - Ignore patterns support anchored paths (`/path`), directory suffix (`dir/`), and globbing (`*.log`).
  - Reads any text‑decodable file up to `RAG_MAX_BYTES` (default 2 MB); binary blobs are skipped.
  - Backend selection: if `REDIS_URL` is set or Redis is reachable at `redis://localhost:6379/0`, Redis is used; otherwise falls back to memory.
  - Vector search: chunks are embedded via OpenAI embeddings (default `text-embedding-3-small`) and ranked by cosine similarity; falls back to sparse token overlap if embeddings are unavailable.
- Chunking
  - `RAG_CHUNK_CHARS` default 4000; `RAG_OVERLAP_CHARS` default 400.
  - Each chunk carries `required_traits` and `classification` metadata used at query time (TBAC).
  - UI controls: Admin → Tools → AI Studio → Ingestion Rules → RAG Settings lets you set Chunk Size and Overlap without env changes.
- Trait‑aware querying (TBAC)
  - Only returns documents where `required_traits ⊆ user.traits`.
  - Defaults to `required_traits=[]` for code/docs; add traits to sensitive datasets to gate access.
- LLM agent through Core gateway (egress allowlist)
  - Proxies to OpenAI via `/gateway/proxy` with plugin_id `ai-core` (allowlist seeded for chat completions).
  - Falls back to a direct call if proxy is unavailable.
  - Default model: `gpt-5-mini` (override with `AI_LLM_MODEL` or `OPENAI_DEFAULT_MODEL`).
- Auto‑training on startup (optional) and periodic updates
  - `AI_AUTO_TRAIN=true` indexes `.` on startup.
  - `RAG_UPDATE_INTERVAL_MINUTES` controls retraining cadence (default 20 minutes).

## Quick Start

1) Start Core with `.env` (OpenAI key optional):

```
uvicorn core.main:app --reload
```

2) (Optional) Auto‑train on startup and enable 20‑minute updates:

```
export AI_AUTO_TRAIN=true
export RAG_UPDATE_INTERVAL_MINUTES=20
uvicorn core.main:app --reload
```

3) Open Admin Console → Tools → “AI Studio”
   - Click “Train from Docs” to index the repo now (respects ignore files).
   - Pick Provider from the dropdown (OpenAI, Claude, or Local). When a provider is selected, the Model dropdown auto‑loads available models from the provider (`/admin/ai/models`) with your configured key and base URL. For Local (e.g., Ollama), popular tags are shown when reachable; otherwise, type your model.
   - Search the index and run Agent to get a human‑readable answer with code/docs context.

## Admin API

- `GET /admin/ai/status` → `{ docs_indexed, last_trained_ts, backend }` (admin)
- `POST /admin/ai/train` → `{ ok, indexed, total }` (admin)
  - Body: `{ sources?: string[] }` (defaults to `"."`)
- `POST /admin/ai/query` → `{ items }` (viewer/admin)
  - Body: `{ q: string }` (filters by user traits)
- `POST /admin/ai/agent/run` → `{ result }` (admin)
  - Body: `{ prompt: string }`
- `GET /admin/ai/models?provider=openai&typ=chat|embeddings` → `{ provider, type, models }` (viewer/admin)
  - Lists model IDs using provider APIs via the Core gateway; includes sensible fallbacks when APIs are unavailable.

Notes:
- The server reads `.env` at startup; set `OPENAI_API_KEY` to use live LLM and embeddings.
- Default chat model is `gpt-5-mini`; override via `AI_LLM_MODEL`.
- Default embeddings model is `text-embedding-3-small`; override via Admin → AI Studio or `EMBEDDING_MODEL`/`OPENAI_EMBEDDING_MODEL`.
- RAG defaults: `REDIS_URL=redis://localhost:6379/0` (if reachable); otherwise memory.
 - Optional RAG backend: set Backend=Plugin and choose your plugin id to delegate indexing/search over the operator lane. Your plugin implements `rag_index` and `rag_query` (see Plugins → RAG DB Plugin).
 - Optional: Use Redis Stack for native vector indices; run `redis-stack` service from docker-compose and set `REDIS_URL=redis://localhost:6380/0`.

## Ignore Model

- `.ragignore` (optional) has priority over `.gitignore`.
- Patterns:
  - Anchored path: `/build/` matches from repo root.
  - Directory: `cache/` prunes entire subtree.
  - Glob: `*.log`, `*.tmp`, `node_modules/`, etc.

Example `.ragignore`:

```
/site/
/node_modules/
*.png
*.jpg
*.pdf
```

### Ingestion Rules (required_traits/classification)

You can attach trait requirements and classification labels to files based on path globs. The indexer will read two optional ConfigService keys:

```
ai.rag.required_traits = {
  "internal-plans/**": ["internal_docs"],
  "data/analytics/**": ["analytics_viewer"],
  "**/*.sql": ["dba_viewer"]
}

ai.rag.classification = {
  "data/analytics/**": ["sensitive"],
  "docs/**": ["internal"]
}
```

Only documents whose `required_traits` are a subset of the current user's traits are considered at query time. Use this to keep PII-gated datasets out of the assistant’s view while permitting HIPAA‑safe analytics.

## TBAC (HIPAA‑safe)

- Each document has `required_traits` (default `[]`) and `classification` (default `internal`).
- Query filters results to those with `required_traits ⊆ user.traits`.
- Classification gates map to traits automatically. Defaults:
  - `phi` requires user trait `hipaa_cleared`
  - `pii` requires user trait `pii_cleared`
  Override with `ai.rag.classification_gate`, e.g.: `{ "phi": ["hipaa_cleared"], "pii": ["pii_cleared"] }`.
- Pattern: Place analytics‑safe data behind a trait such as `analytics_viewer` and exclude PII traits entirely. The agent can answer aggregate questions without ever seeing names/addresses.

## LLM via Gateway

- The agent calls OpenAI via Core’s `/gateway/proxy` using plugin_id `ai-core`. Fallback is direct.
- On startup we seed an allowlist for `api.openai.com` POST `/v1/chat/completions`.
- Configure (prefer ConfigService over env):
  - Admin → Tools → AI Studio → LLM Configuration to set provider (`openai`, `claude`, or `local`), model, base URL, embeddings model, and API key securely.
  - Or via API: `GET/PUT /admin/ai/config`.
  - Legacy endpoints: `GET/PUT /admin/ai/connectors`.

## MCP (Preview)

- Health: `GET /mcp/sse/health`, `GET /mcp/http/health`.
- Tool: `POST /mcp/http/tools/rag/query` → `{ items }` (viewer/admin), body `{ q: string }`.
- Settings (Admin → Settings → MCP) toggle SSE/HTTP and optional OAuth.

## CLI Helper

```
AI_API_URL=http://localhost:8000 API_KEY=bootstrap_admin_only \
  python tools/scripts/rag_train.py --sources .
```

## Smoke Test

To verify RAG + embeddings end‑to‑end locally:

```
API_KEY=bootstrap_admin_only AI_API_URL=http://localhost:8000 \
  OPENAI_API_KEY=sk-... \
  python tools/scripts/rag_smoke.py --train --query "Vivified core platform"
```

The script checks status, trains (if requested), performs a query, and reports the backend (redis/memory) and number of results.

## Troubleshooting

- “Docs haven’t updated”
  - The site publishes from `gh-pages` via mike. Re‑deploy: `mike deploy latest -u -p && mike set-default latest -p`.
  - Hard refresh the browser to bypass CDN caching.
- “LLM calls failing”
  - Confirm `OPENAI_API_KEY` is present and not expired.
  - Check `/gateway/allowlist/effective?plugin_id=ai-core` shows OpenAI allowlist.
  - Review `/gateway/stats` and audit logs.
- “Index skipped files unexpectedly”
  - Inspect `.ragignore` and `.gitignore` matches (anchored vs glob). Remove overly broad patterns.

## Roadmap

- Config v4 secrets for provider keys + traited ingestion rules per path.
- LangGraph agent pipeline with RAG retriever + HTTP/Storage tools.
- Expose RAG query as a full MCP tool bundle (SSE/HTTP) with schemas.
