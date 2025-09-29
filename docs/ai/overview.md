# Vivified AI Studio — Internal RAG + Agent

This document describes the internal AI features wired into the Admin Console.
It is intended for internal development. Customer docs will be carved later.

## What’s included

- RAG Service (Redis-backed, memory fallback) that indexes local `docs/` and `internal-plans/`.
- Admin API endpoints under `/admin/ai/*` to train, query, and run a stub agent.
- Admin UI panel “AI Studio” under Tools.
- Optional auto-train on startup with `AI_AUTO_TRAIN=true`.

No external LLM calls are required for basic operation. All data stays local.

## Admin API

- `GET /admin/ai/status` — returns `{ docs_indexed, last_trained_ts }` (admin trait)
- `POST /admin/ai/train` — body `{ sources?: string[] }`, returns `{ ok, indexed, total }` (admin trait)
- `POST /admin/ai/query` — body `{ q: string }`, returns top hits (admin/viewer)
- `POST /admin/ai/agent/run` — body `{ prompt: string }`, returns `{ result }` (admin)

All calls are audited through FastAPI logging; no PHI is logged.

## Admin UI

- Tools → AI Studio: train RAG and run queries from the console.
- Uses your current API key. DEV_MODE supports `bootstrap_admin_only` for quick testing.

## Redis

If `REDIS_URL` is set, the RAG service uses Redis structures:

- `ai:rag:docs` — set of doc IDs
- `ai:rag:doc:{id}:title`, `:path`, `:content`
- `ai:rag:token:{token}` — set of doc IDs for inverted index

If Redis is unavailable, an in-memory index is used.

## Auto-train

Set `AI_AUTO_TRAIN=true` in the environment to index the entire repository (`.`) at startup. Indexing respects `.ragignore` (first) and `.gitignore` (second).

## TBAC (Trait-Based Access Control)

The RAG index and queries honor user traits. Each indexed document carries metadata with `required_traits` (defaults to empty) and `classification` (defaults to `internal`). At query time, only documents whose `required_traits` are a subset of the user’s traits are considered.

This allows HIPAA-safe usage patterns where the assistant can answer aggregate questions without ever seeing PII fields. For example, you could index randomized patient IDs and diagnosis/outcome fields behind a trait like `analytics_viewer`, while excluding any PII traits entirely. The assistant’s visibility is governed by the same trait system as users.

The current codebase indexing defaults to `required_traits=[]`. Data sources that include sensitive fields should be indexed with appropriate `required_traits` (future enhancement wires this via ingestion policies/config).

## MCP HTTP Tool (preview)

- `POST /mcp/http/tools/rag/query` — body `{ q: string }` returns `{ items }`, gated by user traits (admin or viewer).
- Health endpoints: `/mcp/sse/health`, `/mcp/http/health`.

## CLI helper

`tools/scripts/rag_train.py` calls the API to trigger training.

Example:

```
AI_API_URL=http://localhost:8000 API_KEY=bootstrap_admin_only \
  python tools/scripts/rag_train.py --sources docs internal-plans
```

## Next steps (internal roadmap)

- Wire optional LangGraph pipeline and tool calling (feature flag controlled).
- Add connector config for OpenAI/Anthropic via ConfigService and proxy allowlist.
- Expand Admin UI to visualize vector store stats and per-source toggles.
- MCP integration: expose RAG query as an MCP tool over SSE/HTTP transports.
