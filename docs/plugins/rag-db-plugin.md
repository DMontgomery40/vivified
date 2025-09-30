# RAG Database Plugin (Operator Backend)

This guide defines a minimal operator‑lane contract for a RAG storage/search plugin. Use it to back Vivified’s semantic search with your own database (e.g., Postgres + pgvector, Elastic, Milvus).

## Why
- Enterprise control: keep embeddings and content chunks in your infra.
- Scale and latency: use native ANN/vector indexes (pgvector/FAISS/RediSearch).
- TBAC: enforce trait filters at the data tier.

## Contract (Operations)

Expose these operations via your plugin and declare them in `manifest.endpoints`:

- `rag_index` → `POST /rag/index`
  - Request (Core → Plugin):
    ```json
    {
      "id": "docBase:chunk",
      "title": "path/to/file#chunkN",
      "path": "abs/or/relative/path",
      "content": "chunk text",
      "required_traits": ["..."],
      "classification": ["internal"],
      "vector": [0.1, 0.2, ...]  // optional
    }
    ```
  - Response: `{ "ok": true }`

- `rag_query` → `POST /rag/query`
  - Request (Core → Plugin):
    ```json
    { "q": "question", "top_k": 5, "user_traits": ["..."] }
    ```
  - Response:
    ```json
    {
      "items": [
        {"id":"...","title":"...","path":"path/to/file#chunk","score":0.83}
      ]
    }
    ```

Core calls these via the operator lane:

```
POST /gateway/{plugin_id}/rag_index { caller_plugin: "ai-core", payload: {...} }
POST /gateway/{plugin_id}/rag_query { caller_plugin: "ai-core", payload: {...} }
```

## Implementation Outline

- Storage
  - `documents(id PRIMARY KEY, title, path, required_traits JSONB, classification JSONB)`
  - `chunks(doc_id, chunk_no, content, vector VECTOR(1536))` (pgvector) + ANN index
- Ingest (rag_index)
  - Upsert doc metadata
  - Insert chunk with embedding
- Query (rag_query)
  - Compute embedding for `q` or accept `vector` if you run your own embedder
  - `SELECT ... ORDER BY vector <-> $qvec LIMIT $top_k`
  - Filter by TBAC: `WHERE required_traits ⊆ user_traits`

## Wiring Steps

1. Build plugin container listening on `:8080` with endpoints above.
2. Manifest `endpoints: { "rag_index": "/rag/index", "rag_query": "/rag/query" }` (plus optional `host`/`port`).
3. Register plugin: Admin Console → Plugins → Register.
4. Set operator allowlist: `PUT /admin/operator/allowlist { caller: "ai-core", target: "your-plugin-id", operations: ["rag_index","rag_query"] }` (UI: Plugin Dev Guide → Generate Operator Allowlist).
5. In Admin Console → AI Studio → Ingestion Rules → RAG Settings: set `Backend=Plugin` and `Plugin ID` to your plugin id.
6. Train RAG (AI Studio) and run queries.

## Security and Compliance
- No PHI/PII in logs; store doc previews only if compliant.
- Encrypt at rest and enforce row‑level filters if multi‑tenant.
- Audit all operator calls (Core already emits `operator_call`).

## Troubleshooting
- 403 on `/gateway/...` → missing operator allowlist. Add operations for caller `ai-core` → your plugin.
- Zero results → verify embeddings, confirm TBAC filters, test with broad traits.
- Latency spikes → add ANN index, batch index, tune chunk size/overlap.

