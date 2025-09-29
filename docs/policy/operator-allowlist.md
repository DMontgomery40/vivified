# Operator Allowlist

Operator lane calls are synchronous RPC from one plugin (or Core) to another, brokered by Core. The operator allowlist defines which operations a caller may invoke on a target.

## Keys

Config key pattern: `operator.allow.<caller->target>` with a JSON array of operation names.

Example:

```
operator.allow.ai-core->rag-db = ["rag_index", "rag_query"]
```

## Admin API

- GET `/admin/operator/allowlist?caller=ai-core&target=rag-db` → `{ operations: [...] }`
- PUT `/admin/operator/allowlist` body `{ caller, target, operations: [] }` → `{ ok: true }`

## UI

- Admin Console → Plugin Dev Guide → “Generate Operator Allowlist” to seed operations from a manifest.
- Admin Console → Operator Policy → “Auto‑generate” to seed operations for a caller→target pair from the target manifest endpoints.
- Optional dev toggle: enable `operator.allow.dev_all` in Config (Admin Console) for development to allow manifest‑declared operations without explicit allowlist.

## Enforcement

- Core checks the allowlist in `/gateway/{target}/{operation}` before forwarding.
- Policy engine may also evaluate request context; all calls are audited.

## API

- GET `/admin/operator/allowlist?caller=<id>&target=<id>` → `{ caller, target, operations: [] }`
- PUT `/admin/operator/allowlist` with `{ caller, target, operations: [] }`
- POST `/admin/operator/allowlist/auto-generate` with `{ caller, target, merge?: true }` → seeds from target manifest
