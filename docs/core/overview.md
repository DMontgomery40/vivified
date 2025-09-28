# Core Overview

The Vivified Core is a FastAPI service that mediates all plugin interactions.

Endpoints (Phase 1)

- `GET /health` — Health check
- `POST /plugins/register` — Register a plugin with a manifest
- `GET /plugins` — List registered plugins
- `POST /plugins/{plugin_id}/heartbeat` — Update plugin heartbeat

Key modules

- `core/main.py` — FastAPI app and REST endpoints
- `core/plugin_manager/registry.py` — In-memory plugin registry with JWT issuance
- `core/plugin_interface.py` — Base plugin contracts
- `core/proto/canonical_models.proto` — Canonical data models (proto)

Security and compliance

- Phase 1 keeps registration open; later phases add authN/Z checks
- Logging avoids PII/PHI and includes a trace id
