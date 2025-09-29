# Plugins Overview

Plugins are isolated services that implement features and integrations. In Phase 1, we ship a minimal `user_management` plugin to exercise the interface.

User Management plugin

- Registers itself with core on startup
- Exposes `/health` and a placeholder `/api/users/{user_id}` endpoint

Manifest fields (subset)

- `id`, `name`, `version` — Basic identity
- `contracts` — Capabilities implemented (e.g., `IdentityPlugin`)
- `traits` — Security and behavior hints (e.g., `handles_pii`)
- `security` and `compliance` — HIPAA-related metadata

See `plugins/user_management/main.py` for a concrete example.


## Next

- Read the full Plugin System guide: [Plugin System](plugin-system.md)
