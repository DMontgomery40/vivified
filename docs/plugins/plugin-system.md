# Vivified Plugin System

This guide explains how Vivified plugins work, how they communicate with core, the manifest contract and validation rules, lifecycle and health monitoring, and a concrete example (User Management / IdentityPlugin).

> Security first: All plugin interactions are authenticated, authorized, audited, and mediated by core. No plugin may bypass core.

## What Are Plugins?

Vivified plugins are modular, isolated services that add features or integrations to the platform. Each plugin runs as its own service (typically a container) and communicates with the core over defined interfaces (HTTP/REST or gRPC). Isolation means:

- Plugins can be written in any language/stack that speaks the contract.
- Faulty or malicious plugins are contained; core remains up.
- Core mediates all interactions to enforce policy, security, and compliance.

Benefits:

- Extensibility: add features by adding a plugin, not changing core.
- Isolation & Security: sandboxed execution; strict mediation and audit.
- Polyglot Development: Python, Node.js, Go, etc. supported via standard protocols.
- Modularity: many capabilities (identity, notifications, storage) are plugins; deploy only what you need.

## Communication Model (Three Lanes)

All plugin-to-plugin communication is mediated by core. No direct calls.

- Canonical Event Lane: publish/subscribe via normalized events on the event bus (e.g., NATS). Example: HR publishes `UserCreated`; Accounting subscribes and reacts using the canonical User model.
- Operator API Lane: request/response via core’s API gateway. Example: a plugin requests `GET /identity/users/{id}` through core; policy and authz enforced before routing to the target plugin.
- Proxy Lane: tightly controlled egress to external services via core proxy. Only allowlisted domains are reachable; responses are filtered and everything is audited. Can be disabled entirely.

Note: In Phase 1, the event bus and a basic gateway exist; richer multi‑lane policies expand as the system grows.

## Plugin Manifest & Contract

Every plugin declares a manifest when registering with core. The manifest is the contract: it identifies the plugin, its interfaces, traits, security/compliance posture, and optional health/resources.

Required/optional fields:

- `id` (required): unique, lowercase letters/numbers/hyphens only. Example: `"user-management"`.
- `name` (required): human‑readable display name.
- `version` (required): semantic version (MAJOR.MINOR.PATCH), e.g. `"1.0.0"`.
- `description` (recommended): short summary of functionality.
- `contracts` (required): list of interface roles, e.g. `CommunicationPlugin`, `StoragePlugin`, `IdentityPlugin`. May include multiple.
- `traits` (required ≥1): capability/security/compliance flags used by policy and UI (e.g., `handles_pii`, `handles_phi`, `audit_required`, `external_service`). Reserved/forbidden traits such as `admin`, `root`, `system` are rejected.
- `dependencies` (optional): list of other plugin IDs this plugin requires.
- `allowed_domains` (optional): external hostnames permitted for proxy egress. Required if `external_service` trait is present. Blocklists and format validation apply.
- `endpoints` (optional): name → path mapping for exposed routes (health, APIs, webhooks). Informational and used for routing conventions.
- `security` (object, required):
  - `authentication_required` (required, must be true): all real plugin endpoints require auth.
  - `data_classification` (required, non‑empty): any of `public`, `internal`, `confidential`, `pii`, `phi`.
- `compliance` (object, required for sensitive data):
  - `hipaa_controls` (list): required if handling PHI; validated format (e.g., `"164.312(a)"`).
  - `audit_level` (string): `none|basic|detailed|complete`.
- `health_check` (optional): e.g., `{ "type": "http", "port": 8000, "path": "/health" }` enables core polling.
- `resources` (optional): `{ "memory_limit": MB, "cpu_limit": cores }` with sane ranges (memory: 64–8192 MB, CPU: 0.1–8.0).

### Example Manifest (User Management / IdentityPlugin)

```json
{
  "id": "user-management",
  "name": "User Management Plugin",
  "version": "1.0.0",
  "description": "Manages user profiles and extended attributes",
  "contracts": ["IdentityPlugin"],
  "traits": ["handles_pii", "audit_required"],
  "dependencies": [],
  "allowed_domains": [],
  "endpoints": {
    "health": "/health",
    "user_info": "/api/users/{id}"
  },
  "security": {
    "authentication_required": true,
    "data_classification": ["pii", "internal"]
  },
  "compliance": {
    "hipaa_controls": ["164.312(a)", "164.312(d)"],
    "audit_level": "detailed"
  }
}
```

## Security Validation

Core validates manifests before accepting registration.

- Authentication required: `security.authentication_required` must be true.
- Data classification required: `security.data_classification` must contain only allowed values and be non‑empty.
- Traits required: at least one trait; reserved/dangerous traits are rejected.
- Trait consistency:
  - `handles_phi` → `data_classification` must include `phi` and `compliance.hipaa_controls` must be non‑empty.
  - `handles_pii` → `data_classification` must include `pii`.
  - `external_service` → `allowed_domains` must be non‑empty.
- Network security: each `allowed_domain` must be valid, not blocked (e.g., localhost, IP literals, private ranges), and well‑formed.
- Compliance: PHI/PII require appropriate controls and audit level; retention policies may be enforced by platform policy.
- Resources: if set, limits must be within allowed ranges and numeric.
- Dependencies: must be valid plugin IDs (lowercase, hyphenated). Circular/absent may be warned or rejected depending on phase/policy.

Failures return clear 4xx errors (e.g., missing fields, invalid IDs, inconsistent traits/classification).

## Lifecycle: Registration, Enable/Disable, Unregister

- Register: plugin POSTs manifest to `POST /plugins/register`. On success, core returns a signed plugin JWT token for subsequent authenticated interactions. Core records status `registered`.
- Enable/Disable: admins (or policy) can disable a plugin (quarantine); core stops routing and/or health checks. Enabling re‑validates security and resumes participation and monitoring.
- Unregister: administrative or plugin‑initiated removal; core stops health checks and drops from the registry.

Status values typically include `registered`, `active`, `disabled`. Health is tracked separately (see below).

## Health Monitoring

Core can track health via:

- Active polling: if `health_check` is configured, core periodically pings the endpoint (HTTP 200 expected). Failure thresholds (e.g., 3 consecutive failures) mark `degraded`/`unhealthy`. Metrics from JSON responses (uptime, memory, etc.) may be recorded.
- Passive heartbeats: plugins can POST status/metrics to a heartbeat endpoint (planned); core updates `last_heartbeat` and merges status.

Health states: `healthy`, `degraded`, `unhealthy`, `unknown`.

## Interactions After Registration

- Core → Plugin: gateway routes requests based on responsibilities/endpoints; attaches auth context.
- Plugin → Core: plugin uses its JWT to call core services; operations are authorized via traits/policy and plugin state (e.g., unhealthy plugins are blocked from sensitive ops).
- Plugin → Plugin: mediated via Operator API lane (core gateway). Direct calls between plugins are not allowed.
- External calls: go through core proxy; enforced by `allowed_domains` and policy. Direct egress is discouraged and may be blocked in hardened deployments.

## Management Interfaces

- Admin Console: trait‑aware UI lists plugins, status, health; supports enable/disable and configuration. Surfaces are gated by admin/trait permissions.
- CLI/SDK: tools to validate manifests and scaffold plugins; future commands for packaging/deploy/testing.
- Documentation: each plugin should ship a doc page describing purpose, setup, and endpoints; plugin pages appear under the Plugins section with a table of contents.

## Example: User Management Plugin

A minimal IdentityPlugin demonstrating registration and endpoints:

- FastAPI service with `/health` returning `{ "status": "healthy", "plugin": "user-management" }`.
- `GET /api/users/{user_id}` returns placeholder extended profile data (e.g., department, manager, traits). Real implementations would back this with storage or core identity data.
- Registers on startup, stores issued plugin token (e.g., in `PLUGIN_TOKEN`) and uses it for authenticated interactions with core.
- Traits: `handles_pii`, `audit_required`; Classification: `["pii", "internal"]`; Compliance: `audit_level: detailed` (HIPAA control examples shown).

## Compliance & Security Notes

- HIPAA: plugins handling PHI must declare `phi` classification and list applicable `hipaa_controls`; audit must be enabled at appropriate depth.
- Zero‑trust: every cross‑plugin interaction is mediated and audited; default‑deny stance for proxy egress and dangerous operations.
- No CLI‑only features: all capabilities must be operable through the Admin Console with trait gating.

## Next Steps

- Build new plugins from this contract; validate manifests locally.
- Declare external domains explicitly and keep them minimal.
- Add `health_check` for production to enable proactive monitoring.
- Keep docs for each plugin up to date; changes in code should be reflected here to remain the source of truth.
