# Vivified Rollout Fixes Checklist

This checklist tracks the concrete fixes to align runbooks with the Vivified Full Overview and to remove dead ends/inconsistencies.

## P0 — Make the three lanes operable and consistent
- [ ] Wire NATS auth into runtime (compose/k8s) and SDKs (defer after core fixes)
- [x] PolicyEngine: add `evaluate_data_access(consumer_traits, data_traits)` used by Event Bus
- [x] RPC Gateway: add missing imports and stub helper methods to avoid dead code paths
- [x] PluginRegistry: add `get_plugin(plugin_id)` and `list_plugins(status)` lookups

## P0 — Admin UI toolchain unification
- [x] Standardize Admin UI to Vite (replace CRA `react-scripts` in Phase 4 package.json)

## P0 — Compliance/K8s correctness
- [x] Replace deprecated PodSecurityPolicy with Pod Security Admission (namespace labels)
- [x] Replace invalid Postgres TDE check with realistic encryption checks (SSL in-flight + pgcrypto)

## P0 — Admin API correctness
- [x] Add `get_all_config` to ConfigurationService example
- [x] Add `mask_sensitive_config` helper used by Admin API

## P1 — Logging robustness (planned)
- [ ] Switch examples to JSON logs or `LoggerAdapter` with default `trace_id`

## P1 — Proxy SSRF/egress hardening (planned)
- [ ] Enforce deny-all plugin egress except proxy; add redirect/IP re-resolution controls

## P1 — UI Parity endpoints (planned)
- [ ] Add `/admin/ui-config` and `/admin/user/traits` examples to Admin API

## P2 — Documentation/runbooks completeness
- [ ] Author missing Phase 5–9 runbooks (SDKs, CLI, reference plugins, perf/chaos, rollout)

Notes
- Keep HIPAA/Zero-Trust guarantees front-and-center for every change.
- Do not allow PHI/PII in logs; redact/mask in all examples.

