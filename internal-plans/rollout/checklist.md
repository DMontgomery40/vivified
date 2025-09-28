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


## P0 — Policy/auth decorators and tracing
- [ ] Provide working examples for `@require_auth`, `@audit_log`, `@rate_limit` used in Admin API
- [ ] Ensure end-to-end `trace_id` propagation across all three lanes and logs

## P0 — NATS authentication and wiring
- [ ] Add NATS config with users/passwords; mount config in compose/k8s
- [ ] Update SDK/core envs to use `NATS_CORE_USER/PASSWORD` and `NATS_PLUGIN_USER/PASSWORD`
- [ ] Add smoke test in Phase 3/4 to verify NATS auth is required

## P0 — Rate limiting and session controls
- [ ] Implement/administer rate limits on all admin endpoints via middleware
- [ ] Verify session timeout ≤ 30m and JWT expiry 15m with tests

## P0 — Proxy allowlist enforcement
- [ ] Enforce `allowed_domains` for each plugin in Proxy; add tests (deny internal, allow listed)
- [ ] Add SSRF protections (no redirects to internal IPs; re-resolve after redirects)

## P0 — CI pipeline parity and stability
- [ ] Update CI to build Admin UI (Vite) with Node 20 and cache node_modules
- [ ] Add hadolint and semgrep stages; fail on high/critical issues
- [ ] Add secret scanning (gitleaks) stage

## P1 — Logging and masking improvements
- [ ] Provide JSON logging option and `LoggerAdapter` with default `trace_id`
- [ ] Add centralized masking utility; unit tests to prove no PHI appears in logs

## P1 — Monitoring & alerting artifacts
- [ ] Provide Grafana dashboard JSONs (security, latency, events, RPC, proxy)
- [ ] Verify Alertmanager routes/severities per security/compliance needs

## P1 — Admin UI hardening
- [ ] Set CSP headers at server; keep meta tag as fallback
- [ ] Add strict `X-Frame-Options`/`Referrer-Policy`/`X-Content-Type-Options` headers

## P1 — Storage & sandboxing parity
- [ ] Document Storage Service abstraction (per overview) or mark as deferred with rationale
- [ ] Enforce plugin container resource limits (CPU/mem) in compose and k8s

## P2 — Phase runbooks expansion
- [ ] Phase 5: SDKs (Python/Node/Go), CLI (`vivified create-plugin`, `validate-manifest`)
- [ ] Phase 6: Reference plugin Email Gateway (SMTP via config; proxy demo)
- [ ] Phase 7: Reference plugin User Management (profiles; canonical events)
- [ ] Phase 8: Performance/scalability (load tests, SLO validation, HPA)
- [ ] Phase 9: Rollout/canary and operational runbook

## P2 — Documentation and compliance mapping
- [ ] Update Admin Console import runbook to Vite-only references
- [ ] Expand HIPAA control mappings with concrete test evidence paths
- [ ] Add UI Parity Checklist to all new features (per UI Parity Mandate)


