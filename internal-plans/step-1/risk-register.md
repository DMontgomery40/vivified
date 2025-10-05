# Risk Register — Step 1 Vivified ↔ Integrations Bridge

| Risk | Impact | Likelihood | Mitigation | Owner |
|---|---|---:|---|---|
| Integrator service unavailable | API errors, broken UX | Medium | Healthchecks, 503 mapping, Docker restart policy; internal token; integration tests | Lead |
| OAuth token expiry/refresh | Silent failures, invalid status | Medium | Rely on module refresh; `testAuth` on status or lazy refresh; log invalidation (no secrets) | Agent A |
| OAuth CSRF/state mismatch | Security risk | Low | Vivified generates/verifies `state`; short‑lived storage; reject mismatch | Agent B |
| HIPAA mode misconfig | Non‑compliant connectors enabled | Low | Default deny; explicit allow‑list; tests for block + audit | Agent B |
| PHI/PII in logs | Compliance breach | Low | Redaction filter; allow‑list logging; snapshot/regex tests | Lead |
| Connector drift (API changes) | Breakage post‑upgrade | Medium | Pin versions; module matrix tracking; staged upgrade plan | Lead |
| Rate limits at providers | Throttling/denials | Low | Light usage in Step 1; document; backoff/queuing in future phases | Agent A |
| Identity mapping ambiguity | Cross‑tenant data leak | Low | Treat `userId` as opaque; per‑user isolation in queries; mapping only if required | Agent A |
| Error leakage (vendor names) | White‑label violation | Low | Error mapping table; sanitize messages; tests assert taxonomy | Agent B |
| Egress to unintended hosts | Security exposure | Low | Doc allow‑lists per provider; optional infra rules; log outbound hosts in dev | Lead |

Status: Reviewed and accepted at contracts freeze.

