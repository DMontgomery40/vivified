Admin Console Import Runbook

Purpose: Safely import and rebrand the Faxbot Admin Console into the Vivified Admin Console while enforcing HIPAA compliance, Zero Trust, and CI/CD gating. This runbook formalizes steps, checklists, and controls required to ship the Admin Console as part of Vivified’s Core UI.

Scope: Frontend import and integration to existing Core HTTP APIs via the gateway. No direct plugin-to-plugin calls. All calls must route through the Core gateway and respect the Three-Lane model (Operator lane for synchronous RPC, Canonical lane for events, no direct Proxy lane usage from the UI).

Risk: Medium (UI surface expansion). Backout within minutes by reverting the UI deploy/version and feature flagging.

Data Classification: Admin Console may expose metadata about users, plugins, policies, and audit entries. Treat all such data as confidential; do not display PHI/PII. UI must avoid logging PHI/PII. Use identifiers only in logs.

Release Artifact: Vivified Admin Console (rebranded UI) with:
- Brand Settings page (tenant-aware, white-label; logo upload + theme colors)
- Trait-aware ThemeProvider (HIPAA vs business UX)
- Canonical Schema Registry page (manage canonical versions)
- Plugins, Config, Users/Traits, Audit views wired to Core gateway

Pre-Flight Checklist (must be fully checked before PR merge)
- [ ] Security impact assessment completed (see Security section)
- [ ] PHI/PII handling reviewed (no PHI/PII rendered or logged)
- [ ] Threat model updated for UI attack surface
- [ ] MFA enforced for admin login flows (Core auth)
- [ ] Rate limits verified on all UI-backed endpoints
- [ ] Session timeout ≤ 30 minutes inactivity (Core auth)
- [ ] All traffic via Core gateway (no direct plugin endpoints)
- [ ] Lint, security scan, and tests passed in CI
- [ ] Documentation updated (this runbook + user docs as relevant)

CI/CD Gates (mirror AGENTS.md pipeline)
- Lint: eslint/prettier (UI) if present, black/flake8/mypy (server)
- Security scan: dependency scan + semgrep/bandit (server)
- Test: unit + integration, coverage ≥ 80%
- Compliance check: HIPAA controls validation (Core), PHI handling verification
- Deploy staging → security validation → production

Security Requirements (must hold end-to-end)
- Zero Trust: no implicit trust between UI and services; all calls authenticated via JWT or session cookie, through Core gateway.
- Authentication/Authorization: MFA for admins; short-lived JWTs (~15 min); service keys for service-to-service where applicable.
- Audit Everything: all admin actions must generate audit events; ensure Core endpoints invoked by UI are decorated with audit logging and input validation.
- Data Protection: TLS 1.3+; encryption at rest; no PHI/PII in UI logs; redact values shown in toasts/errors; use trace_id in structured logs.
- Rate limiting: enforced on all admin endpoints.

Deployment Strategy
- Feature flag new Admin Console routes (e.g., ui.admin_console.enabled) default off.
- Ship to staging, validate security and compliance gates, then enable flag for internal users only. Gradually expand to all admins.
- Keep backout ready: toggling off the flag restores the previous UI surface.

Implementation Plan

1) Prerequisites
- Tools: git, node, npm, ripgrep (rg).
- Environments: development and staging Core reachable via gateway (e.g., http://localhost:8000 for dev).
- Access: admin account with MFA to validate operator flows.

2) Import and Rebrand Admin UI (formalized)
- Create workspace and copy the Faxbot Admin UI as the starting point for Vivified Admin Console.
- Rebrand names, strings, colors, favicons, and assets from Faxbot → Vivified.
- Replace any direct API wiring with a single adapter that talks to the Core gateway.

API Adapter (example)
Note: This example enforces a single base URL, timeout, and a minimal surface aligned with Core.

import axios from 'axios'
const CORE = import.meta.env.VITE_CORE_URL
export const http = axios.create({ baseURL: CORE, timeout: 20000 })
export const getSession = () => http.get('/auth/me').then(r=>r.data)
export const login      = (u,p,mfa_code) => http.post('/auth/login',{username:u,password:p,mfa_code}).then(r=>r.data)
export const listPlugins   = () => http.get('/admin/plugins').then(r=>r.data)
export const enablePlugin  = (id) => http.post(`/admin/plugins/${id}/enable`).then(r=>r.data)
export const disablePlugin = (id,reason='') => http.post(`/admin/plugins/${id}/disable`,{reason}).then(r=>r.data)
export const getEffectiveConfig = (params={}) => http.get('/admin/config',{params}).then(r=>r.data)
export const setConfig          = (payload)    => http.put('/admin/config',payload).then(r=>r.data)
export const listTraits = () => http.get('/admin/traits').then(r=>r.data)
export const listUsers  = (params={}) => http.get('/admin/users',{params}).then(r=>r.data)
export const getAudit   = (params={}) => http.get('/admin/audit',{params}).then(r=>r.data)
export const upsertSchema   = (payload) => http.post('/schemas', payload).then(r=>r.data)
export const activateSchema = (name,major,minor,patch) => http.post('/schemas/activate',{name,major,minor,patch}).then(r=>r.data)
export const listSchemas    = (name) => http.get(`/schemas/${encodeURIComponent(name)}`).then(r=>r.data)
export const getActive      = (name,major) => http.get(`/schemas/${encodeURIComponent(name)}/active/${major}`).then(r=>r.data)

3) Brand Settings Page
- Purpose: GUI-first white-labeling. Stores settings under ui.brand.* via Core config service.
- Security: Treat uploaded assets as untrusted input; validate file types in the backend; do not embed secrets in config.
- Privacy: Do not store PHI in brand config; logo is non-sensitive, mark as non-PHI.

Example UI logic (abridged)

import { useEffect, useState } from 'react'
import { getEffectiveConfig, setConfig } from '../lib/api'

export default function BrandSettings(){
  const [title,setTitle] = useState('Vivified')
  const [primary,setPrimary] = useState('#6D28D9')
  const [accent,setAccent] = useState('#22D3EE')
  const [logoData,setLogoData] = useState(null)
  useEffect(()=>{(async ()=>{
    const cfg = await getEffectiveConfig({})
    const b = cfg?.['ui.brand'] || {}
    setTitle(b.title || 'Vivified'); setPrimary(b.primary || '#6D28D9'); setAccent(b.accent || '#22D3EE'); setLogoData(b.logoData || null)
  })()},[])
  const save = async ()=>{ await setConfig({ key:'ui.brand', value:{ title, primary, accent, logoData }, is_sensitive:false, reason:'branding update' }) }
  return null /* render inputs + preview + save button */
}

4) Trait-Aware Theme Provider
- HIPAA users see clinical theme (conservative colors, clear contrasts), non-HIPAA see business theme.
- Derive traits from /auth/me. Do not assume HIPAA without verifying user traits.

Example ThemeProvider (abridged)

import React, { createContext, useContext, useMemo } from 'react'
const ThemeCtx = createContext({ mode:'business', colors:{ primary:'#6D28D9', accent:'#22D3EE' }})
export function useThemeCtx(){ return useContext(ThemeCtx) }
export default function ThemeProvider({ children, userTraits=[], brand={} }){
  const isHIPAA = userTraits.includes('hipaa_compliant')
  const theme = useMemo(()=>{ const primary = brand.primary || '#6D28D9'; const accent = brand.accent || '#22D3EE';
    const palette = isHIPAA ? { primary:'#1E40AF', accent:'#22D3EE', bg:'#F8FAFF', text:'#0F172A' } : { primary, accent, bg:'#F8FAFC', text:'#0F172A' }
    document.documentElement.style.setProperty('--color-primary', palette.primary)
    document.documentElement.style.setProperty('--color-accent', palette.accent)
    return { mode: isHIPAA ? 'hipaa' : 'business', colors: palette }
  }, [isHIPAA, brand.primary, brand.accent])
  return <ThemeCtx.Provider value={theme}>{children}</ThemeCtx.Provider>
}

5) Canonical Schema Registry Page
- Capabilities: list versions, upsert versions, activate major versions.
- Governance: Only admin users with required traits/roles can modify schemas. All actions audited.

6) Wiring and Navigation
- Add routes for Brand Settings (/brand) and Schemas (/schemas). Gate visibility with permissions.
- Load ui.brand on boot (via getEffectiveConfig) and pass to ThemeProvider.

Security and Compliance
- Authentication: Admin UI relies on Core identity service. Require MFA for admin logins.
- Authorization: Enforce RBAC/ABAC in Core; UI hides controls the user is not authorized to invoke.
- Audit Logging: Ensure Core endpoints invoked by Admin UI are decorated with audit logging; include trace_id in all calls.
- Input Validation: All UI inputs must be validated server-side; UI-level validation is a convenience only.
- Secrets Management: No secrets in UI repo. Use environment variables for public config only; sensitive values remain server-side.
- Logging: No PHI/PII in client logs; avoid logging request/response bodies; surface redacted errors.
- Rate Limiting: Core gateway rate limits all admin endpoints; verify limits active in staging.
- Data Retention: Admin UI does not store data locally; respect Core’s retention policies.

HIPAA Controls Mapping (selected)
- 164.312(a) Access Control: MFA, unique user IDs, session timeout, RBAC.
- 164.312(e) Transmission Security: TLS 1.3+, no mixed content.
- 164.312(b) Audit Controls: Audit every admin action; retain logs 7 years; no PHI in logs.
- 164.308(a) Administrative: Security awareness, least privilege, incident response readiness.

Testing Strategy (must be demonstrably executed)
- Unit tests: UI utils and adapters where applicable; server coverage ≥ 80% (CI gate).
- Integration tests: End-to-end flows for login (MFA), plugin toggle, config write, schema upsert/activate.
- Security tests: AuthN/AuthZ checks, rate limit enforcement, input validation, injection attempts.
- Compliance tests: Verify no PHI in audit entries, verify audit completeness for admin actions.
- Performance tests: UI renders within SLO; API p50/p99 within targets in staging.
- Chaos tests: Validate UI behavior under gateway timeouts and partial failures (fail safe patterns).

Rollout Plan
- Pre-release: Complete security scan, compliance validation, performance benchmarks; docs updated.
- Staging: Deploy behind feature flag; run full test suite and manual validation using an MFA-enabled admin.
- Canary: Enable for small set of admin users; monitor metrics and error rates; validate audit trails.
- Production: Gradually roll out; keep backout plan ready (flag off, revert asset version).

Backout Procedure
- Disable ui.admin_console.enabled flag to immediately hide new UI surface.
- Revert to previous UI assets/version in the CDN or deployment artifact store.
- Invalidate caches; verify old console functionality.
- File incident ticket with context if backout due to security/compliance issues.

Monitoring and Alerts
- Metrics: request rate/latency, error rate by endpoint, auth failures, policy violations.
- Alerts: PHI access anomalies, multiple auth failures, service degradation, certificate expiry.
- Dashboards: Admin UI/API gateway dashboards filtered by admin endpoints.

PR Requirements (paste into PR template and complete)
- [ ] Security impact assessment
- [ ] PHI/PII handling changes documented; no PHI in logs
- [ ] Performance impact evaluated (SLO targets considered)
- [ ] Breaking changes noted; migration plan included
- [ ] Migration requirements (feature flags, config keys)
- [ ] Tests added/updated; coverage ≥ 80%
- [ ] Documentation updated (runbook + user docs)

Local Validation (before opening PR)
- Python server checks (mirror CI):
  - pip install black flake8 mypy; run: black --check core/; flake8 core/; mypy core/
  - pip install -r core/requirements.txt pytest pytest-cov; run: pytest --cov=core
- Docs: mkdocs build --strict (site includes docs/ content; this runbook lives outside and does not affect build)
- UI: npm run build (if UI repo present) and validate lint if configured.

Operational Notes
- All UI → Core traffic must flow through the gateway (Operator lane). No direct plugin endpoints or cross-plugin access from UI.
- Feature gating is mandatory for new surfaces.
- Treat all uploads as untrusted; backend must validate and sanitize.
- Ensure CORS rules are least-privilege and environment-specific.

Appendix A: Minimal CSS hooks

:root { --color-primary:#6D28D9; --color-accent:#22D3EE; }
.btn-brand { background: var(--color-primary); color: #fff; }
.text-brand { color: var(--color-primary); }

Appendix B: Example Vite env

VITE_CORE_URL=http://localhost:8000

This runbook aligns with AGENTS.md security, CI/CD, and HIPAA requirements and is suitable for internal rollout and audits.

Execution Log (Automation)
- 2025-09-27: PR #2 merged into claude-test — Align lint/type checks and test env; add .flake8, mypy.ini, ensure pytest imports local core; fix mkdocs deps.
- 2025-09-27: PR #3 merged — Scaffold Admin Console under core/ui (Vite+React) with gateway API adapter.
- 2025-09-27: PR #4 merged — Add Brand Settings page wired to Core config (ui.brand).
- 2025-09-27: PR #5 merged — Add Canonical Schemas page with react-query (list/upsert/activate).
- 2025-09-27: PR #6 merged — Add ThemeProvider (HIPAA/business) and useBrand hook; wrap app root.
- 2025-09-27: PR #7 merged — Add UI build job to CI (Node 20) to build core/ui.

Notes
- All PRs targeted base branch claude-test, per instruction. No changes pushed to development or main.
- CI for Python (black/flake8/mypy/pytest) is green. Docs Check is green. New UI job builds successfully.
- Docs Autopilot push workflow intermittently fails; considered non-blocking for this rollout.
