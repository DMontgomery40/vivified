# Phase 6 — Security Implementation: Agent Prompt (one step at a time)

You are an automation agent. Implement Phase 6 end‑to‑end, following AGENTS.md, vivified_full_overview.md, and phase-6-runbook.md. After EACH step, run the CI loop before continuing.

Golden rules
- Zero Trust + Three Lanes; no direct plugin‑to‑plugin.
- HIPAA: no PHI/PII in logs; audit everything with trace_id.
- Admin Console parity (TBAC): every capability must be operable in the Admin Console; no CLI‑only surfaces. UI traits must map to user traits.
- RBAC + API keys remain enforced.
- Packaging: PEP 517/518 wheels via pyproject.toml. No eggs.

CI loop (after every step)
1) Commit (scope: security) → push → sleep 120s → check CI.
2) If errors: fix → commit → push → sleep 120s → recheck, until green.

Pre‑flight
- Python 3.11 pins per AGENTS.md; Node 20 (Vite UI); Postgres sslmode=require.

Portions (each must include Admin Console parity and smoke tests)
1) Encryption at Rest (AES‑256‑GCM; rotation; tests; UI Security→Encryption).
2) TLS 1.3+ and contexts (UI Security→TLS).
3) MFA TOTP/backup codes (UI Users→MFA).
4) RBAC roles/permissions/hierarchy (UI Roles & Permissions).
5) Data classification & redaction (UI Security→Data Classification).
6) Vulnerability scans wrappers (UI Security→Scans).
7) Incident response workflow (UI Security→Incidents).
8) Compliance: audit integrity/retention (UI Compliance→Audit).
9) TBAC/RBAC wiring: /admin/ui-config and /admin/user/traits.
10) Policy enforcement across lanes + metrics/audit (UI Security→Policy Decisions).
11) Security headers + rate limits (UI Security→Headers/Rate Limits).
12) Docs & CI jobs for scans/integrity; link from UI.

Acceptance
- CI green per portion; ≥80% coverage where applicable; no PHI/PII in logs; TLS 1.3 enforced; TBAC/RBAC effective; no egg artifacts.
