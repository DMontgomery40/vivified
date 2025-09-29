# Vivified Platform

HIPAA-conscious, plugin-first platform with an Admin Console–first mandate and a Zero Trust, three-lane communication model. Everything is trait‑aware and fully operable from the Admin Console.

Key ideas
- Three Lanes: Canonical (events), Operator (RPC), Proxy (egress). All traffic passes through Core for policy, audit, redaction, and rate limits.
- Admin Console First: No CLI‑only features. Trait‑gated surfaces; in DEV_MODE a one‑click dev login is available.
- Security: Default‑deny policy; strict allowlists for RPC operations and egress domains/paths; audit everything.

Defaults
- Database: Postgres by default for non‑test runs (`postgresql+asyncpg://…`). Tests remain on in‑memory SQLite unless `TEST_DB_URL` overrides.
- RAG (AI): Redis by default (`redis://localhost:6379/0`) with graceful fallback to in‑memory.

Quick start (Docker Compose)
```bash
docker-compose up -d
curl -s http://localhost:8080/health | jq
```

Dev environment (Python 3.11)
```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r core/requirements.txt \
  black==25.9.0 flake8==7.3.0 mypy==1.18.2 sqlalchemy==2.0.23 \
  pytest pytest-cov pytest-asyncio

export DATABASE_URL='postgresql+asyncpg://vivified:changeme@localhost:5432/vivified'
export REDIS_URL='redis://localhost:6379/0'

black --check core/ || (echo 'Run: black core/' && exit 1)
flake8 core/
mypy --config-file mypy.ini core/
PYTHONPATH=$PWD pytest -q
```

Docs
- Live: https://docs.vivified.dev
- Local preview: `make docs-serve` (or `mkdocs serve`)
- Three-Lane overview: docs/core/three-lanes.md

Admin Console (DEV)
- Served by Core; open `/admin/ui` from the Core host.
- In `DEV_MODE=true`, a visible “Sign in (Dev)” uses the bootstrap credential automatically.

Security & Compliance
- PHI/PII tagging and redaction built‑in; encryption at rest via StorageService.
- Operator SSRF guard; Proxy blocks IP literals/localhost and non‑allowlisted domains.
- Full audit trails with 7‑year retention target.

Contribution
- Branch strategy: `develop` as integration branch, feature branches `feature/VIVI-XXX-*`.
- All PRs must pass lint/type/test locally (see AGENTS.md preflight) before pushing.

License
- See repository LICENSE if present.
