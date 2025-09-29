# AGENTS.md - Vivified Platform Development Guidelines

## Local CI Parity — Commit Gate (Read This First)

Status: DONE

Stop the flood of CI errors by running exactly what CI runs before every push. Use Python 3.11 and these pinned tool versions.

Required preflight (run from repo root):

```bash
# Python 3.11 environment
python3.11 -m venv .venv && . .venv/bin/activate

# Install runtime + dev tools exactly like CI
pip install -r core/requirements.txt \
  black==25.9.0 flake8==7.3.0 mypy==1.18.2 sqlalchemy==2.0.23 \
  pytest pytest-cov pytest-asyncio

# Lint/type/test — all must pass locally before pushing
black --check core/ || (echo "Run: black core/" && exit 1)
flake8 core/
mypy --config-file mypy.ini core/
PYTHONPATH=$PWD pytest -q
```

Pre-commit (recommended):

```bash
pip install pre-commit
cat > .pre-commit-config.yaml <<'YAML'
repos:
  - repo: https://github.com/psf/black
    rev: 25.9.0
    hooks: [{ id: black }]
  - repo: https://github.com/PyCQA/flake8
    rev: 7.3.0
    hooks: [{ id: flake8 }]
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.18.2
    hooks:
      - id: mypy
        additional_dependencies: ["sqlalchemy==2.0.23"]
  - repo: local
    hooks:
      - id: pytest
        name: pytest (pre-push)
        entry: bash -c 'PYTHONPATH=$PWD pytest -q'
        language: system
        pass_filenames: false
        stages: [push]
YAML
pre-commit install -t pre-commit -t pre-push
```

Optional but recommended UI parity checks (mirrors CI’s UI jobs):

```bash
# Build React Admin UIs locally (skips if node/npm not installed)
make ui-ci-local

# Or via pre-push hook automatically (already added):
#   - ui build (pre-push)
```

Agent gating (block automation until green + merged):

```bash
# Runs local parity first, then polls GitHub for PR merge (requires env)
REPO=owner/repo PR_NUMBER=123 GITHUB_TOKEN=ghp_xxx \
  python tools/scripts/agent_gate.py --wait-merge
```

- Align local preflight with CI (enforce before push)
      - Use existing pre-commit with pre-push pytest. Run:
          - pre-commit install -t pre-commit -t pre-push
      - Use make ci-local before every push. It mirrors CI jobs for Python (lint/
  type/test).
  - Add UI build smoke locally (optional but recommended)
      - Add a Makefile target that, if node is available, runs:
          - npm ci && npm run build in core/ui and core/admin_ui.
      - Example: make ui-ci-local that exits non-zero on any UI build failure.
  - Branch protection + required checks
      - In GitHub settings for development (and your long-lived branches like claude-
  test):
          - Require status checks: Lint, Test, UI Build, Admin UI Build, Docker Core
  Image.
          - Require branches to be up to date before merging.
          - Enable Merge Queue (so only the queue head is validated and merged).
          - Dismiss stale approvals on new commits.
  - Agent gating (don’t let agents move on until merge)
      - Gate the agent runner to wait for PR merge before assigning the next task:
          - Poll GitHub’s Checks/PR status; only continue when the commit is merged to
  the integration branch.
          - Alternatively: require the agent to call make ci-local and block on
      - Use durable version selectors:
          - Node: 20.x or lts/* instead of micro versions.
  - Catch missing files in UI
      - Turn on tsc --noEmit (already part of admin UI build) and ensure we never
  reference components not committed.
      - Consider a CI step to run git ls-files compared to rg import in admin UI for
  basic missing import detection.

  ''''
  


Common pitfalls that cause “THIS MANY ERRORS”:
- Optional defaults: if a parameter default is `None`, type it as `T | None` (or `Optional[T]`). mypy rejects implicit Optional.
- Mutable defaults: for dataclasses use `field(default_factory=list)` and for Pydantic use `Field(default_factory=list)`; do not use `= []` or `= None` for lists.
- SQLAlchemy typing: use `async_sessionmaker(...)` and `async with` sessions for correct async types; keep the mypy plugin enabled and ensure `sqlalchemy` is installed for linting.
- Import-time side effects: avoid making network/DB calls at import. Use in‑memory SQLite in tests (`sqlite+aiosqlite:///:memory:`) or lazy init.
- Async tests: install `pytest-asyncio` and mark async tests with `@pytest.mark.asyncio` when needed.
- Admin UI routes: mount `/admin/ui` and the SPA fallback unconditionally; do not gate route definitions on the presence of built assets. CI’s Docker job separately verifies the real UI build.
- JWT/optional deps: when providing fallbacks for optional libraries, assign them to a variable typed `Any` to avoid module vs. instance type errors.

CI mirrors these exact tools and expectations. If any of the above fails locally, fix it before pushing.

## Admin Console First — Accessibility/Dyslexia Mandate

Status: DONE

Absolutely everything must be operable from the Admin Console. No exceptions.

- No CLI‑only features. If a capability exists (config, identity/users/roles, plugins, audit, diagnostics, lanes, storage, policy, proxy, etc.), it must have a discoverable, trait‑aware path in the Admin Console in the same PR.
- DEV_MODE UX (no-credential friction): When `DEV_MODE=true`, the Admin Console must allow one‑click dev login without typing any API key or password. Use the existing backend bootstrap mapping of `bootstrap_admin_only` to admin claims and present a visible “Sign in (Dev)” button that uses it automatically.
- Documentation + tests: Every feature PR must include an Admin Console flow update and a UI test/smoke that exercises the new surface. CI should fail PRs that introduce CLI‑only features or omit UI trait mappings.
- Trait‑aware rendering: Least‑privilege by default; only show surfaces when the user has `admin` and/or specific traits (e.g., `config_manager`, `plugin_manager`, `audit_viewer`).
- Accessibility considerations: Prefer visual flows, icons, and summaries over terminal commands and long text; the project owner is dyslexic and requires the Admin UI to be the primary interface for understanding and operating the system.

UI structure conventions (must follow):
- Dashboard: static, high‑level status only; every card must link to its detailed counterpart (Diagnostics, Jobs, Inbox, Settings → Security/Providers/Storage, Keys, etc.).
- Tools → Diagnostics: health, provider status, event types, troubleshooting aids only. No tests here.
- Tools → Scripts & Tests: all smoke tests, webhook testers, and scripted helpers live here.
- Tools → Tunnels/Audit/Logs/Gateway/Messaging/Canonical/Policy/Register/Storage: each feature is trait‑gated and operates only within its tab.
- Settings: Setup wizard, core settings, configuration editor, keys, users, and MCP.

## Critical Notice
**THIS PLATFORM HANDLES PHI/PII AND MUST BE HIPAA-COMPLIANT**
Every decision, implementation, and review must consider security and compliance implications.

## Core Principles

### 1. Security-First Architecture
- **ZERO TRUST MODEL**: No component trusts any other by default
- **ALL COMMUNICATION MEDIATED**: Core intercepts and validates every cross-plugin interaction
- **AUDIT EVERYTHING**: Every action, decision, and data movement is logged
- **FAIL SAFE**: When in doubt, block the action rather than allow
- **DATA CLASSIFICATION**: All data must be tagged with sensitivity traits (PHI, PII, confidential)

### 2. Three-Lane Communication Model
All plugin interactions use exactly one of three supervised lanes:
- **Canonical Lane**: Event-driven messaging via normalized data models
- **Operator Lane**: Synchronous RPC calls through core gateway
- **Proxy Lane**: Controlled external API access with domain allowlists

### 3. Plugin Sandboxing Requirements
- Plugins run as isolated containers with no direct network access
- All external communication must go through core proxy with explicit allowlists
- No plugin can access core database or filesystem directly
- Resource limits enforced on all plugin containers
- Plugins authenticate with core using unique tokens

## Repository Structure

```
vivified/
├── core/                    # Core platform services
│   ├── proto/              # Protocol buffer definitions
│   ├── gateway/            # API gateway & RPC broker
│   ├── identity/           # Authentication & user management
│   ├── config/             # Configuration service
│   ├── policy/             # Policy engine & access control
│   ├── messaging/          # Event bus integration
│   ├── plugin_manager/     # Plugin lifecycle management
│   ├── storage/            # Storage service abstraction
│   ├── canonical/          # Canonical model engine
│   ├── audit/              # Audit logging service
│   └── ui/                 # Admin Console
├── plugins/                # Reference plugins
├── sdk/                    # Multi-language SDKs
├── tools/                  # Developer tools
├── docs/                   # Documentation
├── k8s/                    # Kubernetes manifests
├── docker-compose.yml      # Local development
├── Makefile               # Build automation
└── mkdocs.yml             # Documentation config
```

## Development Workflow

### Branch Strategy
```
main (protected)
  └── develop (integration branch)
      ├── feature/VIVI-XXX-description
      ├── bugfix/VIVI-XXX-description
      ├── security/VIVI-XXX-description (expedited review)
      └── hotfix/VIVI-XXX-description (direct to main + develop)
```

### Commit Standards
```
type(scope): subject

body (required for security changes)

VIVI-XXX
```
Types: feat, fix, security, docs, test, refactor, perf, chore
Scope: core, plugins, sdk, ui, k8s, ci

### Pull Request Rules
1. **All PRs require**:
   - Passing CI/CD pipeline
   - Security scan clearance
   - At least 2 approvals (3 for security changes)
   - Updated tests covering changes
   - Documentation updates if applicable

2. **Security PRs require**:
   - Security team review
   - Threat modeling update if architecture changes
   - Penetration test results for major changes
   - Compliance impact assessment

3. **PR Template must include**:
   - [ ] Security impact assessment
   - [ ] PHI/PII handling changes
   - [ ] Performance impact
   - [ ] Breaking changes
   - [ ] Migration requirements

### CI/CD Pipeline

```yaml
stages:
  - lint
  - security-scan
  - test
  - build
  - integration-test
  - performance-test
  - compliance-check
  - deploy-staging
  - security-validation
  - deploy-production
```

#### Required Checks
1. **Lint Stage**:
   - Python: black, flake8, mypy
   - JavaScript/TypeScript: eslint, prettier
   - Go: gofmt, golint
   - Dockerfile: hadolint

2. **Security Scan**:
   - Dependency vulnerability scan (Snyk/Dependabot)
   - Static analysis (Semgrep/SonarQube)
   - Container image scan (Trivy)
   - Secret detection (GitLeaks)

3. **Test Stage**:
   - Unit tests (minimum 80% coverage)
   - Integration tests for all API endpoints
   - Policy engine validation tests
   - Audit trail verification

4. **Compliance Check**:
   - HIPAA control validation
   - PHI handling verification
   - Encryption validation
   - Access control testing

### Security Requirements

#### Authentication & Authorization
- JWT tokens with 15-minute expiry
- API keys for service-to-service auth
- MFA required for admin accounts
- Rate limiting on all endpoints
- Session timeout after 30 minutes of inactivity

#### Data Protection
- All data encrypted at rest (AES-256)
- All communication encrypted in transit (TLS 1.3+)
- PHI data must be tagged and tracked
- No PHI/PII in logs (use identifiers only)
- Automatic data retention policies

#### Network Security
- Network segmentation between tiers
- Plugin network isolation by default
- Explicit egress allowlists only
- No direct plugin-to-plugin communication
- All traffic through core gateway

### Coding Standards

#### General Rules
1. **Input Validation**: Never trust external input
2. **Error Handling**: Fail gracefully, log comprehensively
3. **Secrets Management**: No hardcoded secrets ever
4. **Logging**: Structured logs with trace_id
5. **Testing**: Test security paths explicitly

#### Python Standards
```python
# Required for all modules handling sensitive data
from typing import Optional, Dict, Any
from core.security import sanitize, validate, audit_log

@audit_log
@validate_input
def handle_phi_data(data: Dict[str, Any]) -> Optional[Dict]:
    """All PHI handlers must be decorated with audit_log."""
    sanitized = sanitize(data)
    # Process only after sanitization
    return sanitized
```

#### Security Decorators Required
- `@audit_log` - For any PHI/PII handling
- `@validate_input` - For all external inputs
- `@require_auth` - For protected endpoints
- `@rate_limit` - For public endpoints

### Performance Requirements

#### SLO Targets
| Metric | Target | Critical |
|--------|--------|----------|
| RPC Latency (p50) | <5ms | <10ms |
| RPC Latency (p99) | <50ms | <100ms |
| Event Processing | <10ms | <25ms |
| API Response | <100ms | <200ms |
| Throughput | 1000 req/s | 500 req/s |
| Availability | 99.9% | 99.5% |

### Plugin Requirements

#### Manifest Requirements
```json
{
  "id": "plugin-uuid",
  "name": "Plugin Name",
  "version": "semver",
  "traits": ["handles_phi", "requires_encryption"],
  "security": {
    "allowed_domains": ["api.example.com"],
    "required_traits": ["admin"],
    "data_classification": ["phi", "confidential"]
  },
  "compliance": {
    "hipaa_controls": ["164.312(a)", "164.312(e)"],
    "audit_level": "detailed"
  }
}
```

#### Plugin Security Contract
1. Must authenticate with core on startup
2. Must implement health check endpoint
3. Must tag all data with classification
4. Must not store PHI locally
5. Must use core storage service for persistence

### Testing Requirements

#### Test Categories
1. **Unit Tests**: Minimum 80% coverage
2. **Integration Tests**: All communication paths
3. **Security Tests**: Auth, authz, injection
4. **Compliance Tests**: PHI handling, audit trails
5. **Performance Tests**: Load and stress testing
6. **Chaos Tests**: Failure scenario handling

#### Critical Test Scenarios
- Unauthorized access attempts
- PHI data leak prevention
- Audit trail completeness
- Plugin failure isolation
- Network partition handling
- Token expiry and refresh
- Rate limit enforcement

### Deployment Requirements

#### Container Security
```dockerfile
# Required security measures
FROM alpine:latest
RUN adduser -D -H appuser
USER appuser
COPY --chown=appuser:appuser . /app
WORKDIR /app
# No root, minimal attack surface
```

#### Kubernetes Security
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  capabilities:
    drop:
      - ALL
  readOnlyRootFilesystem: true
```

### Documentation Requirements

Every feature must include:
1. Architecture documentation
2. Security considerations
3. API documentation
4. Deployment guide
5. Troubleshooting guide
6. Compliance mapping

### Code Review Checklist

#### Security Review
- [ ] No hardcoded secrets
- [ ] Input validation present
- [ ] Output sanitization implemented
- [ ] Authentication checks in place
- [ ] Authorization verified
- [ ] Audit logging added
- [ ] Error messages don't leak info
- [ ] Rate limiting configured

#### PHI/PII Review
- [ ] Data classification tags present
- [ ] No PHI in logs
- [ ] Encryption at rest verified
- [ ] Access controls implemented
- [ ] Retention policies defined
- [ ] Audit trail complete

#### Performance Review
- [ ] Database queries optimized
- [ ] Caching implemented where appropriate
- [ ] Connection pooling configured
- [ ] Resource limits set
- [ ] Pagination implemented for lists

### Incident Response

#### Severity Levels
- **P0**: PHI breach, system down
- **P1**: Security vulnerability, data integrity
- **P2**: Performance degradation, partial outage
- **P3**: Minor bugs, documentation issues

#### Response Times
- P0: Immediate, all hands
- P1: Within 1 hour
- P2: Within 4 hours
- P3: Next business day

### Monitoring Requirements

#### Required Metrics
- Request rate and latency
- Error rate by endpoint
- Plugin health status
- Event processing rate
- Policy violations
- Authentication failures
- Resource utilization

#### Required Alerts
- PHI access anomalies
- Multiple auth failures
- Policy violations
- Service degradation
- Certificate expiry
- Resource exhaustion

### Release Process

1. **Pre-release**:
   - Security scan complete
   - Compliance validation passed
   - Performance benchmarks met
   - Documentation updated
   - Migration scripts tested

2. **Release**:
   - Tag with semantic version
   - Generate SBOM
   - Update changelog
   - Security advisory if applicable

3. **Post-release**:
   - Monitor metrics
   - Validate audit trails
   - Check compliance reports
   - Gather feedback

### Compliance Tracking

#### HIPAA Controls Implementation
Track implementation of required HIPAA controls:
- 164.308 - Administrative Safeguards
- 164.310 - Physical Safeguards
- 164.312 - Technical Safeguards

#### Audit Requirements
- All access to PHI logged
- All configuration changes logged
- All policy decisions logged
- Logs retained for 7 years
- Monthly audit reviews required

## Development Phases

Development follows 5 phases, each producing working, tested features:

1. **Phase 1**: Core Scaffolding & Plugin Interface
2. **Phase 2**: Core Services (Identity, Config, Policy)
3. **Phase 3**: Inter-Plugin Communication
4. **Phase 4**: Security & Production Features
5. **Phase 5**: Developer Experience & Ecosystem

Detailed implementation for each phase is in separate runbooks.

## Critical Success Criteria

Before ANY release:
- [ ] Zero high/critical vulnerabilities
- [ ] 100% HIPAA control coverage
- [ ] Audit trail validated
- [ ] Performance SLOs met
- [ ] Security review completed
- [ ] Compliance attestation signed

## Emergency Procedures

### PHI Breach Response
1. Immediately isolate affected systems
2. Preserve audit logs
3. Notify security team within 15 minutes
4. Begin incident documentation
5. Engage legal and compliance teams
6. Follow breach notification requirements

### Security Incident Response
1. Isolate compromised components
2. Revoke affected credentials
3. Deploy security patches
4. Conduct forensic analysis
5. Update threat model
6. Implement additional controls

## Contact Points

- Security Team: security@vivified
- Compliance: compliance@vivified
- On-Call: Use PagerDuty
- Escalation: CTO, CISO, Legal

Remember: When in doubt, prioritize security and compliance over features or performance.

## UI Parity Mandate (Admin Console)

- Everything operable via CLI MUST be operable via the Admin Console.
- All platform capabilities (config, identity/users/roles, plugins, audit, diagnostics, lanes, storage tools, etc.) must have a trait‑gated UI path.
- “No CLI‑only features” policy: If a new capability is added, include an Admin Console flow and corresponding trait mapping in the same PR.
- Trait‑aware rendering is mandatory; least‑privilege by default. Admin surfaces require `admin` and/or specific traits (e.g., `config_manager`, `plugin_manager`, `audit_viewer`).
- Development bootstrap: In DEV_MODE, the UI must be immediately accessible without terminal steps.
  - Accept the bootstrap API key `bootstrap_admin_only` as a development‑only admin credential.
  - The UI login should accept this key; the backend must map it to an admin JWT/claims when `DEV_MODE=true`.
- Accessibility & Developer Experience: The lead developer is extremely dyslexic; visual, trait‑aware UI must be first‑class. Favor visual flows over terminal commands wherever possible.

Implementation notes
- Expose `/auth/me` for trait discovery; wire the Admin Console to hide/show features accordingly.
- Provide `/admin/ui-config` and `/admin/user/traits` for feature flags and trait mapping.
- Add a “UI Parity Checklist” to all runbooks for any new feature.
- CI should fail PRs that introduce CLI‑only features without corresponding UI and trait mappings.
