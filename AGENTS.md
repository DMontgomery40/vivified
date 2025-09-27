# AGENTS.md - Vivified Platform Development Guidelines

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