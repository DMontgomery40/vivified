<div class='grid cards' markdown>

-   :material-security:{ .lg .middle } **Security & Compliance**
    
    ---
    HIPAA-first controls, encryption, RBAC, and auditability

-   :material-shield-check:{ .lg .middle } **Zero Trust**
    
    ---
    No implicit trust between services; mutual TLS or JWT

-   :material-lock-open:{ .lg .middle } **Access Controls**
    
    ---
    Fine-grained RBAC, JIT access, and key management

</div>

!!! warning "PHI Handling"
    PHI requires special handling: encryption, audit, least privilege.

!!! danger "Data Exfiltration"
    Enforce domain allowlists, egress filtering, and DLP for attachments.

!!! tip "Rotation & Key Vault"
    Use a central Key Vault and rotate envelope keys on schedule.

## High-level Policies

| Policy | Summary | Enforced By | HIPAA |
|--------|---------|-------------|-------|
| RBAC | Role-based access controls | Admin API | Compliant |
| Encryption | AES-256 at rest, TLS in transit | Storage/Gateway | Compliant |
| Audit | Immutable logs, 7-year retention | Audit Service | Compliant |


## Authentication

- OAuth2 / JWT
- Short-lived tokens recommended
- Mutual TLS between core services

## Example: Verify JWT in Python

=== "Python"
    ```python
    # (1) Simple JWT verification example
    import jwt
    token = 'eyJ...'
    payload = jwt.decode(token, 'PUBLIC_KEY', algorithms=['RS256'])
    print(payload)
    ```

=== "Node.js"
    ```javascript
    // (1) Node JWT verify
    const jwt = require('jsonwebtoken')
    const payload = jwt.verify(token, 'PUBLIC_KEY')
    console.log(payload)
    ```

=== "curl"
    ```bash
    # (1) Token introspection (if supported)
    curl -X POST https://auth.example.com/introspect -d "token=$TOKEN" -u client:secret
    ```

1. Always validate signature and claims (aud, iss, exp)


## Incident Response

- Revoke compromised tokens and rotate keys
- Notify compliance team and preserve audit logs
- Conduct forensic analysis in isolated environment

| Step | Action |
|------|--------|
| Detection | Alert from monitoring |
| Containment | Revoke tokens, block accounts |
| Recovery | Restore from backups |
| Post-mortem | Audit + improve controls |


??? note "Audit Evidence"
    Keep evidence chain: logs, config snapshots, and access lists for compliance reviews.
