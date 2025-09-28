<div class='grid cards' markdown>

-   :material-api:{ .lg .middle } **Admin API**
    
    ---
    Role-based endpoints for user, plugin, config, and audit management

-   :material-link:{ .lg .middle } **Stable Contracts**
    
    ---
    Versioned REST endpoints with OpenAPI definitions

-   :material-security:{ .lg .middle } **Auth & RBAC**
    
    ---
    OAuth2 / JWT with scoped claims for fine-grained access

</div>

!!! note "Versioned APIs"
    Use the versioned prefix (/v1/) in client integration to avoid breaking changes.

!!! tip "Use SDKs"
    Prefer the provided Python/Node SDKs which handle retries, auth, and logging.

!!! warning "Audit Sensitive Calls"
    Mutating endpoints produce audit events. Ensure proper RBAC before calling.

## Common Endpoints

| Resource | Method | Path | Description |
|----------|--------|------|-------------|
| Users | GET | /api/v1/users | List users with filters |
| Users | POST | /api/v1/users | Create a user |
| Plugins | POST | /api/v1/plugins | Register a plugin |
| Storage | POST | /storage/objects | Upload encrypted object |


## Examples

=== "Python"
    ```python
    # (1) Create a user
    import requests
    payload = {'username':'alice','email':'alice@example.com','roles':['admin']}
    r = requests.post('https://localhost:8443/api/v1/users', json=payload, headers={'Authorization':'Bearer TOKEN'})
    print(r.json())
    ```

=== "Node.js"
    ```javascript
    // (1) Create user via fetch
    const fetch = require('node-fetch')
    fetch('https://localhost:8443/api/v1/users', { method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer TOKEN'}, body: JSON.stringify(payload) })
      .then(r=>r.json()).then(console.log)
    ```

=== "curl"
    ```bash
    # (1) curl create user
    curl -X POST https://localhost:8443/api/v1/users -H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json' -d '{"username":"alice","email":"alice@example.com","roles":["admin"]}'
    ```

1. Creating a user records an audit event and may provision SSO mappings


## Auth & Roles

- OAuth2 / JWT bearer tokens
- RBAC scopes like users:create, plugins:manage, audit:read

| Scope | Purpose |
|-------|---------|
| users:read | Read user metadata |
| users:create | Create users |
| plugins:manage | Install/uninstall plugins |


## Error Handling

- 4xx: client errors (validation, unauthorized)
- 5xx: server errors (retryable depending on idempotency)


## SDK Usage

- Use provided SDK for retries and auth token refresh
- Use ++ctrl+c++ to copy tokens from Admin Console token modal

??? note "Pagination"
    Endpoints use cursor-based pagination; prefer streaming for large datasets.
