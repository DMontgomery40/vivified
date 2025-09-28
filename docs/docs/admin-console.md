<div class='grid cards' markdown>

-   :material-dashboard:{ .lg .middle } **Admin Console**
    
    ---
    Central UI for management: users, plugins, configs, and audits

-   :material-settings:{ .lg .middle } **Configuration First**
    
    ---
    Configure core services and tenant settings from the console

-   :material-security:{ .lg .middle } **Security UI**
    
    ---
    Manage RBAC, keys, and audit views

</div>

!!! tip "Accessibility & Dyslexia"
    UI must be fully accessible. Use high-contrast themes and readable fonts. Keyboard navigation is required.

!!! note "No CLI-only Features"
    If an operation exists in the platform, it must also exist in the Admin Console.

!!! warning "Audit Visibility"
    Sensitive actions (key rotation, exports) should require secondary confirmation and appear in audit logs.

## Admin Console Navigation

- Dashboard
- Users
- Plugins & Marketplace
- Storage Browser
- Policies & Audit


## Quick Tasks

- [x] Create a user
- [x] Install a plugin from Marketplace
- [ ] Rotate storage keys

### Creating a User (step-by-step)

1. Go to Users -> Create
2. Fill username, email, roles
3. Click ++Save++ (or ++ctrl+s++)

=== "Python"
    ```python
    # (1) API equivalent of creating a user
    import requests
    r = requests.post('https://localhost:8443/api/v1/users', json={'username':'bob','email':'bob@example.com','roles':['operator']}, headers={'Authorization':'Bearer TOKEN'})
    print(r.status_code)
    ```

=== "Node.js"
    ```javascript
    // (1) Node create user
    const fetch = require('node-fetch')
    fetch('https://localhost:8443/api/v1/users', { method:'POST', headers:{'Content-Type':'application/json','Authorization':'Bearer TOKEN'}, body: JSON.stringify({username:'bob',email:'bob@example.com',roles:['operator']}) })
    ```

=== "curl"
    ```bash
    # (1) curl create user
    curl -X POST https://localhost:8443/api/v1/users -H 'Authorization: Bearer TOKEN' -H 'Content-Type: application/json' -d '{"username":"bob","email":"bob@example.com","roles":["operator"]}'
    ```

1. Actions performed in the UI map directly to Admin API calls and create audit entries


## Plugin Management

- Install/uninstall plugins via Marketplace
- Configure plugin settings and secrets
- Enable/disable plugin routes without redeploy

```mermaid
flowchart LR
  AdminUI --> API[Admin API]
  API --> PluginRegistry[Plugin Registry]
  PluginRegistry --> Plugin[Deployed Plugin]
```

| UI Section | Purpose | Notes |
|------------|---------|-------|
| Storage Browser | Inspect encrypted objects | Mask content by default |
| Policy Inspector | View policy and allowlists | Editable with audit trail |
| MFA | Manage multi-factor options | Enforce for admins |


??? note "Keyboard Shortcuts"
    - ++ctrl+k++: quick search
    - ++ctrl+s++: save form
    - ++ctrl+shift+p++: open command palette
