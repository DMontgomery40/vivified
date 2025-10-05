<div class='grid cards' markdown>

-   :material-dashboard:{ .lg .middle } **Admin Console**

    ---

    Single-pane management for all platform features, accessible and dyslexia-friendly

-   :material-plugin:{ .lg .middle } **Plugin Marketplace**

    ---

    Browse, install, and configure plugins from the console

-   :material-settings:{ .lg .middle } **Configuration Center**

    ---

    Manage environment variables, retention policies, and system settings

</div>

!!! tip 'Accessibility & Dyslexia'
    The Admin Console uses readable fonts, high-contrast themes, and keyboard-first navigation. Toggle dyslexia settings in Settings > Accessibility.

!!! note 'Admin-first requirement'
    Everything available via CLI must have an equivalent or better experience in the Admin Console.

!!! warning 'Permissions'
    Admin Console actions are controlled by RBAC. Users without sufficient roles will not see certain actions.

## Key screens

| Screen | Purpose | Access |
|--------|---------|--------|
| Dashboard | Health, metrics, quick actions | admin |
| Plugins | Marketplace & registrations | admin |
| Storage Browser | Browse classified objects | admin/storage |
| Policy Inspector | Review routing and filter rules | admin/policy |

<div class='grid cards' markdown>

-   :material-search:{ .lg .middle } **Search & Filter**

    ---

    Global search across users, plugins, and audit logs

-   :material-visibility:{ .lg .middle } **Audit Explorer**

    ---

    View and export audit trails for compliance

</div>

### Keyboard shortcuts

- ++ctrl+k++ — open command palette
- ++ctrl+f++ — focus search
- ++esc++ — close modals

### Building Admin UI locally

=== "Python"
    ```python
    # (1)
    # Build scripts invoked from repo Makefile; these are examples
    ```

=== "Node.js"
    ```javascript
    // (1)
    // Example: build admin UI
    // cd core/admin_ui && npm ci && npm run build
    ```

=== "curl"
    ```bash
    # (1)
    make ui-ci-local || echo 'UI build failed'
    ```

1. The Admin Console is packaged as an SPA and served under /admin/ui. Ensure UI build artifacts are available in production deploys.

```mermaid
graph LR
  AdminUser --> Browser
  Browser -->|HTTPS| AdminConsole
  AdminConsole --> AdminAPI
  AdminAPI --> CoreServices
```

## Settings and configuration

| Setting | Purpose | Where to edit | Notes |
|---------|---------|---------------|-------|
| THEME | UI theme (default/high contrast) | Settings > Appearance | Accessibility setting |
| RETENTION_YEARS | Default PHI retention | Settings > Storage | Overrides per plugin allowed |
| PLUGIN_APPROVAL | Require approval for plugin install | Settings > Plugins | Recommended for prod |

!!! note 'Audit for UI actions'
    Every UI change emits an audit event (actor, action, target). Use Audit Explorer to trace actions.

??? note 'Advanced: embedding widgets'
    Plugins can register Admin UI widgets via the manifest and a JS entrypoint. Follow the UI component style guide in core/ui.

[^1]: The Admin Console is the primary integration point for non-developer users and must support assistive technologies.
