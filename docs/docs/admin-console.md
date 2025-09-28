!!! info "All features must be operable from the Admin Console"
    The Admin Console is the primary UX for operators. No capabilities are CLI-only.

# Admin Console Guide :desktop_computer:

This guide helps administrators use the Admin Console to manage the Vivified platform.

## Main sections (what to find where)

- Dashboard — system health, recent audits, alerts
- Plugins — install, configure, test, enable/disable
- Storage Browser — search, inspect objects, view classification and retention
- Policies — retention, transformation, message filters
- Users & Roles — user management and role assignments
- Settings — global configuration, secrets stores, key rotation

## Plugin workflows

1. Add a plugin from the Marketplace.
2. Complete the setup wizard for required credentials.
3. Run outbound smoke tests and verify health.
4. Enable the plugin in production namespaces.

!!! tip "Setup wizard"
    The Admin Console links to plugin-provided setup pages where plugins can implement guided credential inputs and validation.

## Storage Browser UX

- Use built-in filters for classification, tags, and time range.
- Inspect audit trails per object to see who accessed or modified data.

## Policies

- Transformations: configure canonical transformation rules
- Retention: define deletion/archival rules
- Messaging filters: define conditions that redact or block messages

## Audit search

- Search by actor, event type, object ID, or time window.
- Export audit slices for compliance reviews.

## UI components (for integrators)

The Admin Console exposes UI components for plugin authors to reuse:

- Provider Setup Wizard
- Outbound Smoke Test runner
- Plugin Health & Metrics widgets
- Storage Browser component (read-only)

Use these components to create consistent plugin experiences.

## Accessibility & Dyslexia-friendly features

- High-contrast mode, larger fonts, and readability toggles are available in Settings.
- The Admin Console follows accessibility best practices; file an issue if any screen is not navigable via keyboard or screen reader.

!!! note "No CLI-only features"
    If a plugin or configuration requires a CLI-only step, provide a UI alternative or a guidance page within the Admin Console.
