!!! info "Configuration Reference"
    This page lists user-facing configuration options manageable from the Admin Console and Admin API.

# Configuration Reference :gear:

Configuration is grouped by functional area. Use the Admin Console for interactive editing and validation.

## Global settings

- Default retention bucket — where archival data is stored
- Encryption key rotation schedule — configure via Settings
- Audit retention window — how long audit logs are retained

## Gateway settings

- Domain allowlist — list of approved outbound domains
- Request/response transformation rules — map inbound fields to canonical fields
- Rate limiting per client or IP

## Storage settings

- Classification rules — mapping of file patterns and metadata to classification labels
- Retention policies — time-based, event-based, or tag-based rules
- Data export destinations — approved destinations for archives

## Messaging settings

- Default topics and routing rules
- Delivery retry policies and backoffs
- Filters that apply to message payloads before delivery

## Canonical settings

- Transformation rules for each canonical model
- Redaction masks and PHI handling policies
- Audit hooks and enrichment rules

## Plugins

Each plugin entry includes:
- Enabled/disabled flag
- Configuration fields (sensitive fields are hidden and stored in the secrets store)
- Health check endpoints
- Test runners for outbound/inbound connectivity

## Environment configuration notes

- Secrets should be managed using the Admin Console-integrated secrets backend.
- Avoid storing secrets as plaintext in configuration entries or metadata.

??? details "Example: retention policy"
    ```json
    {
      "name": "clinical-records-longterm",
      "selector": {"classification": "clinical"},
      "retention_days": 3650,
      "action": "archive_then_delete"
    }
    ```

!!! tip "Validate after change"
    When changing policies, run a dry-run or small-scope validation if available to see which objects will be affected.

---

For environment-specific deployment configuration, consult your platform operations team. This documentation focuses on user-facing configuration exposed in the Admin Console and Admin API.
