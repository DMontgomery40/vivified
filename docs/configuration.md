<div class='grid cards' markdown>

-   :material-settings:{ .lg .middle } **Configuration Reference**

    ---

    Centralized environment and configuration keys for the Vivified platform

-   :material-tune:{ .lg .middle } **Per-service settings**

    ---

    Config keys for canonical, storage, messaging, gateway, and API

-   :material-history:{ .lg .middle } **Retention & Compliance**

    ---

    All retention-related keys and defaults

</div>

!!! tip 'Centralized management'
    Configure production keys via the Admin Console or your secrets manager; do not store secrets in repo or plain text.

!!! note 'Structure'
    Use environment variables for runtime-only settings and persisted config for tunable platform behavior.

!!! warning 'Config drift'
    Ensure configuration is consistent across environments: mismatched retention or key settings may cause compliance gaps.

## Global configuration table (complete)

| Key | Service | Purpose | Example | Required |
|-----|---------|---------|---------|----------|
| APP_ENV | global | Environment name | production | yes |
| DATABASE_URL | api/storage | DB connection string | postgresql://... | yes |
| STORAGE_BACKEND | storage | Storage backend type | s3 | yes |
| STORAGE_KMS_KEY | storage | KMS key id | arn:aws:kms:... | yes |
| RETENTION_YEARS | storage | Default PHI retention (years) | 7 | yes |
| AUDIT_RETENTION_YEARS | audit | Audit retention | 7 | recommended |
| BUS_BACKEND | messaging | Messaging backend type | kafka | yes |
| GATEWAY_RATE_LIMIT | gateway | Per-client rate limit | 100/min | recommended |
| GATEWAY_AUTH_TYPE | gateway | Auth mode (jwt/mTLS) | jwt | yes |
| LOG_LEVEL | global | Logging verbosity | INFO | recommended |
| UI_BUILD_ASSETS | admin-ui | Path to UI assets | /var/www/admin_ui | recommended |

## Examples: environment snippets

=== "Python"
    ```python
    # (1)
    # Example: load configuration using pydantic BaseSettings
    from pydantic import BaseSettings
    class Settings(BaseSettings):
        app_env: str
        database_url: str
        class Config:
            env_file = '.env'
    ```

=== "Node.js"
    ```javascript
    // (1)
    // Example: load config via process.env
    const config = {
      dbUrl: process.env.DATABASE_URL,
      storageBackend: process.env.STORAGE_BACKEND || 's3'
    }
    ```

=== "curl"
    ```bash
    # (1)
    export APP_ENV=development
    # Prefer Postgres by default
    export DATABASE_URL='postgresql+asyncpg://vivified:changeme@localhost:5432/vivified'
    # RAG uses Redis by default when available
    export REDIS_URL='redis://localhost:6379/0'
    # Tests remain hermetic unless TEST_DB_URL overrides
    # export TEST_DB_URL='sqlite+aiosqlite:///:memory:'
    ```

1. Prefer a secrets manager for production KMS and DB credentials

```mermaid
graph LR
  Env[Environment Vars] --> App
  ConfigStore --> App
  App --> Services
  Services --> Audit
```

## Per-service configuration comparisons

| Setting | Canonical | Storage | Messaging | Gateway |
|---------|-----------|---------|-----------|---------|
| retention | schema versioning | retention years | retention days | rate limits |
| encryption | N/A | envelope AES-256 & KMS | message-level encryption | TLS & validation |
| audit | transform audits | access & change logs | message audit | request audit |

!!! note 'Versioning & migrations'
    For config fields that are schema-related, use versioned keys and migration tooling. Avoid in-place changes without migrations.

??? note 'Advanced: dynamic flags'
    Some flags may be toggled at runtime via the Admin Console; use feature flags for experimental behavior.

[^1]: Keep production configuration under strict access controls and ensure audit trails for changes.
