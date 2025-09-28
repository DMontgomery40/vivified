!!! info "Welcome to Vivified" 
    <div class="hipaa-badge">HIPAA Compliant</div>

# Getting Started :rocket: 

Short, clear steps to run and explore Vivified locally and in enterprise environments. Read each step — they are intentionally short for clarity.

!!! tip "Quick path"
    If you want to explore the Admin Console and call the Admin API, follow the "Run the platform" section below and then skip to "Admin Console".

## Prerequisites

- A supported Python runtime and a Node LTS runtime for building the Admin Console (if you will run the UI).
- Docker (recommended) for local deployments and encrypted data storage simulation.
- An API client (curl, httpie) or Postman for testing Admin API endpoints.

??? details "Why these prerequisites?"
    Running the core services requires a server runtime and optional UI build tools. Docker is optional but recommended for parity with production.

## Run the platform (simple)

1. Clone the repository to a workspace you control.
2. Use the provided Docker compose (or equivalent) to bring up core services, or run core services directly.

!!! info "Run via Docker (recommended)"
    Use the Docker Compose or platform container bundles provided with your deployment artifacts to start core services, the gateway, and the Admin Console. Consult your operations team for enterprise credentials and secret handling.

## Run the platform (developer)

- If you prefer local processes, start the core FastAPI service and any required backing stores (e.g., a database and a message broker). The Admin Console can be built with the UI toolchain and served locally for development.

=== "Run Admin Console"

=== "Build and run UI"

=== "Serve built UI with gateway"


## Explore the Admin Console

- Open the Admin Console URL provided by your environment.
- Sign in using an account with Admin role.
- Visit these pages first:
  - Dashboard — system health and recent audit activity
  - Plugins — enable/disable and configure plugins
  - Storage Browser — inspect stored objects (HIPAA-aware)
  - Policy Inspector — review retention and audit policies

!!! tip "If you can't see features"
    Ensure your account has the proper role. All features are operable via the Admin Console and require role-based access.

## Try the Admin API (Quick examples)

Use the API to programmatically manage users, plugins, configuration, and audit logs.

=== "curl"

```bash
# List users (Admin API key required)
curl -H "Authorization: Bearer <API_KEY>" \
  https://api.example.com/admin/users
```

=== "Python"

```python
import requests

resp = requests.get(
    "https://api.example.com/admin/users",
    headers={"Authorization": "Bearer <API_KEY>"},
)
print(resp.json())
```

!!! note "Secure your keys"
    Never paste real API keys into public places. Use secrets management in production.

## Next steps

- Read the Core Services docs for each module (Canonical, Storage, Messaging, Gateway, Admin API).
- Follow the Plugin Development Guide to add integrations and custom functionality.


---

<small>Need help? See Troubleshooting and Security & Compliance guides in this documentation set.</small>
