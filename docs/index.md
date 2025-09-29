# Vivified Platform

## Enterprise application kernel with plugin architecture

Vivified is a modular platform for building secure, scalable applications. Deploy anything from ERP systems to security operations centers, messaging hubs to compliance platforms.

<div class="grid cards" markdown>

-   :material-book-open:{ .lg .middle } **Getting Started**

    ---

    Set up Vivified locally in 5 minutes

    [:octicons-arrow-right-24: Quick start](getting-started.md)

-   :material-puzzle:{ .lg .middle } **Plugin Development**

    ---

    Build and deploy custom plugins

    [:octicons-arrow-right-24: Plugin SDK](plugins/development.md)

-   :material-api:{ .lg .middle } **API Reference**

    ---

    REST, WebSocket, and RPC documentation

    [:octicons-arrow-right-24: API docs](api-reference.md)

-   :material-server:{ .lg .middle } **Deployment**

    ---

    Production deployment guides

    [:octicons-arrow-right-24: Deploy](deployment/index.md)

</div>

## Platform Overview

Vivified provides a secure foundation for enterprise applications through its three-lane communication model and trait-based access control (TBAC).

### Architecture

```mermaid
graph TB
    subgraph "Applications"
        APP1[ERP System]
        APP2[Security Platform]
        APP3[Messaging Hub]
        APP4[Custom Application]
    end
    
    subgraph "Core Platform"
        GW[Gateway]
        AUTH[Identity & TBAC]
        POL[Policy Engine]
        STOR[Storage Service]
        MSG[Message Bus]
        AUDIT[Audit Service]
    end
    
    subgraph "Plugins"
        P1[Splunk Integration]
        P2[Slack/Teams]
        P3[Database Connectors]
        P4[Custom Plugins]
    end
    
    APP1 --> GW
    APP2 --> GW
    APP3 --> GW
    APP4 --> GW
    
    GW --> AUTH
    AUTH --> POL
    GW --> MSG
    MSG --> P1
    MSG --> P2
    MSG --> P3
    MSG --> P4
```

### Use Cases

=== "Enterprise Operations"

    **ERP for SMB**
    - Inventory management plugins
    - Financial processing
    - HR workflows
    - Custom reporting

    **Messaging Nerve Center**
    - Route faxes to Slack/Teams
    - Push notifications via Pushover
    - Email-to-SMS bridges
    - Trait-based routing (no manual lists)

=== "Security Operations"

    **Red Team/Blue Team Platform**
    - Splunk integration
    - Custom SIEM from your SOC
    - Aircrack-ng automation
    - Vulnerability scanning orchestration
    
    **Compliance & Audit**
    - Automated compliance checks
    - Audit trail aggregation
    - Policy enforcement
    - Report generation

=== "Healthcare & Compliance"

    **HIPAA-Compliant Systems**
    - Patient data management
    - Clinical workflows
    - Insurance processing
    - Regulatory reporting
    
    **Financial Services**
    - Transaction processing
    - Risk assessment
    - Regulatory compliance
    - Audit requirements

### Core Features

| Feature | Description | Use Case |
|---------|-------------|----------|
| **Trait-Based Access Control** | Dynamic permission system based on user/service traits | No manual ACL maintenance |
| **Three-Lane Communication** | Canonical events, RPC operations, proxied external calls | Clean plugin isolation |
| **Plugin Architecture** | Hot-loadable plugins with sandboxing | Extend without modifying core |
| **Audit Service** | Comprehensive audit logging with configurable retention | Compliance and debugging |
| **Policy Engine** | Declarative policies for access control | Fine-grained permissions |
| **Storage Abstraction** | Pluggable storage backends | Use existing infrastructure |

## Quick links

- Architecture → [Three-Lane Model](architecture/three-lanes.md)
- Architecture → [Diagrams](architecture/diagrams.md)
- AI & Agents → [Overview](ai/overview.md)

## Defaults

- Database: Postgres (`postgresql+asyncpg://…`) for non‑test runs; tests default to in‑memory SQLite unless `TEST_DB_URL` overrides
- RAG (AI): Redis (`redis://localhost:6379/0`) by default with graceful fallback to in‑memory

## Quick start

```bash
docker-compose up -d
curl http://localhost:8080/health
```

## Development

!!! note "Language Support"
    Both Python and Node.js SDKs provide identical functionality. Choose based on your existing stack.

### Plugin Example

=== "Python"

    ```python
    from vivified import Plugin, canonical, operator
    
    class IntegrationPlugin(Plugin):
        """Example integration plugin"""
        
        @canonical.subscribe("document.received")
        async def handle_document(self, event):
            # Route based on traits
            recipients = await self.identity.find_by_traits(
                ["department:finance", "notify:documents"]
            )
            
            for recipient in recipients:
                await self.send_notification(recipient, event.data)
        
        @operator.expose("send_notification")
        async def send_notification(self, recipient, data):
            # Send via configured channel
            channel = recipient.traits.get("preferred_channel", "email")
            return await self.channels[channel].send(recipient, data)
    ```

=== "Node.js"

    ```javascript
    import { Plugin, canonical, operator } from '@vivified/sdk';
    
    class IntegrationPlugin extends Plugin {
      @canonical.subscribe('document.received')
      async handleDocument(event) {
        // Route based on traits
        const recipients = await this.identity.findByTraits([
          'department:finance',
          'notify:documents'
        ]);
        
        for (const recipient of recipients) {
          await this.sendNotification(recipient, event.data);
        }
      }
      
      @operator.expose('sendNotification')
      async sendNotification(recipient, data) {
        // Send via configured channel
        const channel = recipient.traits.preferredChannel || 'email';
        return await this.channels[channel].send(recipient, data);
      }
    }
    ```

=== "Configuration"

    ```yaml
    # plugin.yaml
    name: integration-plugin
    version: 1.0.0
    traits:
      - can_send_notifications
      - can_access_user_directory
    channels:
      email:
        provider: smtp
        host: mail.example.com
      slack:
        webhook_url: ${SLACK_WEBHOOK}
      pushover:
        app_token: ${PUSHOVER_TOKEN}
    ```

### Communication Patterns

??? info "Three-Lane Model"

    **Canonical Lane** - Event-driven messaging
    - Asynchronous processing
    - Event sourcing patterns
    - Loose coupling between services
    
    **Operator Lane** - Synchronous RPC
    - Direct method invocation
    - Request/response patterns
    - Strong typing support
    
    **Proxy Lane** - External API access
    - Controlled external communication
    - Rate limiting and retry logic
    - Credential management

## Quick Start

### Local Development

```bash
# Clone repository
git clone https://github.com/DMontgomery40/vivified.git
cd vivified

# Start services
docker-compose up -d

# Verify health
curl http://localhost:8080/health

# View logs
docker-compose logs -f
```

### Configuration

!!! tip "Environment Variables"
    See `.env.example` for all configuration options

| Variable | Description | Default |
|----------|-------------|---------|
| `GATEWAY_PORT` | API gateway port | `8080` |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://vivified:changeme@localhost:5432/vivified` |
| `REDIS_URL` | Redis connection for RAG (default) | `redis://localhost:6379/0` |
| `LOG_LEVEL` | Logging verbosity | `info` |
| `PLUGIN_DIR` | Plugin directory path | `./plugins` |

## Production Deployment

=== "Kubernetes"

    ```yaml
    # vivified-deployment.yaml
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: vivified-core
    spec:
      replicas: 3
      selector:
        matchLabels:
          app: vivified
      template:
        metadata:
          labels:
            app: vivified
        spec:
          containers:
          - name: vivified
            image: vivified/core:latest
            env:
            - name: DATABASE_URL
              valueFrom:
                secretKeyRef:
                  name: vivified-secrets
                  key: database-url
    ```

=== "Docker Swarm"

    ```yaml
    # docker-stack.yml
    version: '3.8'
    services:
      vivified:
        image: vivified/core:latest
        deploy:
          replicas: 3
          update_config:
            parallelism: 1
            delay: 10s
        environment:
          DATABASE_URL: ${DATABASE_URL}
    ```

=== "AWS ECS"

    ```json
    {
      "family": "vivified",
      "taskDefinition": {
        "containerDefinitions": [{
          "name": "vivified-core",
          "image": "vivified/core:latest",
          "memory": 2048,
          "cpu": 1024,
          "essential": true
        }]
      }
    }
    ```

## Documentation

- [Core Services](core/overview.md) - Gateway, Identity, Policy, Storage
- [Plugin Development](plugins/development.md) - SDK reference and examples
- [Admin Console](admin-console.md) - Web-based management interface
- [API Reference](api-reference.md) - REST, WebSocket, and RPC APIs
- [Deployment Guide](deployment/index.md) - Production deployment
- [Troubleshooting](troubleshooting.md) - Common issues and solutions

## Community

- [GitHub Issues](https://github.com/DMontgomery40/vivified/issues) - Bug reports and feature requests
- [Discussions](https://github.com/DMontgomery40/vivified/discussions) - Questions and community support
- [Contributing](contributing.md) - Contribution guidelines

---

MIT License | [GitHub](https://github.com/DMontgomery40/vivified)
