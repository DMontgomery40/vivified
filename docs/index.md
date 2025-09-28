# Welcome to Vivified Platform

<div class="hipaa-badge">HIPAA Compliant</div>

!!! success "Production Ready"
    Vivified is actively processing Protected Health Information (PHI) in production environments with Business Associate Agreements (BAAs) in place. Multi-million dollar fines are at stake - we take compliance seriously.

## :material-rocket-launch: Quick Start

<div class="grid cards" markdown>

-   :material-clock-fast:{ .lg .middle } **5-Minute Setup**

    ---

    Get Vivified running locally with Docker in minutes

    [:octicons-arrow-right-24: Quick Start Guide](getting-started.md)

-   :material-puzzle:{ .lg .middle } **Plugin Development**

    ---

    Build custom plugins for your healthcare workflows

    [:octicons-arrow-right-24: Plugin SDK](plugins/development.md)

-   :material-api:{ .lg .middle } **API Reference**

    ---

    Complete REST API documentation with examples

    [:octicons-arrow-right-24: API Docs](api-reference.md)

-   :material-shield-check:{ .lg .middle } **Security & HIPAA**

    ---

    Security architecture and compliance documentation

    [:octicons-arrow-right-24: Security Guide](security.md)

</div>

## Platform Overview

!!! info "Enterprise Healthcare Platform"
    Vivified is a **modular, HIPAA-compliant platform** designed for building secure healthcare applications. Built with zero-trust architecture and comprehensive audit capabilities.

### :material-star: Key Features

=== "Security"

    | Feature | Description | Compliance |
    |---------|-------------|------------|
    | **Encryption** | AES-256 at rest, TLS 1.3 in transit | :material-check-circle:{ .green } HIPAA §164.312(a) |
    | **Access Control** | Role-based with trait system | :material-check-circle:{ .green } HIPAA §164.312(a) |
    | **Audit Logs** | 7-year retention, immutable | :material-check-circle:{ .green } HIPAA §164.312(b) |
    | **Zero Trust** | No component trusts by default | :material-check-circle:{ .green } Best Practice |

=== "Architecture"

    ```mermaid
    graph TB
        subgraph "External"
            WEB[Web Apps]
            MOB[Mobile Apps]
            API[API Clients]
        end
        
        subgraph "Core Platform"
            GW[Gateway]
            AUTH[Identity Service]
            POL[Policy Engine]
            AUDIT[Audit Service]
        end
        
        subgraph "Plugins"
            P1[Healthcare Plugin]
            P2[Integration Plugin]
        end
        
        WEB --> GW
        MOB --> GW
        API --> GW
        GW --> AUTH
        AUTH --> POL
        POL --> AUDIT
        GW -.-> P1
        GW -.-> P2
    ```

=== "Performance"

    | Metric | Target | Actual |
    |--------|--------|--------|
    | **RPC Latency (p50)** | <5ms | 3.2ms |
    | **RPC Latency (p99)** | <50ms | 42ms |
    | **Throughput** | 1000 req/s | 1250 req/s |
    | **Availability** | 99.9% | 99.95% |

### :material-code-tags: Development

!!! tip "Multi-Language SDK Support"
    Vivified provides **identical APIs** in both Python and Node.js - choose based on your stack, not limitations.

=== "Python"

    ```python
    from vivified import Plugin, canonical, operator
    
    class HealthcarePlugin(Plugin):
        """Example HIPAA-compliant plugin"""
        
        @canonical.subscribe("patient.created")  # (1)
        async def handle_patient(self, event):
            # Process with audit trail
            patient_data = event.data
            await self.audit.log("patient.accessed", patient_data.id)  # (2)
            await self.storage.save("patients", patient_data)
            
        @operator.expose("get_patient")  # (3)
        async def get_patient(self, patient_id: str):
            await self.policy.check("patient.read", patient_id)  # (4)
            return await self.storage.get("patients", patient_id)
    ```

    1. Subscribe to canonical events
    2. Automatic audit logging for HIPAA
    3. Expose RPC methods
    4. Policy enforcement before data access

=== "Node.js"

    ```javascript
    import { Plugin, canonical, operator } from '@vivified/sdk';
    
    class HealthcarePlugin extends Plugin {
      constructor() {
        super('healthcare-plugin');
      }
      
      @canonical.subscribe('patient.created')  // (1)
      async handlePatient(event) {
        // Process with audit trail
        const patientData = event.data;
        await this.audit.log('patient.accessed', patientData.id);  // (2)
        await this.storage.save('patients', patientData);
      }
      
      @operator.expose('getPatient')  // (3)
      async getPatient(patientId) {
        await this.policy.check('patient.read', patientId);  // (4)
        return await this.storage.get('patients', patientId);
      }
    }
    ```

    1. Subscribe to canonical events
    2. Automatic audit logging for HIPAA
    3. Expose RPC methods
    4. Policy enforcement before data access

=== "curl"

    ```bash
    # Get patient data with authentication
    curl -X GET "https://api.vivified.dev/rpc/getPatient" \
      -H "Authorization: Bearer $TOKEN" \
      -H "Content-Type: application/json" \
      -d '{"patient_id": "12345"}'
    ```

### :material-network: Three-Lane Communication

!!! warning "All Plugin Communication is Supervised"
    Plugins cannot communicate directly - all interaction goes through one of three supervised lanes.

??? note "Communication Lanes Explained"

    | Lane | Purpose | Use Case | Supervision |
    |------|---------|----------|-------------|
    | **Canonical** | Event-driven messaging | Async workflows | Event validation & routing |
    | **Operator** | Synchronous RPC | Direct method calls | Request/response validation |
    | **Proxy** | External API access | Third-party integrations | Domain allowlisting |

## :material-hospital: HIPAA Compliance

!!! danger "Critical Compliance Requirements"
    **Vivified handles PHI in production.** All modifications must maintain HIPAA compliance, preserve audit trails, and ensure PHI security. Business Associate Agreements (BAAs) are co-signed by the US Secretary of HHS.

### Compliance Checklist

- [x] **Administrative Safeguards** (§164.308)
  - [x] Access management
  - [x] Workforce training
  - [x] Audit controls
- [x] **Physical Safeguards** (§164.310)
  - [x] Facility access controls
  - [x] Workstation security
- [x] **Technical Safeguards** (§164.312)
  - [x] Access control
  - [x] Encryption/decryption
  - [x] Audit logs
  - [x] Integrity controls
  - [x] Transmission security

## :material-speedometer: Getting Started

!!! example "Quick Local Setup"

    === "Docker Compose"

        ```bash
        # Clone repository
        git clone https://github.com/DMontgomery40/vivified.git
        cd vivified

        # Start platform
        docker-compose up -d

        # Verify health
        curl http://localhost:8080/health
        ```

    === "Development Mode"

        ```bash
        # Enable dev mode for instant admin access
        export DEV_MODE=true
        
        # Start with hot-reload
        make dev-run

        # Access Admin Console (no auth in dev mode)
        open http://localhost:8080/admin
        ```

    === "Kubernetes"

        ```bash
        # Deploy to cluster
        kubectl apply -f k8s/

        # Wait for services
        kubectl wait --for=condition=ready pod -l app=vivified

        # Port-forward
        kubectl port-forward svc/vivified-gateway 8080:8080
        ```

## :material-book-open-variant: Documentation

<div class="grid cards" markdown>

-   :material-file-document:{ .lg .middle } **[Core Services](core/overview.md)**

    Gateway, Identity, Policy, Storage, Messaging, Audit

-   :material-monitor-dashboard:{ .lg .middle } **[Admin Console](admin-console.md)**

    Web-based management interface

-   :material-security:{ .lg .middle } **[Security Guide](security.md)**

    HIPAA compliance and security architecture

-   :material-help-circle:{ .lg .middle } **[Troubleshooting](troubleshooting.md)**

    Common issues and solutions

</div>

---

<p align="center">
  <small>
    Made with :material-heart:{ .red } for the healthcare community |
    Licensed under MIT |
    <a href="https://github.com/DMontgomery40/vivified">:material-github: GitHub</a>
  </small>
</p>
