![Vivified Platform](vivified_logo_dark_mode.png)

# Vivified Platform

**Zero-Trust Enterprise Application Kernel**

Vivified is the first platform that solves the fundamental problem of enterprise software: **how to build secure, compliant applications that can safely handle PHI/PII while remaining infinitely extensible.**

Build anything - ERP systems, security operations centers, healthcare platforms, financial services - on a foundation that makes data breaches mathematically impossible.

## The Breakthrough

### **Complete Plugin Isolation**
Plugins run in containers with **zero network access**. They cannot:
- Access databases directly
- Make external API calls  
- Talk to other plugins
- See data they don't have traits for

Every interaction goes through Core where security policies are enforced.

### **Three-Lane Communication Model**
All data movement happens through three supervised channels:

**Canonical Lane** - Normalized business events
- HR plugin emits `UserCreated` → Payroll plugin automatically responds
- **Zero coupling** between plugins, just standard events
- **Schema validation** and **policy enforcement** on every message

**Operator Lane** - Authenticated service calls
- Accounting plugin calls Identity service for user details  
- **SSRF protection** - no raw URLs, only internal operations
- **Policy evaluation** on every call

**Proxy Lane** - Controlled external access
- Plugin requests Slack API → Core handles secrets and allowlists
- **Domain allowlisting** - only pre-approved services accessible
- **Automatic secret injection** - plugins never see credentials

### **Trait-Based Access Control (TBAC)**
Revolutionary security model where access is based on **what you can do**, not **who you are**:

- Users have traits like `handles_phi`, `finance_team`, `admin`
- Data is classified as `phi`, `pii`, `confidential`, `internal`
- **Automatic filtering** - you literally cannot see data you don't have traits for
- **Even the AI respects TBAC** - RAG queries only return results your traits allow

## Why This Changes Everything

### **For Healthcare**
- **HIPAA compliance by design** - PHI is invisible to users without proper traits
- **Audit trails** with 7-year retention automatically generated
- **Zero-trust architecture** prevents data breaches at the architectural level

### **For Financial Services**
- **PCI DSS compliance** built-in with automatic data classification
- **Regulatory reporting** generated from comprehensive audit logs  
- **Risk assessment** through policy engine evaluation

### **For Enterprise**
- **Infinite extensibility** without security compromise
- **Plugin marketplace** with automatic security validation
- **Multi-tenant by design** with complete tenant isolation

## Quick Start

### Docker Compose (Fastest)
```bash
git clone https://github.com/your-org/vivified.git
cd vivified
docker-compose up -d

# Access Admin Console
open http://localhost:8080/admin/ui
# Use "Sign in (Dev)" button in development mode
```

### Local Development
```bash
# Python 3.11 required
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r core/requirements.txt

# Set up databases  
export DATABASE_URL='postgresql+asyncpg://vivified:changeme@localhost:5432/vivified'
export REDIS_URL='redis://localhost:6379/0'

# Start the platform
python -m core.main
```

## Architecture Overview

```mermaid
graph TB
    subgraph "Your Applications"
        APP1[Healthcare Platform]
        APP2[Financial Services]
        APP3[Security Operations]
        APP4[Custom Enterprise App]
    end
    
    subgraph "Vivified Core - Zero Trust Kernel"
        GW[Three-Lane Gateway]
        TBAC[Trait-Based Access Control]
        POL[Policy Engine]
        AUDIT[Audit Service]
        CANON[Canonical Engine]
    end
    
    subgraph "Sandboxed Plugin Ecosystem"
        P1[EHR Integration]
        P2[Payment Processing]
        P3[SIEM Connector]
        P4[AI/RAG Engine]
        P5[Custom Plugins]
    end
    
    APP1 --> GW
    APP2 --> GW
    APP3 --> GW
    APP4 --> GW
    
    GW --> TBAC
    TBAC --> POL
    GW --> AUDIT
    GW --> CANON
    GW -.-> P1
    GW -.-> P2
    GW -.-> P3
    GW -.-> P4
    GW -.-> P5
```

## Revolutionary Features

### **AI That Respects Security**
- **TBAC-Protected RAG** - AI can only see data your traits allow
- **Automatic plugin generation** - Describe what you need, get working code
- **Multi-provider support** - OpenAI, Claude, DeepSeek, Local (Ollama)
- **Zero PHI leakage** - Sensitive data is invisible to AI without proper traits

### **Admin Console First**
- **No CLI-only features** - Everything operable via web interface
- **Trait-aware UI** - Shows only what you're authorized to access
- **Visual plugin builder** - Generate plugins through conversation
- **Real-time diagnostics** - Monitor three-lane traffic and policy decisions

### **Enterprise-Grade Security**
- **Encryption at rest** (AES-256) and in transit (TLS 1.3+)
- **Comprehensive audit logs** with trace IDs across all lanes
- **Policy engine** with fail-safe defaults (deny when uncertain)
- **Rate limiting** and DDoS protection on all endpoints

### **Compliance Ready**
- **HIPAA controls** implementation with automatic tracking
- **SOC 2 Type II** audit trail requirements built-in
- **GDPR compliance** with right-to-be-forgotten support
- **Custom frameworks** via declarative policy engine

## Plugin Development

### **AI-Powered Generation**
The embedded AI can build complete plugins for you:

1. **Open AI Studio** in Admin Console
2. **Train on your context** - RAG learns your business requirements  
3. **Describe your need**: *"Build a QuickBooks integration that syncs invoices"*
4. **Get working plugin** - Complete with manifest, code, tests, documentation

**TBAC Protection**: The AI only sees documentation and code your traits allow access to.

### **Manual Development** 
For developers who prefer control, scaffolding tools generate templates for any plugin type.

## Security Model Deep Dive

### **Journey of PHI Through the System**
Based on the [comprehensive documentation](https://docs.vivified.dev/latest/core/three-lanes/?h=journey#visuals):

1. **Plugin receives PHI** - Tags with `classification=["phi"]` and `tenant_id`
2. **External LLM call** - Goes through Proxy lane with domain allowlisting and secret injection
3. **Canonical event** - Publishes `DocumentSummarized` with references, not raw PHI
4. **Operator call** - Requests embedding via authenticated RPC to vectorizer plugin  
5. **Audit trail** - Every step logged with `trace_id` for complete lineage
6. **TBAC filtering** - Only users with proper traits can access results

### **Failure Modes (Fail-Safe)**
- **Proxy**: Domain not allowlisted → Request denied and audited
- **Canonical**: Missing classification → Event rejected and audited  
- **Operator**: Caller lacks traits → Call denied and audited
- **Policy**: Cannot prove safety → Action blocked by default

## Documentation

- **[Getting Started](https://docs.vivified.dev/)** - Complete setup guide
- **[Three-Lane Model](https://docs.vivified.dev/latest/core/three-lanes/)** - Deep dive into the architecture
- **[Plugin Development](https://docs.vivified.dev/latest/plugins/)** - Build your first plugin
- **[Security Model](https://docs.vivified.dev/latest/security/)** - TBAC and compliance details

## What You Can Build

**Healthcare & Life Sciences**
- HIPAA-compliant patient management systems
- Clinical workflow automation
- Insurance claims processing
- Regulatory reporting platforms

**Financial Services**  
- PCI DSS compliant payment processing
- Risk assessment and compliance monitoring
- Regulatory reporting automation
- Multi-tenant banking platforms

**Security Operations**
- SIEM and SOC platforms
- Threat intelligence aggregation
- Compliance monitoring systems
- Incident response automation

**Enterprise Applications**
- Multi-tenant ERP systems
- Supply chain management
- HR and payroll platforms  
- Custom business applications

## Contributing

We welcome contributions! See our [Contributing Guide](CONTRIBUTING.md).

### Development Standards
- **Python**: Black formatting, flake8 linting, mypy type checking
- **Security**: All PRs require security review for PHI/PII handling
- **Testing**: Minimum 80% coverage with comprehensive integration tests
- **Documentation**: Every feature must include security considerations

## License

[MIT License](LICENSE) - Build the future of secure enterprise software.

---

**Ready to build applications that are secure by design?**

[Get Started](https://docs.vivified.dev/) • [View Documentation](https://docs.vivified.dev/latest/) • [Enterprise Support](mailto:enterprise@vivified.dev)
