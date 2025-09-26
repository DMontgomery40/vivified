# Platform Core Architecture - The Unbreakable Foundation

## Executive Summary

Faxbot is architected as a **secure core platform** with extensive plugin capabilities. The core provides all security, compliance, routing, and infrastructure services that cannot be compromised. Plugins extend functionality while operating within the safety boundaries enforced by the core.

**Philosophy**: Give customers enough rope to hang themselves, but not enough rope to hang us.

## The Core Platform (Unchangeable & Non-Negotiable)

### 1. API Layer (FastAPI)
**Location**: `api/app/main.py`, `api/app/routers/`
**Responsibility**: REST API endpoints, request validation, response formatting
**Why Core**:
- Enforces all security policies
- Validates all input data
- Applies rate limiting and audit logging
- Maintains API contract stability for SDKs

```python
# Core API guarantees:
# - All endpoints protected by authentication/authorization
# - All requests/responses logged for audit
# - Rate limiting applied consistently
# - Input validation and sanitization
# - Error handling with proper HTTP codes
```

### 2. SDKs (Node.js & Python)
**Location**: `sdks/node/`, `sdks/python/`
**Responsibility**: Client libraries with identical API surface
**Why Core**:
- Consistent developer experience across languages
- Built-in security best practices
- Version synchronization with API changes
- Error handling and retry logic

### 3. MCP Servers (All Transports)
**Location**: `node_mcp/`, `python_mcp/`
**Responsibility**: AI assistant integration via stdio/HTTP/SSE
**Why Core**:
- Security-first AI integration
- Consistent tool interface for AI assistants
- OAuth/JWT authentication handling
- File handling with proper validation

### 4. Security & HIPAA Compliance Engine
**Location**: `api/app/auth.py`, `api/app/middleware/`, `HIPAA_REQUIREMENTS.md`
**Responsibility**: Authentication, authorization, compliance enforcement
**Why Core**:
```python
class SecurityCore:
    """Non-negotiable security enforcement"""

    def authenticate_request(self, request):
        # Core handles all auth - plugins cannot bypass
        pass

    def authorize_action(self, user, resource, action):
        # Core enforces permissions - plugins cannot override
        pass

    def enforce_hipaa_compliance(self, operation):
        # Core ensures HIPAA requirements - non-negotiable
        pass

    def audit_event(self, event):
        # Core logs everything - plugins cannot suppress
        pass
```

**Non-Negotiable Protections**:
- API key validation and scoping
- Session management and timeouts
- Input sanitization and validation
- PHI detection and protection
- Encryption at rest and in transit
- Access control and permissions

### 5. Audit & Observability Engine
**Location**: `api/app/audit.py`, `api/app/utils/observability.py`
**Responsibility**: Complete audit trail, telemetry, monitoring
**Why Core**:
- Compliance requires complete audit trails
- Security monitoring cannot have gaps
- Performance metrics for SLA compliance
- Breach detection and alerting

```python
# Every action is logged - plugins cannot opt out
audit_event("user_action", user_id=user.id, action="send_fax",
           resource="fax_job_123", result="success")

# Telemetry for platform health
log_metric("plugin_execution_time", plugin="email_gateway", time_ms=150)
```

### 6. VPN & Tunneling Infrastructure
**Location**: Built-in WireGuard, Tailscale, Cloudflare integrations
**Responsibility**: Secure connectivity, network isolation
**Why Core**:
- Security boundary enforcement
- HIPAA requires encrypted transit
- Network-level protection for plugins
- Cannot be bypassed or disabled

### 7. Rate Limiting & Traffic Management
**Location**: `api/app/main.py` middleware
**Responsibility**: DOS protection, fair resource allocation
**Why Core**:
- Protects platform stability
- Prevents abuse by misbehaving plugins
- Enforces SLA guarantees
- Cannot be circumvented

```python
# Rate limiting applies to EVERYTHING
@rate_limit(requests_per_minute=100)
def plugin_endpoint(request):
    # Even plugin endpoints get rate limiting
    pass
```

### 8. Storage, TTL & Retention Engine
**Location**: `api/app/storage.py`, retention policies
**Responsibility**: Data lifecycle, HIPAA retention, cleanup
**Why Core**:
- HIPAA requires specific retention periods
- Data must be deleted securely
- Compliance audits depend on proper cleanup
- Plugins cannot override retention policies

### 9. Testing & Diagnostics Suite
**Location**: `api/tests/`, `api/app/routers/diagnostics.py`
**Responsibility**: Platform health, plugin validation, compliance testing
**Why Core**:
- Ensures plugin compliance with core contracts
- Validates security implementations
- Provides platform health monitoring
- Required for certification and audits

### 10. LLM Ingestion & Routing Logic
**Location**: MCP integration, canonical models
**Responsibility**: AI/ML request routing, content processing
**Why Core**:
- Security filtering of AI requests
- Content sanitization and PHI protection
- Rate limiting for expensive AI operations
- Consistent interface for all AI providers

### 11. Canonical Model Engine
**Location**: `api/app/canonical/`
**Responsibility**: Universal data format translation
**Why Core**:
- Ensures plugins can interoperate
- Provides security validation layer
- Enables platform evolution without breaking changes
- Enforces data quality standards

```python
# All plugin data flows through canonical models
class CanonicalMessage:
    def __init__(self):
        self.id: str
        self.sender: CanonicalIdentity
        self.recipient: CanonicalIdentity
        self.content: CanonicalContent
        self.security_traits: List[str]  # ['hipaa_compliant', 'encrypted']
        self.audit_metadata: Dict[str, Any]

    def validate_security(self) -> bool:
        # Core validates all messages for security compliance
        return SecurityCore.validate_message(self)
```

## Plugin Extension Points (Customizable)

### 1. Identity & User Management Plugins
**Interface**: `api/app/plugins/identity/base.py`
**Default**: Built-in SQLAlchemy users/groups
**Customizable**: LDAP, Active Directory, SAML, custom ERP

```python
class IdentityProvider(Plugin):
    def authenticate(self, credentials: Dict) -> Optional[User]:
        pass

    def get_user_traits(self, user_id: str) -> List[str]:
        pass

    def get_permissions(self, user_id: str, resource: str) -> List[str]:
        pass
```

### 2. Configuration Storage Plugins
**Interface**: `api/app/plugins/config/base.py`
**Default**: PostgreSQL with hierarchy
**Customizable**: etcd, Consul, Redis, custom database

### 3. Communication Channel Plugins
**Interface**: `api/app/plugins/communication/base.py`
**Includes**: Fax providers (Phaxio, SIP), Email gateway, SMS, webhooks
**Customizable**: Any communication method

### 4. Storage Backend Plugins
**Interface**: `api/app/plugins/storage/base.py`
**Default**: Local filesystem, S3
**Customizable**: Azure Blob, Google Cloud, custom storage

### 5. Frontend/UI Plugins
**Interface**: Component-based extension
**Default**: React Admin Console
**Customizable**: Custom branding, additional views, alternative frameworks

## Core-Plugin Contract System

### Plugin Manifest Requirements
```json
{
  "id": "custom_user_management",
  "version": "1.0.0",
  "type": "identity_provider",

  "core_version_required": ">=3.0.0",
  "security_level": "hipaa_compliant",

  "canonical_models": {
    "User": "required",
    "Group": "required",
    "Permission": "required"
  },

  "audit_events": [
    "user_login", "user_logout", "permission_change"
  ],

  "rate_limits": {
    "authenticate": "100/minute",
    "get_user": "1000/minute"
  }
}
```

### Security Boundaries
```python
class PluginSandbox:
    """Core enforces security boundaries for all plugins"""

    def __init__(self, plugin: Plugin):
        self.plugin = plugin
        self.core_security = SecurityCore()

    def execute_plugin_method(self, method_name: str, *args, **kwargs):
        # Pre-execution security check
        if not self.core_security.authorize_plugin_action(
            plugin=self.plugin,
            method=method_name,
            args=args
        ):
            raise SecurityException("Plugin action not authorized")

        # Execute with resource limits
        with ResourceLimits(cpu_time=30, memory_mb=100):
            result = getattr(self.plugin, method_name)(*args, **kwargs)

        # Post-execution validation
        if not self.core_security.validate_plugin_result(result):
            raise SecurityException("Plugin result failed validation")

        # Mandatory audit logging
        audit_event("plugin_execution",
                   plugin_id=self.plugin.id,
                   method=method_name,
                   result_status="success")

        return result
```

### Data Flow Architecture
```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Client SDK    │    │   Core Platform  │    │     Plugins     │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
         │  1. API Request       │                       │
         ├──────────────────────►│                       │
         │                       │ 2. Auth/Validate      │
         │                       │                       │
         │                       │ 3. Plugin Call        │
         │                       ├──────────────────────►│
         │                       │                       │
         │                       │ 4. Canonical Result   │
         │                       │◄──────────────────────┤
         │                       │ 5. Security Check     │
         │                       │                       │
         │                       │ 6. Audit Log          │
         │                       │                       │
         │  7. Response          │                       │
         │◄──────────────────────┤                       │
```

## HIPAA Compliance Integration

### Trait-Based Enforcement
```python
class HIPAAEnforcer:
    """Core HIPAA enforcement - plugins cannot bypass"""

    def validate_data_handling(self, plugin: Plugin, data: Any):
        if self.contains_phi(data):
            if not plugin.has_trait('hipaa_compliant'):
                raise ComplianceError("Non-HIPAA plugin cannot handle PHI")

    def enforce_encryption(self, data: Any):
        if self.contains_phi(data):
            return self.encrypt_phi(data)
        return data

    def audit_phi_access(self, user: User, action: str, data: Any):
        if self.contains_phi(data):
            audit_event("phi_access", user_id=user.id, action=action,
                       phi_detected=True, requires_notification=True)
```

### UI Adaptation
```typescript
// Core determines UI behavior based on user traits
interface CoreUserContext {
  traits: string[];
  permissions: string[];
  compliance_mode: 'hipaa' | 'standard';
}

// Plugins receive adapted context
function PluginComponent({ userContext }: { userContext: CoreUserContext }) {
  // Plugin UI adapts to user's compliance requirements
  const showHIPAAWarnings = userContext.compliance_mode === 'hipaa';
  const canAccessPHI = userContext.traits.includes('phi_authorized');

  return (
    <PluginInterface
      showCompliance={showHIPAAWarnings}
      dataAccess={canAccessPHI}
    />
  );
}
```

## Migration Strategy

### Phase 1: Core Consolidation (Weeks 1-4)
1. **Extract Core Services**: Move all non-negotiable components to `core/` module
2. **Define Plugin Interfaces**: Create abstract base classes for all plugin types
3. **Implement Security Boundaries**: Add plugin sandboxing and validation
4. **Create Canonical Models**: Universal data formats for plugin interop

### Phase 2: Plugin Conversion (Weeks 5-8)
1. **User Management**: Convert existing auth to plugin (backward compatible)
2. **Provider Adapters**: Convert Phaxio/SIP to plugins
3. **Configuration System**: Move from .env to pluggable config storage
4. **Email Gateway**: Implement as pure plugin

### Phase 3: Enhancement (Weeks 9-12)
1. **Advanced Traits**: Full HIPAA/non-HIPAA UI adaptation
2. **Plugin Marketplace**: Registry and installation system
3. **Customer Integration**: Support for custom plugins
4. **Monitoring & Observability**: Plugin performance and health

## Benefits of This Architecture

### For Faxbot
- **Security**: Core boundaries cannot be violated
- **Compliance**: HIPAA requirements always enforced
- **Stability**: Core platform remains stable regardless of plugins
- **Evolution**: Can pivot to any domain while maintaining platform value

### For Customers
- **Flexibility**: Replace any non-core component
- **Integration**: Plug into existing systems (ERP, LDAP, storage)
- **Customization**: Adapt UI and workflows to their needs
- **Future-Proof**: Platform evolves with their requirements

### For Developers
- **Clear Boundaries**: Know exactly what can/cannot be changed
- **Consistent APIs**: Core provides stable foundation
- **Rich Ecosystem**: Build on proven security and compliance foundation
- **Innovation**: Focus on business logic, not infrastructure

## Example: Customer Integration

A hospital wants to integrate with their existing Epic ERP:

1. **What They Build**: Epic identity plugin implementing `IdentityProvider` interface
2. **What Core Provides**: Security validation, audit logging, API access, HIPAA compliance
3. **Result**: Seamless integration with their existing systems while maintaining all compliance and security requirements

They get the flexibility they need, we maintain the security guarantees we require. Win-win.

## Conclusion

This architecture provides a **secure, compliant platform** that can adapt to any customer requirement while maintaining non-negotiable security boundaries. The core handles all the complex, critical infrastructure while plugins provide unlimited customization possibilities.

**Core Principle**: Trust but verify. Plugins can do anything they want, as long as it passes through our security and compliance validation layer.