# Phase 2: Trait-Based Authentication & User Management Implementation Plan

**Branch**: `auto-tunnel` (CRITICAL - all v4 work stays here)
**Status**: Updated with head planning agent feedback - ready for implementation

## Critical Updates Applied

Based on comprehensive review from head planning agent, the following must-fix changes have been incorporated:

### 🔧 **Async DB Correctness** (Blocking Risk Fixed)
- **Problem**: Sync SQLAlchemy calls inside async methods would block event loop
- **Solution**: Switch to `AsyncSessionLocal` end-to-end with proper `await` for all DB operations
- **Added**: Alembic migration support for Phase 2 tables

### 🔐 **Enhanced Password Security** (HIPAA-Aligned)
- **Problem**: bcrypt is acceptable but Argon2id is preferred for memory-hard hashing
- **Solution**: Use `argon2-cffi` with tuned parameters (time_cost=3, memory_cost=65536)
- **Added**: Password complexity policy (length 12+), rate-limiting, lockout/backoff

### 🍪 **Secure Session Management** (HIPAA-Friendly)
- **Problem**: localStorage storage + Authorization header (XSS risk)
- **Solution**: Opaque, rotating session IDs in HttpOnly, Secure, SameSite=Strict cookies
- **Added**: CSRF tokens, session rotation on login/elevation, auto-expire elevated privileges

### 📋 **Explicit Permission Grammar** (Trait Semantics Fixed)
- **Problem**: Mixed trait names and permission strings without clear mapping
- **Solution**: Structured permission format: `{namespace}.{resource}:{action}` (e.g., `admin.users:write`)
- **Added**: Static trait → permission mapping, precedence rules (deny > allow), cycle detection

### 🌳 **Safe Group Hierarchy** (Cycle Prevention)
- **Problem**: Parent groups could create infinite cycles
- **Solution**: Cycle detection on save, max depth cap, precomputed flattened trait sets
- **Added**: `assert_no_cycle()` function with depth limiting

### 🔍 **Audit & Privacy Guardrails** (Compliance Ready)
- **Problem**: Risk of PHI/secrets in logs, inconsistent audit format
- **Solution**: Standardized `audit_event(level, actor, subject, action, result, correlation_id)`
- **Added**: Privacy linter pipeline, no PHI in logs, partial token logging only

### 🔌 **Plugin Interface Consistency** (Architecture Aligned)
- **Problem**: IdentityProvider mixed BasePlugin/FaxbotPlugin inheritance
- **Solution**: Define `IdentityPlugin(FaxbotPlugin)` with `plugin_type = "identity"`
- **Added**: Load-time plugin type enforcement

### ⏱️ **Session Elevation Management** (Privilege Control)
- **Problem**: Session traits like `mfa_verified` needed time-bounded elevation
- **Solution**: `Session.elevation_at/elevation_expires_at` with auto-drop of `phi_authorized`
- **Added**: Automatic privilege expiry, elevation tracking

### 🎨 **Efficient UI Adaptations** (Performance & Caching)
- **Problem**: Full JSON blob in headers (size/caching issues)
- **Solution**: `/admin/ui-config` endpoint returning cached config with ETag
- **Added**: Proper frontend caching, reduced header payload

### 🔄 **Stable Backward Compatibility** (API Consistency)
- **Problem**: UnifiedAuthMiddleware permission → scope mapping was implicit
- **Solution**: Explicit `permissions_to_legacy_scopes()` mapper with documented equivalences
- **Added**: Stable mapping table, clear scope/permission correspondence

## Executive Summary

Phase 2 transforms Faxbot from API key-only authentication to a comprehensive trait-based authentication system with full user management. This phase builds directly on the Phase 1 platform core, enabling real users, sessions, groups, and dynamic trait-based UX adaptation while maintaining 100% backward compatibility with existing API keys. Admin Console remains the primary setup and management surface; any CLI helpers are optional and must not be required.

**Dependencies**: Phase 1 must be 100% complete (SecurityCore, AuditLogger, TraitEngine, CanonicalMessage system, PluginManager, HybridConfigProvider DB→.env)
**Timeline**: 5-7 weeks
**Goal**: Real users with trait-based authentication alongside existing API keys

## Phase 1 Integration Points

### Required Phase 1 Components:
- ✅ `SecurityCore` - Will be extended for session management
- ✅ `AuditLogger` - Enhanced for user action logging
- ✅ `TraitEngine` - Extended with comprehensive trait definitions
- ✅ `PluginManager` - Used for identity provider plugins
- ✅ `CanonicalMessage` - Enhanced with user identity support

### Phase 1 → Phase 2 Evolution:
```python
# Phase 1: API key traits from scopes
auth_info = security_core.authenticate_request(api_key)
traits = trait_engine.resolve_traits_from_auth(auth_info)

# Phase 2: User traits from identity + groups + roles
user = identity_provider.get_user(user_id)
traits = trait_engine.resolve_traits_from_user(user)
```

## Core Architecture Overview

### The Trait-First Philosophy

**Everything in Phase 2 has traits:**
- **Users**: `['hipaa_compliant', 'fax_capable', 'admin_capable']`
- **Groups**: `['medical_staff', 'requires_phi_access']`
- **Sessions**: `['mfa_verified', 'secure_device']`
- **Resources**: `['contains_phi', 'admin_only']`
- **UI Components**: `['hipaa_mode', 'show_advanced']`

### Dual Authentication System

**Coexistence Pattern** - Phase 2 runs alongside existing API keys:
```python
# Both authentication methods work simultaneously
def authenticate_request(api_key: str = None, session_token: str = None):
    if session_token:
        # New: Session-based auth
        session = identity_provider.validate_session(session_token)
        return session.user_context
    elif api_key:
        # Existing: API key auth (unchanged)
        return security_core.authenticate_request(api_key)
    else:
        return None
```

## Current Faxbot Integration Map (Phase 2)

- Backward compatibility (no route breaks): keep all existing Admin and provider routes intact; middleware populates legacy `request.state.auth_info` for API‑key flows while introducing session cookies for Admin Console.
- Providers & storage unchanged at API surface: identity/session work must not change `/phaxio-callback`, `/sinch-inbound`, `/admin/tunnel/*`, storage download paths, or job endpoints.
- UI shell reuse: integrate login/session and user management into the existing Admin Console shell (`api/admin_ui/src/App.tsx`) using responsive kits and `docsBase` links; no new global CSS.
- Tunnel + Sinch: keep `/admin/tunnel/register-sinch` action wired (client exists in `api/admin_ui/src/api/client.ts:284`) and ensure identity/session changes don’t affect tunnel endpoints.
- Trait gating: replace any remaining backend-name checks in UI with trait checks (`useTraits().hasTrait/traitValue`); do not gate content on `active?.outbound === 'sinch'` etc.

## P0 Must‑Fix (Apply Now)

These six items are required to prevent runtime and security issues. They update or override earlier examples where applicable.

### 1) Use Async SQLAlchemy patterns everywhere

Do not call `db.query(...).first()` in async code. Use `AsyncSession` with `select(...)` and async engine DDL.

```python
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from api.app.db.async import AsyncSessionLocal, engine  # async engine

async def get_user_by_id(user_id: str):
    async with AsyncSessionLocal() as db:  # type: AsyncSession
        res = await db.execute(select(DBUser).where(DBUser.id == user_id))
        return res.scalar_one_or_none()

# Dev-only fallback DDL (prefer Alembic migrations)
async def create_tables_dev_only():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
```

Apply this pattern to all reads/writes in the identity provider and session flows.

### 2) Identity plugin lookup by type (not name)

Add a type-based getter to the manager, and switch callsites to it.

```python
# api/app/plugins/manager.py
def get_active_by_type(self, plugin_type: str):
    bucket = self.plugins.get(plugin_type, {})
    if len(bucket) == 1:
        return next(iter(bucket.values()))
    # fallback to default id from config
    default_id = self.config_provider.get(f"plugins.{plugin_type}.default")
    return bucket.get(default_id)

# Call sites
identity_provider = core_platform.plugin_manager.get_active_by_type("identity")
```

### 3) Enforce CSRF for cookie sessions

Add CSRF middleware for state‑changing routes when using cookie auth.

```python
# api/app/middleware/csrf.py
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import hmac

class CSRFMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, cookie_name="fb_csrf", header_name="x-csrf-token"):
        super().__init__(app)
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.methods = {"POST","PUT","PATCH","DELETE"}

    async def dispatch(self, request: Request, call_next):
        if request.method in self.methods:
            cookie = request.cookies.get(self.cookie_name)
            header = request.headers.get(self.header_name)
            if not cookie or not header or not hmac.compare_digest(cookie, header):
                raise HTTPException(status_code=403, detail="CSRF token invalid")
        return await call_next(request)
```

Enable for Admin Console/API where cookie sessions are used.

### 4) Hash session tokens at rest (pepper)

Never store raw session tokens; store a peppered hash and compare on validate.

```python
import os, hashlib, hmac, secrets
PEPPER = os.environ["FAXBOT_SESSION_PEPPER"].encode()

def _hash_token(raw: str) -> str:
    return hmac.new(PEPPER, raw.encode(), hashlib.sha256).hexdigest()

async def create_session(self, user_id: str, metadata: Dict[str, Any]) -> Session:
    raw = secrets.token_urlsafe(64)
    token_hash = _hash_token(raw)
    async with AsyncSessionLocal() as db:
        db_session = DBSession(token=token_hash, user_id=user_id, ...)
        db.add(db_session); await db.commit()
    # Return raw to client (cookie); never persist/display raw elsewhere
    return Session(token=raw, user=..., ...)

async def validate_session(self, raw_token: str) -> Optional[Session]:
    token_hash = _hash_token(raw_token)
    async with AsyncSessionLocal() as db:
        res = await db.execute(select(DBSession).where(DBSession.token == token_hash, ...))
        db_session = res.scalar_one_or_none()
        ...
```

Note: `DBSession.token` length supports SHA‑256 hex (64 chars).

### 5) Bootstrap admin flow (no lockout)

Provide at least one of the following (env bootstrap shown):

```python
pwd = os.getenv("FAXBOT_BOOTSTRAP_PASSWORD")
if not admin_exists and pwd:
    admin_user.password_hash = self._hash_password(pwd)
    admin_user.metadata = json.dumps({"must_change_password": True})
    db.add(admin_user); await db.commit()
```

Alternative: one‑time bootstrap token route writing a token to `.faxbot_bootstrap` then deleted after first use.

### 6) Logout/refresh must handle cookies

Use cookie first, then Authorization fallback; clear cookie on logout.

```python
@router.post("/logout")
async def logout(request: Request, response: Response):
    token = request.cookies.get("fb_session") or request.headers.get('authorization','').replace('Bearer ','')
    if not token:
        raise HTTPException(400, "No session token provided")
    identity = core_platform.plugin_manager.get_active_by_type("identity")
    if identity:
        await identity.revoke_session(token)
    response.delete_cookie("fb_session", httponly=True, secure=True, samesite="strict", path="/")
    return {"success": True}

@router.post("/refresh")
async def refresh_session(request: Request):
    token = request.cookies.get("fb_session") or request.headers.get('authorization','').replace('Bearer ','')
    if not token:
        raise HTTPException(400, "No session token provided")
    identity = core_platform.plugin_manager.get_active_by_type("identity")
    session = await identity.refresh_session(token)
    if not session:
        raise HTTPException(401, "Invalid or expired session")
    return {"success": True, "expires_at": session.expires_at.isoformat()}
```

P1 (safe to defer):

- Admin override match: `any(p == 'admin:*' or p.startswith('admin.') for p in permissions)`
- UI Login.tsx signature: drop `sessionToken` param (cookie-based)
- Import gaps/nits and rate‑limit/lockout hooks: tail of Phase‑2 or Phase‑3

## Week 1-2: Enhanced TraitEngine & Trait System

### 1. Comprehensive Trait Definitions

**Create `api/app/core/traits.py`**

```python
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass

@dataclass
class TraitDefinition:
    """Complete trait definition with UI adaptations"""
    name: str
    description: str
    category: str
    requires: List[str] = None
    incompatible_with: List[str] = None
    permissions: List[str] = None
    ui_adaptations: Dict[str, Any] = None
    audit_level: str = "standard"

    def __post_init__(self):
        if self.requires is None:
            self.requires = []
        if self.incompatible_with is None:
            self.incompatible_with = []
        if self.permissions is None:
            self.permissions = []
        if self.ui_adaptations is None:
            self.ui_adaptations = {}

class TraitCategory(Enum):
    COMPLIANCE = "compliance"
    CAPABILITY = "capability"
    PERMISSION = "permission"
    SECURITY = "security"
    CONTENT = "content"
    SYSTEM = "system"
    UI = "ui"

# Comprehensive trait definitions
TRAIT_DEFINITIONS = {
    # === COMPLIANCE TRAITS (mutually exclusive) ===
    'hipaa_compliant': TraitDefinition(
        name='hipaa_compliant',
        description='Entity operates under HIPAA requirements',
        category=TraitCategory.COMPLIANCE,
        requires=['audit_logging', 'encryption_capable'],
        incompatible_with=['non_hipaa'],
        permissions=['phi.data:read', 'phi.data:write', 'audit.logs:read'],
        ui_adaptations={
            'theme': 'medical',
            'color_scheme': 'medical_blues',
            'show_compliance_warnings': True,
            'terminology': 'clinical',
            'require_acknowledgments': True,
            'show_phi_warnings': True
        },
        audit_level='high'
    ),

    'non_hipaa': TraitDefinition(
        name='non_hipaa',
        description='Entity operates without HIPAA restrictions',
        category=TraitCategory.COMPLIANCE,
        incompatible_with=['hipaa_compliant', 'handles_phi', 'phi_authorized'],
        ui_adaptations={
            'theme': 'business',
            'color_scheme': 'neutral_grays',
            'show_compliance_warnings': False,
            'terminology': 'standard',
            'simplified_ui': True
        },
        audit_level='standard'
    ),

    # === CAPABILITY TRAITS ===
    'fax_capable': TraitDefinition(
        name='fax_capable',
        description='Can send and receive fax messages',
        category=TraitCategory.CAPABILITY,
        requires=['communication_capable'],
        permissions=['fax.jobs:write', 'fax.jobs:read', 'fax.messages:read'],
        ui_adaptations={
            'show_fax_menu': True,
            'enable_fax_widgets': True
        }
    ),

    'email_capable': TraitDefinition(
        name='email_capable',
        description='Can send and receive email messages',
        category=TraitCategory.CAPABILITY,
        requires=['communication_capable'],
        permissions=['email.jobs:write', 'email.jobs:read', 'email.messages:read'],
        ui_adaptations={
            'show_email_menu': True,
            'enable_email_widgets': True
        }
    ),

    'admin_capable': TraitDefinition(
        name='admin_capable',
        description='Administrative privileges and access',
        category=TraitCategory.CAPABILITY,
        requires=['authenticated', 'audit_logging'],
        permissions=['admin.users:write', 'admin.plugins:write', 'admin.system:read', 'admin.config:write'],
        ui_adaptations={
            'show_admin_menu': True,
            'enable_advanced_settings': True,
            'show_system_metrics': True
        },
        audit_level='high'
    ),

    # === PERMISSION TRAITS ===
    'phi_authorized': TraitDefinition(
        name='phi_authorized',
        description='Authorized to access Protected Health Information',
        category=TraitCategory.PERMISSION,
        requires=['hipaa_compliant', 'mfa_enabled', 'audit_logging'],
        permissions=['phi.data:read', 'phi.data:write', 'phi.messages:read'],
        ui_adaptations={
            'show_phi_data': True,
            'enable_phi_processing': True,
            'show_phi_indicators': True
        },
        audit_level='critical'
    ),

    'mfa_enabled': TraitDefinition(
        name='mfa_enabled',
        description='Multi-factor authentication enabled',
        category=TraitCategory.SECURITY,
        requires=['authenticated'],
        ui_adaptations={
            'require_mfa_prompts': True,
            'show_mfa_status': True
        },
        audit_level='high'
    ),

    # === SYSTEM TRAITS ===
    'authenticated': TraitDefinition(
        name='authenticated',
        description='Successfully authenticated entity',
        category=TraitCategory.SECURITY,
        permissions=['system:access'],
        audit_level='standard'
    ),

    'session_based': TraitDefinition(
        name='session_based',
        description='Authentication via session token',
        category=TraitCategory.SYSTEM,
        requires=['authenticated'],
        ui_adaptations={
            'enable_logout': True,
            'show_session_timeout': True
        }
    ),

    'api_key_based': TraitDefinition(
        name='api_key_based',
        description='Authentication via API key',
        category=TraitCategory.SYSTEM,
        requires=['authenticated'],
        ui_adaptations={
            'hide_logout': True,
            'show_api_key_info': True
        }
    )
}

class EnhancedTraitEngine:
    """Enhanced trait engine with comprehensive definitions and UI adaptations"""

    def __init__(self):
        self.trait_definitions = TRAIT_DEFINITIONS
        self.compatibility_cache = {}

    def get_trait_definition(self, trait: str) -> Optional[TraitDefinition]:
        """Get complete trait definition"""
        return self.trait_definitions.get(trait)

    def get_ui_adaptations(self, traits: List[str]) -> Dict[str, Any]:
        """Get combined UI adaptations for trait list"""
        adaptations = {}

        for trait in traits:
            definition = self.get_trait_definition(trait)
            if definition and definition.ui_adaptations:
                adaptations.update(definition.ui_adaptations)

        return adaptations

    def get_permissions(self, traits: List[str]) -> List[str]:
        """Get all permissions granted by traits"""
        permissions = set()

        for trait in traits:
            definition = self.get_trait_definition(trait)
            if definition and definition.permissions:
                permissions.update(definition.permissions)

        return list(permissions)

    def permissions_to_legacy_scopes(self, permissions: List[str]) -> List[str]:
        """Convert new permissions to legacy scopes for backward compatibility"""
        LEGACY_SCOPE_MAP = {
            'fax.jobs:read': 'fax.read',
            'fax.jobs:write': 'fax.send',
            'fax.messages:read': 'fax.read',
            'email.jobs:read': 'email.read',
            'email.jobs:write': 'email.send',
            'email.messages:read': 'email.read',
            'admin.users:write': 'admin',
            'admin.users:read': 'admin',
            'admin.plugins:write': 'admin',
            'admin.system:read': 'admin',
            'admin.config:write': 'admin',
            'admin:*': 'admin',
            'phi.data:read': 'phi.read',
            'phi.data:write': 'phi.write',
            'phi.messages:read': 'phi.read',
            'system:access': 'system'
        }

        scopes = set()
        for perm in permissions:
            if perm in LEGACY_SCOPE_MAP:
                scopes.add(LEGACY_SCOPE_MAP[perm])
            # Wildcard admin permissions
            elif perm.startswith('admin.'):
                scopes.add('admin')

        return sorted(list(scopes))

    def validate_trait_combination(self, traits: List[str]) -> Dict[str, Any]:
        """Comprehensive trait validation"""
        errors = []
        warnings = []
        missing = []

        trait_set = set(traits)

        for trait in traits:
            definition = self.get_trait_definition(trait)
            if not definition:
                errors.append(f"Unknown trait: {trait}")
                continue

            # Check requirements
            for required in definition.requires:
                if required not in trait_set:
                    missing.append(f"Trait '{trait}' requires '{required}'")

            # Check incompatibilities
            for incompatible in definition.incompatible_with:
                if incompatible in trait_set:
                    errors.append(f"Trait '{trait}' incompatible with '{incompatible}'")

        # Check for missing compliance trait
        compliance_traits = [t for t in traits if self.get_trait_definition(t) and
                           self.get_trait_definition(t).category == TraitCategory.COMPLIANCE]
        if not compliance_traits:
            warnings.append("No compliance trait specified - defaulting to 'non_hipaa'")

        # Check for group cycles in validation
        self._check_group_cycles(traits)

        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'missing_requirements': missing
        }

    def resolve_default_traits(self, base_traits: List[str]) -> List[str]:
        """Add default/implied traits"""
        traits = set(base_traits)

        # Add default compliance trait if none specified
        compliance_traits = [t for t in traits if self.get_trait_definition(t) and
                           self.get_trait_definition(t).category == TraitCategory.COMPLIANCE]
        if not compliance_traits:
            traits.add('non_hipaa')

        # Add 'authenticated' if user has any permissions
        has_permissions = any(self.get_trait_definition(t) and self.get_trait_definition(t).permissions
                            for t in traits if self.get_trait_definition(t))
        if has_permissions:
            traits.add('authenticated')

        return list(traits)

    def _check_group_cycles(self, traits: List[str]) -> None:
        """Check for cycles in group hierarchy (placeholder for group validation)"""
        # This will be enhanced when group hierarchy is implemented
        pass

    def assert_no_cycle(self, group_id: str, parent_id: Optional[str], fetch_parent_func) -> None:
        """Assert no cycles in group hierarchy"""
        seen = {group_id}
        cur = parent_id
        depth = 0
        max_depth = 10  # Cap max depth

        while cur and depth < max_depth:
            if cur in seen:
                raise ValueError(f"Group hierarchy cycle detected: {cur} already in path")
            seen.add(cur)
            cur = fetch_parent_func(cur)
            depth += 1

        if depth >= max_depth:
            raise ValueError(f"Group hierarchy too deep (>{max_depth} levels)")
```

### 2. Integration with Phase 1 TraitEngine

**Enhance `api/app/middleware/traits.py`**

```python
# Import enhanced engine
from api.app.core.traits import EnhancedTraitEngine

# Replace global trait_engine
trait_engine = EnhancedTraitEngine()

# Add new middleware functions
def get_user_ui_adaptations(request: Request) -> Dict[str, Any]:
    """Get UI adaptations for current user"""
    traits = get_user_traits_from_request(request)
    return trait_engine.get_ui_adaptations(traits)

def get_user_permissions(request: Request) -> List[str]:
    """Get all permissions for current user"""
    traits = get_user_traits_from_request(request)
    return trait_engine.get_permissions(traits)

def has_permission(request: Request, permission: str) -> bool:
    """Check if user has specific permission"""
    permissions = get_user_permissions(request)
    return permission in permissions
```

## Week 2-3: User Management Plugin Architecture

### 3. Identity Provider Plugin System

**Create `api/app/plugins/identity/base.py`**

```python
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from dataclasses import dataclass
from api.app.plugins.base import BasePlugin

@dataclass
class User:
    """Universal user representation"""
    id: str
    username: str
    email: str
    full_name: str
    is_active: bool
    traits: List[str]
    groups: List[str]
    metadata: Dict[str, Any]
    created_at: datetime
    last_login: Optional[datetime] = None

    def has_trait(self, trait: str) -> bool:
        return trait in self.traits

    def has_group(self, group: str) -> bool:
        return group in self.groups

@dataclass
class Group:
    """User group with traits"""
    id: str
    name: str
    description: str
    traits: List[str]
    parent_group: Optional[str] = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

@dataclass
class Session:
    """User session with security context"""
    token: str
    user_id: str
    user: User
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    traits: List[str]  # Session-specific traits (e.g., mfa_verified)
    metadata: Dict[str, Any] = None
    elevation_at: Optional[datetime] = None
    elevation_expires_at: Optional[datetime] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

    def is_valid(self) -> bool:
        return datetime.utcnow() < self.expires_at and self.user.is_active

    def effective_traits(self) -> List[str]:
        """Combined user + session traits with elevation check"""
        traits = set(self.user.traits + self.traits)

        # Auto-drop elevated privileges if expired
        if self.elevation_expires_at and datetime.utcnow() > self.elevation_expires_at:
            traits.discard('phi_authorized')
            traits.discard('mfa_verified')

        return list(traits)

@dataclass
class AuthResult:
    """Authentication result"""
    success: bool
    user: Optional[User] = None
    session: Optional[Session] = None
    error: Optional[str] = None
    requires_mfa: bool = False
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}

class IdentityPlugin(FaxbotPlugin):
    """Base identity provider plugin interface"""
    plugin_type = "identity"
    required_scope = "trusted"
    traits = {"user_auth", "session_mgmt"}

class IdentityProvider(IdentityPlugin):

    @abstractmethod
    async def authenticate(self, credentials: Dict[str, Any]) -> AuthResult:
        """Authenticate user with credentials"""
        pass

    @abstractmethod
    async def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        pass

    @abstractmethod
    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        pass

    @abstractmethod
    async def get_user_groups(self, user_id: str) -> List[Group]:
        """Get all groups user belongs to"""
        pass

    @abstractmethod
    async def create_session(self, user_id: str, metadata: Dict[str, Any]) -> Session:
        """Create authenticated session"""
        pass

    @abstractmethod
    async def validate_session(self, session_token: str) -> Optional[Session]:
        """Validate existing session"""
        pass

    @abstractmethod
    async def refresh_session(self, session_token: str) -> Optional[Session]:
        """Refresh session expiration"""
        pass

    @abstractmethod
    async def revoke_session(self, session_token: str) -> bool:
        """Revoke session"""
        pass

    @abstractmethod
    async def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for user"""
        pass

    # Optional administrative operations
    async def create_user(self, user_data: Dict[str, Any]) -> Optional[User]:
        """Create new user (if supported)"""
        return None

    async def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """Update user (if supported)"""
        return False

    async def delete_user(self, user_id: str) -> bool:
        """Delete user (if supported)"""
        return False

    async def create_group(self, group_data: Dict[str, Any]) -> Optional[Group]:
        """Create new group (if supported)"""
        return None

    async def add_user_to_group(self, user_id: str, group_id: str) -> bool:
        """Add user to group (if supported)"""
        return False

    async def remove_user_from_group(self, user_id: str, group_id: str) -> bool:
        """Remove user from group (if supported)"""
        return False

    # Trait integration
    async def resolve_user_traits(self, user: User) -> List[str]:
        """Resolve effective traits for user (user + groups)"""
        traits = set(user.traits)

        # Add group traits
        groups = await self.get_user_groups(user.id)
        for group in groups:
            traits.update(group.traits)

        # Apply trait engine defaults
        from api.app.core.traits import trait_engine
        return trait_engine.resolve_default_traits(list(traits))
```

Current Faxbot Integration Map (Phase 2)

- Plugin registry/ingestor: continue to use `api/app/plugins/registry/{service,validator,signature}.py` for manifest validation and loader wiring.
- Identity providers: anchor implementations under existing shells `api/app/plugins/identity/{ldap,saml,oauth2}/` with the new typed `IdentityPlugin` base.
- Storage backends: no changes required, but user/group session artifacts must remain compatible with existing storage behavior when present.
- Events/webhooks: reuse `api/app/events/{bus,webhooks,delivery}.py`—extend with trait‑aware audit, do not fork a parallel bus.

### 4. Default SQLAlchemy Identity Provider

**Create `api/app/plugins/identity/providers/sqlalchemy.py`**

```python
import secrets
import argon2
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy import Column, String, DateTime, Boolean, Text, ForeignKey, Table, select
from sqlalchemy.orm import relationship
from api.app.plugins.identity.base import IdentityProvider, User, Group, Session, AuthResult
from api.app.plugins.base import FaxbotPlugin
from api.app.db import Base
# Use async DB to prevent event loop blocking
from api.app.db.async import AsyncSessionLocal
from api.app.core.audit import AuditLevel

# Association table for user-group many-to-many
user_groups = Table(
    'user_groups',
    Base.metadata,
    Column('user_id', String(40), ForeignKey('users.id'), primary_key=True),
    Column('group_id', String(40), ForeignKey('groups.id'), primary_key=True)
)

class DBUser(Base):
    """Database user model"""
    __tablename__ = "users"

    id = Column(String(40), primary_key=True, index=True)
    username = Column(String(100), unique=True, index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(200), nullable=False)
    password_hash = Column(String(200), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    traits = Column(Text, nullable=True)  # JSON array of traits
    metadata = Column(Text, nullable=True)  # JSON metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    # Relationships
    groups = relationship("DBGroup", secondary=user_groups, back_populates="users")
    sessions = relationship("DBSession", back_populates="user", cascade="all, delete-orphan")

class DBGroup(Base):
    """Database group model"""
    __tablename__ = "groups"

    id = Column(String(40), primary_key=True, index=True)
    name = Column(String(100), unique=True, index=True, nullable=False)
    description = Column(Text, nullable=True)
    traits = Column(Text, nullable=True)  # JSON array of traits
    parent_group_id = Column(String(40), ForeignKey('groups.id'), nullable=True)
    metadata = Column(Text, nullable=True)  # JSON metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    # Relationships
    users = relationship("DBUser", secondary=user_groups, back_populates="groups")
    parent_group = relationship("DBGroup", remote_side="DBGroup.id")

class DBSession(Base):
    """Database session model"""
    __tablename__ = "user_sessions"

    token = Column(String(128), primary_key=True, index=True)
    user_id = Column(String(40), ForeignKey('users.id'), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    traits = Column(Text, nullable=True)  # JSON array of session traits
    metadata = Column(Text, nullable=True)  # JSON metadata
    revoked_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("DBUser", back_populates="sessions")

class SQLAlchemyIdentityProvider(IdentityProvider):
    """Default SQLAlchemy-based identity provider"""

    def __init__(self, security_core, audit_logger, trait_engine, manifest):
        super().__init__(security_core, audit_logger, trait_engine, manifest)
        self.session_timeout_hours = 8  # Default session timeout

    async def initialize(self) -> bool:
        """Initialize the identity provider"""
        try:
            # Create tables
            from api.app.db import engine
            Base.metadata.create_all(bind=engine)

            # Create default admin user if none exists
            await self._create_default_admin()

            self.log_event('initialized', AuditLevel.STANDARD)
            return True

        except Exception as e:
            self.log_event('initialization_failed', AuditLevel.CRITICAL, error=str(e))
            return False

    async def shutdown(self) -> bool:
        """Shutdown the identity provider"""
        self.log_event('shutdown', AuditLevel.STANDARD)
        return True

    def _hash_password(self, password: str) -> str:
        """Hash password with Argon2id (HIPAA-compliant)"""
        ph = argon2.PasswordHasher(
            time_cost=3,  # Iterations
            memory_cost=65536,  # Memory in KB (64MB)
            parallelism=1,  # Threads
            hash_len=32,  # Hash length
            salt_len=16  # Salt length
        )
        return ph.hash(password)

    def _verify_password(self, password: str, hash: str) -> bool:
        """Verify password against Argon2id hash"""
        ph = argon2.PasswordHasher()
        try:
            ph.verify(hash, password)
            return True
        except argon2.exceptions.VerifyMismatchError:
            return False

    def _parse_json_field(self, field: Optional[str]) -> List[str]:
        """Parse JSON array field"""
        if not field:
            return []
        try:
            import json
            return json.loads(field)
        except:
            return []

    def _serialize_json_field(self, data: List[str]) -> str:
        """Serialize to JSON array"""
        import json
        return json.dumps(data)

    def _db_user_to_user(self, db_user: DBUser) -> User:
        """Convert database user to User object"""
        return User(
            id=db_user.id,
            username=db_user.username,
            email=db_user.email,
            full_name=db_user.full_name,
            is_active=db_user.is_active,
            traits=self._parse_json_field(db_user.traits),
            groups=[g.id for g in db_user.groups],
            metadata=self._parse_json_field(db_user.metadata) if db_user.metadata else {},
            created_at=db_user.created_at,
            last_login=db_user.last_login
        )

    def _db_group_to_group(self, db_group: DBGroup) -> Group:
        """Convert database group to Group object"""
        return Group(
            id=db_group.id,
            name=db_group.name,
            description=db_group.description or "",
            traits=self._parse_json_field(db_group.traits),
            parent_group=db_group.parent_group_id,
            metadata=self._parse_json_field(db_group.metadata) if db_group.metadata else {}
        )

    def _db_session_to_session(self, db_session: DBSession, user: User) -> Session:
        """Convert database session to Session object"""
        return Session(
            token=db_session.token,
            user_id=db_session.user_id,
            user=user,
            created_at=db_session.created_at,
            expires_at=db_session.expires_at,
            last_activity=db_session.last_activity,
            ip_address=db_session.ip_address or "",
            user_agent=db_session.user_agent or "",
            traits=self._parse_json_field(db_session.traits),
            metadata=self._parse_json_field(db_session.metadata) if db_session.metadata else {}
        )

    async def authenticate(self, credentials: Dict[str, Any]) -> AuthResult:
        """Authenticate user with username/password"""
        username = credentials.get('username')
        password = credentials.get('password')

        if not username or not password:
            self.log_event('authentication_failed', AuditLevel.HIGH,
                         reason='missing_credentials', username=username)
            return AuthResult(success=False, error="Username and password required")

        async with AsyncSessionLocal() as db:
            db_user = db.query(DBUser).filter(DBUser.username == username).first()

            if not db_user:
                self.log_event('authentication_failed', AuditLevel.HIGH,
                             reason='user_not_found', username=username)
                return AuthResult(success=False, error="Invalid credentials")

            if not db_user.is_active:
                self.log_event('authentication_failed', AuditLevel.HIGH,
                             reason='user_inactive', username=username, user_id=db_user.id)
                return AuthResult(success=False, error="Account disabled")

            if not self._verify_password(password, db_user.password_hash):
                self.log_event('authentication_failed', AuditLevel.HIGH,
                             reason='invalid_password', username=username, user_id=db_user.id)
                return AuthResult(success=False, error="Invalid credentials")

            # Update last login
            db_user.last_login = datetime.utcnow()
            await db.commit()

            user = self._db_user_to_user(db_user)

            self.log_event('authentication_successful', AuditLevel.STANDARD,
                         username=username, user_id=user.id)

            return AuthResult(success=True, user=user)

    async def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        async with AsyncSessionLocal() as db:
            db_user = db.query(DBUser).filter(DBUser.id == user_id).first()
            return self._db_user_to_user(db_user) if db_user else None

    async def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        async with AsyncSessionLocal() as db:
            db_user = db.query(DBUser).filter(DBUser.username == username).first()
            return self._db_user_to_user(db_user) if db_user else None

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        async with AsyncSessionLocal() as db:
            db_user = db.query(DBUser).filter(DBUser.email == email).first()
            return self._db_user_to_user(db_user) if db_user else None

    async def get_user_groups(self, user_id: str) -> List[Group]:
        """Get all groups user belongs to"""
        async with AsyncSessionLocal() as db:
            db_user = db.query(DBUser).filter(DBUser.id == user_id).first()
            if not db_user:
                return []
            return [self._db_group_to_group(g) for g in db_user.groups]

    async def create_session(self, user_id: str, metadata: Dict[str, Any]) -> Session:
        """Create authenticated session"""
        user = await self.get_user(user_id)
        if not user:
            raise ValueError(f"User {user_id} not found")

        # Generate secure session token
        session_token = secrets.token_urlsafe(64)

        expires_at = datetime.utcnow() + timedelta(hours=self.session_timeout_hours)

        async with AsyncSessionLocal() as db:
            db_session = DBSession(
                token=session_token,
                user_id=user_id,
                expires_at=expires_at,
                ip_address=metadata.get('ip_address'),
                user_agent=metadata.get('user_agent'),
                traits=self._serialize_json_field(metadata.get('traits', [])),
                metadata=self._serialize_json_field(metadata.get('additional', {}))
            )
            db.add(db_session)
            await db.commit()

            session = self._db_session_to_session(db_session, user)

            self.log_event('session_created', AuditLevel.STANDARD,
                         user_id=user_id, session_token=session_token[:8] + '...',
                         expires_at=expires_at.isoformat())

            return session

    async def validate_session(self, session_token: str) -> Optional[Session]:
        """Validate existing session"""
        async with AsyncSessionLocal() as db:
            db_session = db.query(DBSession).filter(
                DBSession.token == session_token,
                DBSession.revoked_at == None,
                DBSession.expires_at > datetime.utcnow()
            ).first()

            if not db_session:
                return None

            user = await self.get_user(db_session.user_id)
            if not user or not user.is_active:
                return None

            # Update last activity
            db_session.last_activity = datetime.utcnow()
            await db.commit()

            return self._db_session_to_session(db_session, user)

    async def refresh_session(self, session_token: str) -> Optional[Session]:
        """Refresh session expiration"""
        async with AsyncSessionLocal() as db:
            db_session = db.query(DBSession).filter(DBSession.token == session_token).first()

            if not db_session or db_session.revoked_at:
                return None

            # Extend expiration
            db_session.expires_at = datetime.utcnow() + timedelta(hours=self.session_timeout_hours)
            db_session.last_activity = datetime.utcnow()
            await db.commit()

            user = await self.get_user(db_session.user_id)
            if not user:
                return None

            self.log_event('session_refreshed', AuditLevel.STANDARD,
                         user_id=db_session.user_id, session_token=session_token[:8] + '...')

            return self._db_session_to_session(db_session, user)

    async def revoke_session(self, session_token: str) -> bool:
        """Revoke session"""
        async with AsyncSessionLocal() as db:
            db_session = db.query(DBSession).filter(DBSession.token == session_token).first()

            if not db_session:
                return False

            db_session.revoked_at = datetime.utcnow()
            await db.commit()

            self.log_event('session_revoked', AuditLevel.STANDARD,
                         user_id=db_session.user_id, session_token=session_token[:8] + '...')

            return True

    async def revoke_all_sessions(self, user_id: str) -> int:
        """Revoke all sessions for user"""
        async with AsyncSessionLocal() as db:
            count = db.query(DBSession).filter(
                DBSession.user_id == user_id,
                DBSession.revoked_at == None
            ).update({'revoked_at': datetime.utcnow()})
            await db.commit()

            self.log_event('all_sessions_revoked', AuditLevel.HIGH,
                         user_id=user_id, sessions_revoked=count)

            return count

    async def _create_default_admin(self):
        """Create default admin user if none exists"""
        async with AsyncSessionLocal() as db:
            admin_exists = db.query(DBUser).filter(DBUser.username == 'admin').first()

            if not admin_exists:
                import uuid
                admin_id = uuid.uuid4().hex
                default_password = secrets.token_urlsafe(16)  # Generate random password

                admin_user = DBUser(
                    id=admin_id,
                    username='admin',
                    email='admin@faxbot.local',
                    full_name='Default Administrator',
                    password_hash=self._hash_password(default_password),
                    is_active=True,
                    traits=self._serialize_json_field(['admin_capable', 'non_hipaa', 'fax_capable'])
                )

                db.add(admin_user)
                await db.commit()

            # Do not log or print credentials. Surface a one-time setup notice in the Admin Console
            # prompting the operator to set a secure administrator password on first login.
```

## Week 3-4: Dual Authentication System

### 5. Enhanced SecurityCore with Session Support

**Enhance `api/app/core/security.py`**

```python
from typing import Dict, Any, List, Optional, Union
from api.app.auth import verify_db_key
from api.app.audit import audit_event
from api.app.plugins.identity.base import Session, User

class AuthContext:
    """Unified authentication context"""
    def __init__(self, auth_type: str, user_id: str, traits: List[str],
                 permissions: List[str], metadata: Dict[str, Any] = None):
        self.auth_type = auth_type  # 'api_key' or 'session'
        self.user_id = user_id
        self.traits = traits
        self.permissions = permissions
        self.metadata = metadata or {}
        self.authenticated = True

    def has_trait(self, trait: str) -> bool:
        return trait in self.traits

    def has_permission(self, permission: str) -> bool:
        return permission in self.permissions

class DualSecurityCore:
    """Enhanced SecurityCore supporting both API keys and sessions"""

    def __init__(self, identity_provider=None):
        self.identity_provider = identity_provider
        self.auth_cache = {}

    def set_identity_provider(self, provider):
        """Set identity provider (injected after initialization)"""
        self.identity_provider = provider

    async def authenticate_request(self, api_key: Optional[str] = None,
                                 session_token: Optional[str] = None) -> Optional[AuthContext]:
        """Unified authentication supporting both methods"""

        # Try session authentication first
        if session_token:
            session_auth = await self._authenticate_session(session_token)
            if session_auth:
                return session_auth

        # Fall back to API key authentication
        if api_key:
            api_auth = await self._authenticate_api_key(api_key)
            if api_auth:
                return api_auth

        # No valid authentication
        audit_event('authentication_failed', reason='no_valid_credentials')
        return None

    async def _authenticate_session(self, session_token: str) -> Optional[AuthContext]:
        """Authenticate via session token"""
        if not self.identity_provider:
            return None

        try:
            session = await self.identity_provider.validate_session(session_token)
            if not session or not session.is_valid():
                audit_event('session_authentication_failed',
                           reason='invalid_session',
                           session_token=session_token[:8] + '...')
                return None

            # Get effective traits
            from api.app.core.traits import trait_engine
            effective_traits = await self.identity_provider.resolve_user_traits(session.user)

            # Add session-specific traits
            all_traits = list(set(effective_traits + session.traits + ['session_based']))

            # Get permissions from traits
            permissions = trait_engine.get_permissions(all_traits)

            audit_event('session_authentication_success',
                       user_id=session.user_id,
                       session_token=session_token[:8] + '...',
                       traits=all_traits)

            return AuthContext(
                auth_type='session',
                user_id=session.user_id,
                traits=all_traits,
                permissions=permissions,
                metadata={
                    'username': session.user.username,
                    'email': session.user.email,
                    'full_name': session.user.full_name,
                    'session_created': session.created_at.isoformat(),
                    'last_activity': session.last_activity.isoformat()
                }
            )

        except Exception as e:
            audit_event('session_authentication_error',
                       session_token=session_token[:8] + '...',
                       error=str(e))
            return None

    async def _authenticate_api_key(self, api_key: str) -> Optional[AuthContext]:
        """Authenticate via API key (existing system)"""
        auth_info = verify_db_key(api_key)

        if not auth_info:
            audit_event('api_key_authentication_failed', reason='invalid_api_key')
            return None

        # Convert API key scopes to traits
        from api.app.core.traits import trait_engine
        traits = trait_engine.resolve_traits_from_auth(auth_info)
        traits.append('api_key_based')  # Mark as API key auth

        # Get permissions from traits
        permissions = trait_engine.get_permissions(traits)

        audit_event('api_key_authentication_success',
                   key_id=auth_info.get('key_id'),
                   scopes=auth_info.get('scopes'),
                   traits=traits)

        return AuthContext(
            auth_type='api_key',
            user_id=auth_info.get('key_id', 'unknown'),  # Use key_id as user_id for API keys
            traits=traits,
            permissions=permissions,
            metadata={
                'key_name': auth_info.get('name'),
                'scopes': auth_info.get('scopes', [])
            }
        )

    def authorize_action(self, auth_context: AuthContext, resource: str, action: str) -> bool:
        """Enhanced authorization with detailed audit"""
        if not auth_context:
            return False

        # Check permission directly
        required_permission = f"{resource}:{action}"
        has_direct_permission = required_permission in auth_context.permissions

        # Check admin override
        has_admin_permission = 'admin:all' in auth_context.permissions

        # Check wildcard permission
        has_wildcard_permission = f"{resource}:*" in auth_context.permissions

        authorized = has_direct_permission or has_admin_permission or has_wildcard_permission

        audit_event('authorization_check',
                   user_id=auth_context.user_id,
                   auth_type=auth_context.auth_type,
                   resource=resource,
                   action=action,
                   required_permission=required_permission,
                   available_permissions=auth_context.permissions,
                   traits=auth_context.traits,
                   authorized=authorized)

        return authorized
```

### 6. Session Management Endpoints

**Create `api/app/routers/auth.py`**

```python
from fastapi import APIRouter, HTTPException, Request, Response, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from typing import Optional, Dict, Any
from api.app.core import core_platform

router = APIRouter(prefix="/auth", tags=["Authentication"])

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    success: bool
    session_token: Optional[str] = None
    user: Optional[Dict[str, Any]] = None
    ui_adaptations: Optional[Dict[str, Any]] = None
    expires_at: Optional[str] = None

@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, http_request: Request):
    """User login with session creation"""

    if not core_platform.plugin_manager.get_plugin('identity'):
        raise HTTPException(503, "Identity provider not available")

    identity_provider = core_platform.plugin_manager.get_plugin('identity')

    # Authenticate user
    credentials = {
        'username': request.username,
        'password': request.password
    }

    auth_result = await identity_provider.authenticate(credentials)

    if not auth_result.success:
        raise HTTPException(401, auth_result.error or "Authentication failed")

    # Create session
    session_metadata = {
        'ip_address': http_request.client.host if http_request.client else None,
        'user_agent': http_request.headers.get('user-agent', ''),
        'traits': [],  # Session-specific traits can be added here
        'additional': {}
    }

    session = await identity_provider.create_session(auth_result.user.id, session_metadata)

    # Get effective traits and UI adaptations
    traits = await identity_provider.resolve_user_traits(auth_result.user)
    from api.app.core.traits import trait_engine
    ui_adaptations = trait_engine.get_ui_adaptations(traits)

    return LoginResponse(
        success=True,
        session_token=session.token,
        user={
            'id': auth_result.user.id,
            'username': auth_result.user.username,
            'email': auth_result.user.email,
            'full_name': auth_result.user.full_name,
            'traits': traits
        },
        ui_adaptations=ui_adaptations,
        expires_at=session.expires_at.isoformat()
    )

@router.post("/logout")
async def logout(request: Request):
    """User logout with session revocation"""
    session_token = request.headers.get('authorization', '').replace('Bearer ', '')

    if not session_token:
        raise HTTPException(400, "No session token provided")

    identity_provider = core_platform.plugin_manager.get_plugin('identity')
    if identity_provider:
        await identity_provider.revoke_session(session_token)

    return {"success": True, "message": "Logged out successfully"}

@router.get("/me")
async def get_current_user(request: Request):
    """Get current user information"""
    # This will use the enhanced authentication middleware
    auth_context = getattr(request.state, 'auth_context', None)

    if not auth_context:
        raise HTTPException(401, "Not authenticated")

    from ..core.traits import trait_engine
    ui_adaptations = trait_engine.get_ui_adaptations(auth_context.traits)

    return {
        'user_id': auth_context.user_id,
        'auth_type': auth_context.auth_type,
        'traits': auth_context.traits,
        'permissions': auth_context.permissions,
        'ui_adaptations': ui_adaptations,
        'metadata': auth_context.metadata
    }

@router.post("/refresh")
async def refresh_session(request: Request):
    """Refresh session expiration"""
    session_token = request.headers.get('authorization', '').replace('Bearer ', '')

    if not session_token:
        raise HTTPException(400, "No session token provided")

    identity_provider = core_platform.plugin_manager.get_plugin('identity')
    if not identity_provider:
        raise HTTPException(503, "Identity provider not available")

    session = await identity_provider.refresh_session(session_token)

    if not session:
        raise HTTPException(401, "Invalid or expired session")

    return {
        'success': True,
        'expires_at': session.expires_at.isoformat()
    }
```

## Week 4: Secure Session & Cookie Implementation

### 6.5. Cookie-Based Session Management (HIPAA-Friendly)

**Create `api/app/middleware/session.py`**

```python
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
import secrets
from datetime import datetime, timedelta

class SecureSessionMiddleware(BaseHTTPMiddleware):
    """HIPAA-friendly session management with secure cookies"""

    def __init__(self, app):
        super().__init__(app)
        self.session_timeout_hours = 8

    async def dispatch(self, request: Request, call_next):
        # Generate CSRF token for forms
        if request.url.path.startswith('/admin'):
            csrf_token = request.cookies.get('fb_csrf') or secrets.token_urlsafe(32)

        response = await call_next(request)

        # Set session cookie with secure attributes
        if hasattr(request.state, 'new_session_token'):
            self._set_session_cookie(response, request.state.new_session_token)

        # Set/refresh CSRF token cookie
        if request.url.path.startswith('/admin') and csrf_token:
            self._set_csrf_cookie(response, csrf_token)

        return response

    def _set_session_cookie(self, response: Response, session_token: str):
        """Set secure session cookie"""
        response.set_cookie(
            key='fb_session',
            value=session_token,
            max_age=self.session_timeout_hours * 3600,  # 8 hours
            httponly=True,  # Prevent XSS access
            secure=True,    # HTTPS only
            samesite='strict',  # CSRF protection
            path='/'
        )

    def _set_csrf_cookie(self, response: Response, csrf_token: str):
        """Set CSRF token cookie (readable by JavaScript)"""
        response.set_cookie(
            key='fb_csrf',
            value=csrf_token,
            max_age=self.session_timeout_hours * 3600,
            httponly=False,  # Accessible to JS for form submission
            secure=True,
            samesite='strict',
            path='/'
        )

    def _rotate_session_on_elevation(self, old_token: str) -> str:
        """Rotate session token on privilege elevation"""
        # This will be called when user gains phi_authorized or other elevated traits
        return secrets.token_urlsafe(64)
```

**Update `api/app/routers/auth.py` for cookie support**

```python
@router.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest, http_request: Request, response: Response):
    """User login with secure cookie session"""

    # ... existing authentication logic ...

    session = await identity_provider.create_session(auth_result.user.id, session_metadata)

    # Set secure session cookie instead of returning token
    response.set_cookie(
        key='fb_session',
        value=session.token,
        max_age=8 * 3600,  # 8 hours
        httponly=True,
        secure=True,
        samesite='strict',
        path='/'
    )

    # Don't return session_token in response body for security
    return LoginResponse(
        success=True,
        session_token=None,  # Not exposed to JavaScript
        user=user_dict,
        ui_adaptations=ui_adaptations,
        expires_at=session.expires_at.isoformat()
    )
```

## Week 5: Enhanced Authentication Middleware

### 7. Unified Authentication Middleware

**Create `api/app/middleware/auth.py`**

```python
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from api.app.core import core_platform

class UnifiedAuthMiddleware(BaseHTTPMiddleware):
    """Middleware supporting both API keys and sessions"""

    def __init__(self, app):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        # Skip auth for public endpoints
        if self._is_public_endpoint(request.url.path):
            response = await call_next(request)
            return response

        # Extract authentication credentials
        api_key = request.headers.get('X-API-Key')
        session_token = self._extract_session_token(request)

        # Authenticate request
        auth_context = await core_platform.security.authenticate_request(
            api_key=api_key,
            session_token=session_token
        )

        if auth_context:
            # Store auth context in request state
            request.state.auth_context = auth_context
            request.state.auth_info = self._convert_to_legacy_format(auth_context)  # Backward compatibility
            request.state.user_traits = auth_context.traits

            # Continue processing
            response = await call_next(request)

            # Update session activity if session-based
            if auth_context.auth_type == 'session' and session_token:
                await self._update_session_activity(session_token)

            return response
        else:
            # Authentication failed
            if self._requires_auth(request.url.path):
                raise HTTPException(401, "Authentication required")
            else:
                # Continue without auth for optional-auth endpoints
                response = await call_next(request)
                return response

    def _extract_session_token(self, request: Request) -> Optional[str]:
        """Extract session token from secure cookie or Authorization header"""
        # Primary: Secure HTTP-only cookie (preferred for admin console)
        session_token = request.cookies.get('fb_session')
        if session_token:
            return session_token

        # Fallback: Bearer token in Authorization header (for API clients)
        auth_header = request.headers.get('authorization', '')
        if auth_header.startswith('Bearer '):
            return auth_header[7:]

        return None

    def _is_public_endpoint(self, path: str) -> bool:
        """Check if endpoint is public (no auth required)"""
        public_paths = [
            '/docs', '/openapi.json', '/redoc',
            '/health', '/ping',
            '/auth/login',
            '/auth/register',  # If registration is enabled
        ]

        for public_path in public_paths:
            if path.startswith(public_path):
                return True
        return False

    def _requires_auth(self, path: str) -> bool:
        """Check if endpoint requires authentication"""
        # Most endpoints require auth by default
        optional_auth_paths = []  # Add paths that work better with optional auth

        for optional_path in optional_auth_paths:
            if path.startswith(optional_path):
                return False
        return True

    def _convert_to_legacy_format(self, auth_context) -> Dict[str, Any]:
        """Convert AuthContext to legacy auth_info format for backward compatibility"""
        from api.app.core.traits import trait_engine

        if auth_context.auth_type == 'api_key':
            return {
                'key_id': auth_context.user_id,
                'name': auth_context.metadata.get('key_name'),
                'scopes': auth_context.metadata.get('scopes', [])
            }
        else:
            # Convert session to API key format for backward compatibility
            legacy_scopes = trait_engine.permissions_to_legacy_scopes(auth_context.permissions)
            return {
                'key_id': f"session_{auth_context.user_id}",
                'name': auth_context.metadata.get('full_name', auth_context.metadata.get('username')),
                'scopes': legacy_scopes  # Use converted legacy scopes
            }

    async def _update_session_activity(self, session_token: str):
        """Update session last activity timestamp"""
        identity_provider = core_platform.plugin_manager.get_plugin('identity')
        if identity_provider:
            try:
                await identity_provider.validate_session(session_token)  # This updates last_activity
            except:
                pass  # Ignore errors in activity update
```

### 8. Efficient UI Config Endpoint (Replaces Header Method)

**Create `api/app/routers/ui_config.py`**

```python
from fastapi import APIRouter, Request, HTTPException, Header
from typing import Optional
from api.app.core.traits import trait_engine
from api.app.core import core_platform

router = APIRouter(prefix="/admin", tags=["UI Configuration"])

@router.get("/ui-config")
async def get_ui_config(request: Request, if_none_match: Optional[str] = Header(None)):
    """Get UI configuration with ETag caching"""
    auth_context = getattr(request.state, 'auth_context', None)

    if not auth_context:
        raise HTTPException(401, "Authentication required")

    # Generate UI configuration
    config = {
        'traits': auth_context.traits,
        'permissions': auth_context.permissions,
        'ui_adaptations': trait_engine.get_ui_adaptations(auth_context.traits),
        'theme': trait_engine.get_ui_adaptations(auth_context.traits).get('theme', 'business'),
        'user_info': {
            'user_id': auth_context.user_id,
            'auth_type': auth_context.auth_type,
            'metadata': auth_context.metadata
        }
    }

    # Generate ETag based on content
    import hashlib
    import json
    content_hash = hashlib.md5(json.dumps(config, sort_keys=True).encode()).hexdigest()
    etag = f'"{content_hash}"'

    # Check if client has current version
    if if_none_match == etag:
        return Response(status_code=304)  # Not Modified

    # Return config with ETag
    response = JSONResponse(config)
    response.headers['ETag'] = etag
    response.headers['Cache-Control'] = 'private, max-age=300'  # 5-minute cache

    return response

# Remove the previous header-based UI adaptation middleware - no longer needed
```

## Blocking I/O Audit (dev helper)

```bash
# Run from repo root to surface blocking/sync usage on hot paths
echo "== requests/http sync use ==" && rg -n "requests\."
echo "== sync SQLAlchemy in async context ==" && rg -n "\.query\(" api/app | rg -v "tests?/"
echo "== subprocess blocking ==" && rg -n "subprocess\.(run|Popen|check_)" api/app
echo "== time.sleep ==" && rg -n "time\.sleep\(" api/app
echo "== file open on hot path ==" && rg -n "open\(" api/app | rg -v "(migrations|setup|tests?)/"
echo "== os.walk on request path ==" && rg -n "os\.walk\(" api/app
echo "== sync YAML/JSON loads per-request ==" && rg -n "(yaml|json)\.(load|loads)\(" api/app | rg -v "config/bootstrap|startup"
```

## Week 5-6: Admin Console Integration

### 9. User Management Admin UI

**Create `api/admin_ui/src/components/UserManagement.tsx`**

```typescript
import React, { useState, useEffect } from 'react';
import {
  Paper, Typography, Button, Table, TableBody, TableCell, TableContainer,
  TableHead, TableRow, Dialog, DialogTitle, DialogContent, DialogActions,
  TextField, Chip, Box, Alert, Stack, Switch, FormControlLabel
} from '@mui/material';
import { ResponsiveCard } from './common/ResponsiveCard';
import { ResponsiveFormSection, ResponsiveTextField, ResponsiveSelect } from './common/ResponsiveFormFields';

interface User {
  id: string;
  username: string;
  email: string;
  full_name: string;
  is_active: boolean;
  traits: string[];
  groups: string[];
  created_at: string;
  last_login?: string;
}

interface UserManagementProps {
  client: AdminAPIClient;
  docsBase?: string;
}

export default function UserManagement({ client, docsBase }: UserManagementProps) {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [createDialogOpen, setCreateDialogOpen] = useState(false);
  const [newUser, setNewUser] = useState({
    username: '',
    email: '',
    full_name: '',
    password: '',
    traits: [] as string[],
    is_active: true
  });

  const availableTraits = [
    'hipaa_compliant',
    'non_hipaa',
    'fax_capable',
    'email_capable',
    'admin_capable',
    'phi_authorized',
    'mfa_enabled'
  ];

  useEffect(() => {
    loadUsers();
  }, []);

  const loadUsers = async () => {
    setLoading(true);
    try {
      const response = await client.get('/admin/users');
      setUsers(response.data.users || []);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load users');
    } finally {
      setLoading(false);
    }
  };

  const createUser = async () => {
    try {
      await client.post('/admin/users', newUser);
      setCreateDialogOpen(false);
      setNewUser({
        username: '',
        email: '',
        full_name: '',
        password: '',
        traits: [],
        is_active: true
      });
      await loadUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to create user');
    }
  };

  const toggleUserActive = async (userId: string, isActive: boolean) => {
    try {
      await client.patch(`/admin/users/${userId}`, { is_active: isActive });
      await loadUsers();
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to update user');
    }
  };

  const getTraitColor = (trait: string) => {
    if (trait === 'hipaa_compliant') return 'error';
    if (trait === 'admin_capable') return 'warning';
    if (trait.includes('capable')) return 'primary';
    return 'default';
  };

  return (
    <ResponsiveCard title="User Management" subtitle="Manage platform users and permissions">
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 3 }}>
        <Typography variant="h6">
          Users ({users.length})
        </Typography>
        <Button
          variant="contained"
          onClick={() => setCreateDialogOpen(true)}
          sx={{ borderRadius: 2 }}
        >
          Create User
        </Button>
      </Box>

      <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
        <Table>
          <TableHead>
            <TableRow>
              <TableCell>Username</TableCell>
              <TableCell>Full Name</TableCell>
              <TableCell>Email</TableCell>
              <TableCell>Traits</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Last Login</TableCell>
              <TableCell>Actions</TableCell>
            </TableRow>
          </TableHead>
          <TableBody>
            {users.map((user) => (
              <TableRow key={user.id}>
                <TableCell>{user.username}</TableCell>
                <TableCell>{user.full_name}</TableCell>
                <TableCell>{user.email}</TableCell>
                <TableCell>
                  <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5 }}>
                    {user.traits.map((trait) => (
                      <Chip
                        key={trait}
                        label={trait}
                        size="small"
                        color={getTraitColor(trait)}
                        sx={{ fontSize: '0.75rem' }}
                      />
                    ))}
                  </Box>
                </TableCell>
                <TableCell>
                  <Switch
                    checked={user.is_active}
                    onChange={(e) => toggleUserActive(user.id, e.target.checked)}
                    size="small"
                  />
                  <Typography variant="body2" sx={{ ml: 1, display: 'inline' }}>
                    {user.is_active ? 'Active' : 'Disabled'}
                  </Typography>
                </TableCell>
                <TableCell>
                  {user.last_login
                    ? new Date(user.last_login).toLocaleDateString()
                    : 'Never'
                  }
                </TableCell>
                <TableCell>
                  <Button size="small" variant="outlined">
                    Edit
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </TableContainer>

      {/* Create User Dialog */}
      <Dialog
        open={createDialogOpen}
        onClose={() => setCreateDialogOpen(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Create New User</DialogTitle>
        <DialogContent>
          <ResponsiveFormSection title="User Information">
            <Stack spacing={2} sx={{ mt: 2 }}>
              <ResponsiveTextField
                label="Username"
                value={newUser.username}
                onChange={(value) => setNewUser({...newUser, username: value})}
                required
              />
              <ResponsiveTextField
                label="Email"
                type="email"
                value={newUser.email}
                onChange={(value) => setNewUser({...newUser, email: value})}
                required
              />
              <ResponsiveTextField
                label="Full Name"
                value={newUser.full_name}
                onChange={(value) => setNewUser({...newUser, full_name: value})}
                required
              />
              <ResponsiveTextField
                label="Password"
                type="password"
                value={newUser.password}
                onChange={(value) => setNewUser({...newUser, password: value})}
                required
                helperText="Minimum 8 characters"
              />
              <FormControlLabel
                control={
                  <Switch
                    checked={newUser.is_active}
                    onChange={(e) => setNewUser({...newUser, is_active: e.target.checked})}
                  />
                }
                label="Active"
              />
            </Stack>
          </ResponsiveFormSection>

          <ResponsiveFormSection title="Traits & Permissions" sx={{ mt: 3 }}>
            <Typography variant="body2" sx={{ mb: 2 }}>
              Select traits that define the user's capabilities and compliance requirements
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
              {availableTraits.map((trait) => (
                <Chip
                  key={trait}
                  label={trait}
                  color={newUser.traits.includes(trait) ? getTraitColor(trait) : 'default'}
                  variant={newUser.traits.includes(trait) ? 'filled' : 'outlined'}
                  onClick={() => {
                    if (newUser.traits.includes(trait)) {
                      setNewUser({
                        ...newUser,
                        traits: newUser.traits.filter(t => t !== trait)
                      });
                    } else {
                      setNewUser({
                        ...newUser,
                        traits: [...newUser.traits, trait]
                      });
                    }
                  }}
                  sx={{ cursor: 'pointer' }}
                />
              ))}
            </Box>

            {newUser.traits.includes('hipaa_compliant') && (
              <Alert severity="warning" sx={{ mt: 2 }}>
                <Typography variant="body2">
                  HIPAA-compliant users require additional security measures and audit logging.
                  Ensure proper training and access controls are in place.
                </Typography>
              </Alert>
            )}
          </ResponsiveFormSection>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCreateDialogOpen(false)}>Cancel</Button>
          <Button
            onClick={createUser}
            variant="contained"
            disabled={!newUser.username || !newUser.email || !newUser.full_name || !newUser.password}
          >
            Create User
          </Button>
        </DialogActions>
      </Dialog>

      <Box sx={{ mt: 3, display: 'flex', gap: 2 }}>
        <Button
          variant="outlined"
          onClick={() => window.open(`${docsBase}/user-management/getting-started`)}
        >
          📚 User Management Guide
        </Button>
        <Button
          variant="outlined"
          onClick={() => window.open(`${docsBase}/user-management/traits-system`)}
        >
          🏷️ Traits Reference
        </Button>
      </Box>
    </ResponsiveCard>
  );
}
```

### 10. Login Component

**Create `api/admin_ui/src/components/Login.tsx`**

```typescript
import React, { useState } from 'react';
import {
  Paper, TextField, Button, Typography, Alert, Box, Card, CardContent
} from '@mui/material';

interface LoginProps {
  onLogin: (sessionToken: string, user: any, uiAdaptations: any) => void;
  client: AdminAPIClient;
}

export default function Login({ onLogin, client }: LoginProps) {
  const [credentials, setCredentials] = useState({ username: '', password: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    try {
      const response = await client.post('/auth/login', credentials);
      const { session_token, user, ui_adaptations } = response.data;

      // Session token will be set via secure HTTP-only cookie automatically
      // No need to store in localStorage (XSS risk eliminated)

      // Apply UI adaptations immediately
      document.body.setAttribute('data-theme', ui_adaptations.theme || 'business');

      onLogin(session_token, user, ui_adaptations);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      sx={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: '100vh',
        bgcolor: 'background.default'
      }}
    >
      <Card sx={{ width: 400, borderRadius: 3, p: 2 }}>
        <CardContent>
          <Typography variant="h4" component="h1" align="center" sx={{ mb: 3 }}>
            Faxbot Login
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <form onSubmit={handleLogin}>
            <TextField
              label="Username"
              fullWidth
              margin="normal"
              value={credentials.username}
              onChange={(e) => setCredentials({...credentials, username: e.target.value})}
              required
              sx={{ borderRadius: 2 }}
            />

            <TextField
              label="Password"
              type="password"
              fullWidth
              margin="normal"
              value={credentials.password}
              onChange={(e) => setCredentials({...credentials, password: e.target.value})}
              required
              sx={{ borderRadius: 2 }}
            />

            <Button
              type="submit"
              fullWidth
              variant="contained"
              size="large"
              disabled={loading || !credentials.username || !credentials.password}
              sx={{ mt: 3, borderRadius: 2, height: 48 }}
            >
              {loading ? 'Signing In...' : 'Sign In'}
            </Button>
          </form>

          <Box sx={{ mt: 3, textAlign: 'center' }}>
            <Typography variant="body2" color="text.secondary">
              Don't have an account? Contact your administrator.
            </Typography>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}
```

## Week 6-7: Security Hardening & Testing

### 10. Privacy Linter & Audit Compliance

**Create `api/app/core/privacy_linter.py`**

```python
import re
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class PrivacyViolation:
    field: str
    value: str
    violation_type: str
    severity: str
    line_number: Optional[int] = None

class PrivacyLinter:
    """Prevents PHI and secrets from entering logs"""

    # Patterns that should never appear in logs
    PROHIBITED_PATTERNS = {
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
        'password': r'(password|pwd|pass)["\s]*[:=]["\s]*[^"\s]+',
        'api_key': r'["\s](sk|pk|api)_[a-zA-Z0-9]{20,}["\s]',
        'jwt_token': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
        'session_token': r'fb_session["\s]*[:=]["\s]*[a-zA-Z0-9_-]{32,}',
        'email_partial': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',  # Only in non-audit contexts
        'phone_number': r'\b\d{3}-\d{3}-\d{4}\b|\(\d{3}\)\s*\d{3}-\d{4}',
    }

    def scan_log_content(self, content: str, context: str = "general") -> List[PrivacyViolation]:
        """Scan content for privacy violations"""
        violations = []

        for violation_type, pattern in self.PROHIBITED_PATTERNS.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                # Email addresses are OK in audit contexts
                if violation_type == 'email_partial' and context == 'audit':
                    continue

                violations.append(PrivacyViolation(
                    field=violation_type,
                    value=match.group(),
                    violation_type=violation_type,
                    severity='CRITICAL' if violation_type in ['ssn', 'credit_card'] else 'HIGH'
                ))

        return violations

    def redact_sensitive_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Redact sensitive data for logging"""
        safe_data = {}

        for key, value in data.items():
            if isinstance(value, str):
                # Always redact tokens and passwords
                if 'token' in key.lower() or 'password' in key.lower() or 'secret' in key.lower():
                    safe_data[key] = value[:8] + '...' if len(value) > 8 else '[REDACTED]'
                # Redact email addresses (keep domain for debugging)
                elif '@' in value:
                    parts = value.split('@')
                    if len(parts) == 2:
                        safe_data[key] = f"{parts[0][:2]}***@{parts[1]}"
                    else:
                        safe_data[key] = '[REDACTED]'
                else:
                    safe_data[key] = value
            else:
                safe_data[key] = value

        return safe_data

# Update AuditLogger to use privacy linter
def audit_event(level: str, actor: str, subject: str, action: str,
               result: str, correlation_id: str = None, **kwargs):
    """Standardized audit event with privacy protection"""
    from api.app.core.privacy_linter import PrivacyLinter

    linter = PrivacyLinter()
    safe_kwargs = linter.redact_sensitive_data(kwargs)

    audit_record = {
        'timestamp': datetime.utcnow().isoformat(),
        'level': level,
        'actor': actor,
        'subject': subject,
        'action': action,
        'result': result,
        'correlation_id': correlation_id or secrets.token_hex(8),
        **safe_kwargs
    }

    # Log the audit record
    logger.info(f"AUDIT: {json.dumps(audit_record)}")
```

## Security & Testing Checklist

### 🔐 **Security Verification (Pre-Implementation)**

#### Authentication & Session Security
- [ ] **Argon2id password hashing** with tuned parameters (time_cost=3, memory_cost=65536)
- [ ] **HTTP-only cookies** for session tokens (no localStorage)
- [ ] **Secure, SameSite=Strict** cookie attributes
- [ ] **CSRF token protection** for state-changing operations
- [ ] **Session rotation** on login and privilege elevation
- [ ] **Auto-expiry of elevated privileges** (`phi_authorized` drops after timeout)
- [ ] **Brute-force protection** with exponential backoff per account and IP

#### Permission & Trait System
- [ ] **Permission grammar validation** (`{namespace}.{resource}:{action}`)
- [ ] **Trait precedence rules** (deny > allow)
- [ ] **Group hierarchy cycle detection** with depth limiting
- [ ] **Legacy scope compatibility** via explicit mapping
- [ ] **MFA scaffolding** for TOTP (WebAuthn later)

#### Privacy & Audit Compliance
- [ ] **No PHI in logs** - privacy linter prevents leakage
- [ ] **Structured audit events** with correlation IDs
- [ ] **Token redaction** in logs (first 8 chars only)
- [ ] **Audit retention policy** for compliance requirements

#### Infrastructure Security
- [ ] **TLS everywhere** with HSTS headers
- [ ] **Database migrations** via Alembic
- [ ] **Async DB operations** (no event loop blocking)
- [ ] **Admin Console CORS** locked to known origins

### 🧪 **Testing Requirements (Implementation Phase)**

#### Unit Tests (per component)
- [ ] **Trait validation** - requires/incompatible, permission expansion
- [ ] **Password hashing** - Argon2id verification, timing attacks
- [ ] **Session management** - creation, validation, expiry, rotation
- [ ] **Group hierarchy** - cycle detection, depth limits
- [ ] **Permission mapping** - trait → permission → legacy scope
- [ ] **Privacy linter** - PHI detection, redaction accuracy

#### Integration Tests (end-to-end flows)
- [ ] **Login/logout/refresh** - cookie-based and bearer token flows
- [ ] **MFA elevation** - privilege grant and auto-expiry
- [ ] **API key compatibility** - existing clients continue working
- [ ] **Admin Console UI** - user management, trait assignment
- [ ] **Dual authentication** - API keys and sessions coexist

#### Security Tests (attack scenarios)
- [ ] **Brute-force resistance** - account lockout, rate limiting
- [ ] **Session fixation** - token regeneration on login
- [ ] **CSRF protection** - token validation on state changes
- [ ] **XSS prevention** - no token access from JavaScript
- [ ] **Log redaction** - no secrets or PHI leak to logs

#### Performance Tests (scalability)
- [ ] **Trait resolution** ≤ 2ms p95 for 50 traits
- [ ] **Session lookup** ≤ 5ms p95 with database indexes
- [ ] **UI config endpoint** - ETag caching effectiveness
- [ ] **Permission checks** - sub-millisecond authorization

### 📋 **Acceptance Criteria**

Before Phase 2 completion, verify:
1. **All existing API key clients work unchanged**
2. **Admin Console login uses secure cookies (not localStorage)**
3. **HIPAA-compliant users see appropriate UI adaptations**
4. **Elevated privileges auto-expire** (phi_authorized drops after timeout)
5. **No PHI or secrets appear in any log files**
6. **MFA flows are scaffolded** (implementation ready for Phase 3)
7. **Database performance** meets scalability targets
8. **Privacy linter catches** all prohibited patterns in CI

## Integration & Testing Plan

<function_calls>
<invoke name="TodoWrite">
<parameter name="todos">[{"content": "Create detailed Phase 2 implementation plan", "status": "completed", "activeForm": "Creating detailed Phase 2 implementation plan"}, {"content": "Analyze Phase 1 dependencies for Phase 2 design", "status": "completed", "activeForm": "Analyzing Phase 1 dependencies for Phase 2 design"}, {"content": "Design trait-based auth system architecture", "status": "completed", "activeForm": "Designing trait-based auth system architecture"}, {"content": "Plan user management integration strategy", "status": "completed", "activeForm": "Planning user management integration strategy"}, {"content": "Create timeline and implementation order for Phase 2", "status": "completed", "activeForm": "Creating timeline and implementation order for Phase 2"}]
