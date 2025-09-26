# Phase 3: Hierarchical Configuration, Diagnostics, and Enterprise Reliability

**Branch**: `auto-tunnel` (CRITICAL - all v4 work stays here)
**Status**: Detailed implementation plan with head planning agent feedback applied

## Executive Summary

Phase 3 transforms the Phase 1/2 foundation into an enterprise-ready platform: hierarchical configuration (Global → Tenant → Department → Group → User) with Admin Console management, Redis-backed caching with precise invalidation, canonical events lifecycle, webhook hardening with circuit breakers, provider health monitoring, rate limiting, and MCP SSE OAuth validation for HIPAA compliance. All work maintains Admin Console-first, traits-first, and HIPAA-aligned principles (no PHI in logs or streams).

**Dependencies**: Phase 1 (platform core, plugins, HybridConfigProvider) and Phase 2 (trait-based auth, user management) must be 100% complete.
**Timeline**: 5-6 weeks
**Goal**: Production-ready enterprise configuration and reliability layer

## Phase 1 & Phase 2 Integration Points

### Required Phase 1 Components:
- ✅ `SecurityCore` - Enhanced with configuration-aware auth policies
- ✅ `PluginManager` - Extended with health monitoring and circuit breakers
- ✅ `HybridConfigProvider` - Evolved to full hierarchical configuration
- ✅ `CanonicalMessage` - Enhanced with event lifecycle tracking
- ✅ `AuditLogger` - Extended with configuration change auditing

### Required Phase 2 Components:
- ✅ `TraitEngine` - Used for configuration access control
- ✅ `IdentityProvider` - Provides user context for config resolution
- ✅ `AuthContext` - Enhanced with configuration scope resolution
- ✅ Enhanced Admin Console - Extended with configuration management

### Phase 2 → Phase 3 Evolution:
```python
# Phase 2: Flat configuration
config_value = hybrid_config.get('fax.provider.endpoint')

# Phase 3: Hierarchical configuration with user context
user_context = {
    'user_id': auth_context.user_id,
    'groups': ['medical_staff'],
    'department': 'cardiology',
    'tenant_id': 'hospital_main'
}
config_value = hierarchical_config.get_effective('fax.provider.endpoint', user_context)
```

## Core Architecture Overview

### The Hierarchical Configuration Philosophy

**Configuration Resolution Order** (Phase 3 implements full hierarchy):
1. **User-level**: `user_id` specific overrides (highest priority)
2. **Group-level**: First matching group by priority order
3. **Department-level**: Department-specific settings
4. **Tenant-level**: Tenant-wide defaults
5. **Global-level**: System-wide defaults
6. **Built-in defaults**: Hardcoded fallbacks (lowest priority)
7. **`.env` fallback**: Only when DB completely unavailable

### Enterprise Reliability Stack

**Phase 3 adds comprehensive reliability**:
- **Redis-backed caching** with intelligent invalidation
- **Circuit breakers** with provider health monitoring
- **Rate limiting** per user/endpoint with hierarchical configuration
- **Canonical events** with SSE diagnostics (HIPAA-compliant)
- **Webhook hardening** with signature verification and DLQ
- **MCP SSE OAuth** validation for secure communication

## Week 1-2: Hierarchical Configuration System

P0 security/correctness updates applied in this phase:
- Config encryption: require `CONFIG_MASTER_KEY` to be a 44‑char base64 Fernet key; fail fast if missing. Use Fernet (AES‑CBC + HMAC) in Phase 3 for at-rest config values. AES‑GCM may be adopted later without plan rewrite.
- Audit safety: never store decrypted secrets in `config_audit`. Store masked snapshots only plus `value_hmac` (HMAC‑SHA256 with server‑side `AUDIT_PEPPER`).
- Async SQLAlchemy: do not `await db.merge(...)` (it’s sync); call `db.merge(...)` then `await db.commit()`.
- .env fallback: only when DB is unavailable (connection failure). If DB is reachable but key is absent, use built‑in defaults or treat as unset and surface in UI; do not fall back to env.
- Cache invalidation: unify key shape and invalidation helpers to avoid mismatches.
- Provider health: read via `get_effective(...)` using a system context, not raw `get(...)`.
- SSE concurrency: guard subscriber set with an `asyncio.Lock()` and copy before iterating.
- Webhook DLQ: allowlist headers metadata; never persist Authorization or secrets.
- Admin UI flush‑cache: send `scope` via query parameter, not JSON body.
- Rate limiting: enforce on critical endpoints and return 429 + `Retry-After`.

### 1. Enhanced Database Schema

**Create `api/db/migrations/003_hierarchical_config.py`**

```python
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

def upgrade():
    # Global configuration (system-wide defaults)
    op.create_table('config_global',
        sa.Column('key', sa.String(200), primary_key=True, nullable=False),
        sa.Column('value_encrypted', sa.Text(), nullable=False),
        sa.Column('value_type', sa.String(20), nullable=False, default='string'),
        sa.Column('encrypted', sa.Boolean(), nullable=False, default=True),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(50), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Index('idx_global_key', 'key'),
        sa.Index('idx_global_category', 'category')
    )

    # Tenant-level configuration
    op.create_table('config_tenant',
        sa.Column('tenant_id', sa.String(100), nullable=False),
        sa.Column('key', sa.String(200), nullable=False),
        sa.Column('value_encrypted', sa.Text(), nullable=False),
        sa.Column('value_type', sa.String(20), nullable=False, default='string'),
        sa.Column('encrypted', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('tenant_id', 'key'),
        sa.Index('idx_tenant_key', 'tenant_id', 'key')
    )

    # Department-level configuration
    op.create_table('config_department',
        sa.Column('tenant_id', sa.String(100), nullable=False),
        sa.Column('department', sa.String(100), nullable=False),
        sa.Column('key', sa.String(200), nullable=False),
        sa.Column('value_encrypted', sa.Text(), nullable=False),
        sa.Column('value_type', sa.String(20), nullable=False, default='string'),
        sa.Column('encrypted', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('tenant_id', 'department', 'key'),
        sa.Index('idx_dept_key', 'tenant_id', 'department', 'key')
    )

    # Group-level configuration
    op.create_table('config_group',
        sa.Column('group_id', sa.String(100), nullable=False),
        sa.Column('key', sa.String(200), nullable=False),
        sa.Column('value_encrypted', sa.Text(), nullable=False),
        sa.Column('value_type', sa.String(20), nullable=False, default='string'),
        sa.Column('encrypted', sa.Boolean(), nullable=False, default=True),
        sa.Column('priority', sa.Integer(), nullable=False, default=0),  # For group ordering
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('group_id', 'key'),
        sa.Index('idx_group_key', 'group_id', 'key'),
        sa.Index('idx_group_priority', 'group_id', 'priority')
    )

    # User-level configuration
    op.create_table('config_user',
        sa.Column('user_id', sa.String(100), nullable=False),
        sa.Column('key', sa.String(200), nullable=False),
        sa.Column('value_encrypted', sa.Text(), nullable=False),
        sa.Column('value_type', sa.String(20), nullable=False, default='string'),
        sa.Column('encrypted', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('updated_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.PrimaryKeyConstraint('user_id', 'key'),
        sa.Index('idx_user_key', 'user_id', 'key')
    )

    # Configuration audit trail
    op.create_table('config_audit',
        sa.Column('id', sa.String(40), primary_key=True, nullable=False),
        sa.Column('level', sa.String(20), nullable=False),  # global|tenant|department|group|user
        sa.Column('level_id', sa.String(200), nullable=True),  # tenant_id, group_id, user_id, etc.
        sa.Column('key', sa.String(200), nullable=False),
        # Store masked snapshots only; never decrypted secrets
        sa.Column('old_value_masked', sa.Text(), nullable=True),
        sa.Column('new_value_masked', sa.Text(), nullable=False),
        # Integrity fingerprint for audit diffs (HMAC with server-side AUDIT_PEPPER)
        sa.Column('value_hmac', sa.String(64), nullable=False),  # hex sha256
        sa.Column('value_type', sa.String(20), nullable=False),
        sa.Column('changed_by', sa.String(100), nullable=False),  # user_id or api_key_id
        sa.Column('changed_at', sa.DateTime(), nullable=False, server_default=sa.func.now()),
        sa.Column('reason', sa.Text(), nullable=True),
        sa.Column('ip_address', sa.String(45), nullable=True),
        sa.Column('user_agent', sa.Text(), nullable=True),
        sa.Index('idx_audit_level', 'level', 'level_id'),
        sa.Index('idx_audit_key', 'key'),
        sa.Index('idx_audit_time', 'changed_at'),
        sa.Index('idx_audit_user', 'changed_by')
    )

def downgrade():
    op.drop_table('config_audit')
    op.drop_table('config_user')
    op.drop_table('config_group')
    op.drop_table('config_department')
    op.drop_table('config_tenant')
    op.drop_table('config_global')
```

### 2. Configuration Models

**Create `api/app/models/config.py`**

```python
from datetime import datetime
from typing import Optional, Any
from sqlalchemy import Column, String, Text, Boolean, DateTime, Integer, PrimaryKeyConstraint
from sqlalchemy.sql import func
from api.app.db import Base

class ConfigGlobal(Base):
    """Global configuration table"""
    __tablename__ = "config_global"

    key = Column(String(200), primary_key=True, nullable=False)
    value_encrypted = Column(Text(), nullable=False)
    value_type = Column(String(20), nullable=False, default='string')
    encrypted = Column(Boolean(), nullable=False, default=True)
    description = Column(Text(), nullable=True)
    category = Column(String(50), nullable=True)
    created_at = Column(DateTime(), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(), nullable=False, server_default=func.now())

class ConfigTenant(Base):
    """Tenant-level configuration"""
    __tablename__ = "config_tenant"

    tenant_id = Column(String(100), primary_key=True, nullable=False)
    key = Column(String(200), primary_key=True, nullable=False)
    value_encrypted = Column(Text(), nullable=False)
    value_type = Column(String(20), nullable=False, default='string')
    encrypted = Column(Boolean(), nullable=False, default=True)
    created_at = Column(DateTime(), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(), nullable=False, server_default=func.now())

class ConfigDepartment(Base):
    """Department-level configuration"""
    __tablename__ = "config_department"

    tenant_id = Column(String(100), primary_key=True, nullable=False)
    department = Column(String(100), primary_key=True, nullable=False)
    key = Column(String(200), primary_key=True, nullable=False)
    value_encrypted = Column(Text(), nullable=False)
    value_type = Column(String(20), nullable=False, default='string')
    encrypted = Column(Boolean(), nullable=False, default=True)
    created_at = Column(DateTime(), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(), nullable=False, server_default=func.now())

class ConfigGroup(Base):
    """Group-level configuration"""
    __tablename__ = "config_group"

    group_id = Column(String(100), primary_key=True, nullable=False)
    key = Column(String(200), primary_key=True, nullable=False)
    value_encrypted = Column(Text(), nullable=False)
    value_type = Column(String(20), nullable=False, default='string')
    encrypted = Column(Boolean(), nullable=False, default=True)
    priority = Column(Integer(), nullable=False, default=0)  # For group ordering
    created_at = Column(DateTime(), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(), nullable=False, server_default=func.now())

class ConfigUser(Base):
    """User-level configuration"""
    __tablename__ = "config_user"

    user_id = Column(String(100), primary_key=True, nullable=False)
    key = Column(String(200), primary_key=True, nullable=False)
    value_encrypted = Column(Text(), nullable=False)
    value_type = Column(String(20), nullable=False, default='string')
    encrypted = Column(Boolean(), nullable=False, default=True)
    created_at = Column(DateTime(), nullable=False, server_default=func.now())
    updated_at = Column(DateTime(), nullable=False, server_default=func.now())

class ConfigAudit(Base):
    """Configuration audit trail"""
    __tablename__ = "config_audit"

    id = Column(String(40), primary_key=True, nullable=False)
    level = Column(String(20), nullable=False)
    level_id = Column(String(200), nullable=True)
    key = Column(String(200), nullable=False)
    old_value_masked = Column(Text(), nullable=True)
    new_value_masked = Column(Text(), nullable=False)
    value_hmac = Column(String(64), nullable=False)
    value_type = Column(String(20), nullable=False)
    changed_by = Column(String(100), nullable=False)
    changed_at = Column(DateTime(), nullable=False, server_default=func.now())
    reason = Column(Text(), nullable=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(Text(), nullable=True)
```

### 3. Enhanced Hierarchical Configuration Provider

**Update `api/app/config/hierarchical_provider.py`**

```python
import secrets
import json
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Literal, Union
from dataclasses import dataclass
from cryptography.fernet import Fernet
from sqlalchemy import select, update, delete
from sqlalchemy.exc import IntegrityError

from api.app.db.async import AsyncSessionLocal
from api.app.models.config import (
    ConfigGlobal, ConfigTenant, ConfigDepartment,
    ConfigGroup, ConfigUser, ConfigAudit
)
from api.app.core.audit import AuditLevel

ConfigLevel = Literal['global', 'tenant', 'department', 'group', 'user']
ConfigSource = Literal['db', 'env', 'default', 'cache']

@dataclass
class ConfigValue:
    """Configuration value with metadata"""
    value: Any
    source: ConfigSource
    level: Optional[ConfigLevel] = None
    level_id: Optional[str] = None
    encrypted: bool = False
    updated_at: Optional[datetime] = None

@dataclass
class UserContext:
    """User context for hierarchical config resolution"""
    user_id: str
    tenant_id: Optional[str] = None
    department: Optional[str] = None
    groups: List[str] = None
    traits: List[str] = None

    def __post_init__(self):
        if self.groups is None:
            self.groups = []
        if self.traits is None:
            self.traits = []

class ConfigEncryption:
    """Handles configuration value encryption/decryption"""

    def __init__(self, master_key: str):
        # P0: require 44-char base64 Fernet key; fail fast if missing/invalid
        if not master_key or len(master_key) != 44:
            raise ValueError("CONFIG_MASTER_KEY must be a 44-char base64 Fernet key")
        self.fernet = Fernet(master_key.encode())

    def encrypt_value(self, value: Any, should_encrypt: bool = True) -> str:
        """Encrypt configuration value"""
        json_value = json.dumps(value)
        if should_encrypt:
            return self.fernet.encrypt(json_value.encode()).decode()
        return json_value

    def decrypt_value(self, encrypted_value: str, is_encrypted: bool = True) -> Any:
        """Decrypt configuration value"""
        try:
            if is_encrypted:
                decrypted = self.fernet.decrypt(encrypted_value.encode()).decode()
                return json.loads(decrypted)
            else:
                return json.loads(encrypted_value)
        except Exception:
            # Fallback for non-JSON values
            return encrypted_value

class HierarchicalConfigProvider:
    """Advanced hierarchical configuration provider"""

    # Built-in defaults for essential configurations
    BUILT_IN_DEFAULTS = {
        'fax.timeout_seconds': 30,
        'fax.max_pages': 100,
        'fax.retry_attempts': 3,
        'api.rate_limit_rpm': 60,
        'api.session_timeout_hours': 8,
        'redis.ttl_effective': 300,  # 5 minutes
        'redis.ttl_local': 60,       # 1 minute
        'security.require_mfa': False,
        'security.password_min_length': 12,
        'webhook.verify_signatures': True,
        'provider.health_check_interval': 300,  # 5 minutes
        'provider.circuit_breaker_threshold': 5,
        'provider.circuit_breaker_timeout': 60,
        'admin.max_config_history': 1000,
        'audit.retention_days': 365,
        'notifications.enable_sse': True,
        'hipaa.enforce_compliance': False
    }

    # Configuration keys that should always be encrypted
    ALWAYS_ENCRYPT_KEYS = {
        'fax.provider.api_key', 'fax.provider.secret', 'fax.provider.token',
        'email.smtp.password', 'database.password', 'redis.password',
        'oauth.client_secret', 'encryption.master_key'
    }

    # Safe keys that can be edited in Admin Console (Phase 3 scope)
    SAFE_EDIT_KEYS = {
        'fax.timeout_seconds': {'type': 'integer', 'min': 10, 'max': 300},
        'fax.max_pages': {'type': 'integer', 'min': 1, 'max': 1000},
        'fax.retry_attempts': {'type': 'integer', 'min': 0, 'max': 10},
        'api.rate_limit_rpm': {'type': 'integer', 'min': 1, 'max': 10000},
        'api.session_timeout_hours': {'type': 'integer', 'min': 1, 'max': 168},
        'security.require_mfa': {'type': 'boolean'},
        'webhook.verify_signatures': {'type': 'boolean'},
        'provider.health_check_interval': {'type': 'integer', 'min': 60, 'max': 3600},
        'provider.circuit_breaker_threshold': {'type': 'integer', 'min': 1, 'max': 100},
        'notifications.enable_sse': {'type': 'boolean'},
        'hipaa.enforce_compliance': {'type': 'boolean'}
    }

    def __init__(self, encryption_key: str, audit_logger, cache_manager=None):
        self.encryption = ConfigEncryption(encryption_key)
        self.audit_logger = audit_logger
        self.cache_manager = cache_manager
        self._fallback_env = {}  # .env fallback when DB unavailable

    async def get_effective(self, key: str, user_context: UserContext,
                          default: Any = None) -> ConfigValue:
        """Get effective configuration value with full hierarchy resolution"""

        # Try cache first
        if self.cache_manager:
            cache_key = self._build_cache_key('effective', user_context, key)
            cached = await self.cache_manager.get(cache_key)
            if cached:
                return ConfigValue(**cached, source='cache')

        # Resolve through hierarchy
        config_value = await self._resolve_hierarchy(key, user_context, default)

        # Cache the result
        if self.cache_manager and config_value.source == 'db':
            cache_key = self._build_cache_key('effective', user_context, key)
            await self.cache_manager.set(cache_key, {
                'value': config_value.value,
                'source': 'db',
                'level': config_value.level,
                'level_id': config_value.level_id,
                'encrypted': config_value.encrypted,
                'updated_at': config_value.updated_at.isoformat() if config_value.updated_at else None
            }, ttl=300)

        return config_value

    async def _resolve_hierarchy(self, key: str, user_context: UserContext,
                               default: Any = None) -> ConfigValue:
        """Resolve configuration through hierarchy levels"""

        async with AsyncSessionLocal() as db:
            # 1. User level (highest priority)
            if user_context.user_id:
                result = await db.execute(
                    select(ConfigUser).where(
                        ConfigUser.user_id == user_context.user_id,
                        ConfigUser.key == key
                    )
                )
                user_config = result.scalar_one_or_none()
                if user_config:
                    value = self.encryption.decrypt_value(
                        user_config.value_encrypted, user_config.encrypted
                    )
                    return ConfigValue(
                        value=value,
                        source='db',
                        level='user',
                        level_id=user_context.user_id,
                        encrypted=user_config.encrypted,
                        updated_at=user_config.updated_at
                    )

            # 2. Group level (first match by priority)
            if user_context.groups:
                result = await db.execute(
                    select(ConfigGroup)
                    .where(
                        ConfigGroup.group_id.in_(user_context.groups),
                        ConfigGroup.key == key
                    )
                    .order_by(ConfigGroup.priority.desc())
                )
                group_config = result.first()
                if group_config:
                    group_config = group_config[0]
                    value = self.encryption.decrypt_value(
                        group_config.value_encrypted, group_config.encrypted
                    )
                    return ConfigValue(
                        value=value,
                        source='db',
                        level='group',
                        level_id=group_config.group_id,
                        encrypted=group_config.encrypted,
                        updated_at=group_config.updated_at
                    )

            # 3. Department level
            if user_context.tenant_id and user_context.department:
                result = await db.execute(
                    select(ConfigDepartment).where(
                        ConfigDepartment.tenant_id == user_context.tenant_id,
                        ConfigDepartment.department == user_context.department,
                        ConfigDepartment.key == key
                    )
                )
                dept_config = result.scalar_one_or_none()
                if dept_config:
                    value = self.encryption.decrypt_value(
                        dept_config.value_encrypted, dept_config.encrypted
                    )
                    return ConfigValue(
                        value=value,
                        source='db',
                        level='department',
                        level_id=f"{user_context.tenant_id}:{user_context.department}",
                        encrypted=dept_config.encrypted,
                        updated_at=dept_config.updated_at
                    )

            # 4. Tenant level
            if user_context.tenant_id:
                result = await db.execute(
                    select(ConfigTenant).where(
                        ConfigTenant.tenant_id == user_context.tenant_id,
                        ConfigTenant.key == key
                    )
                )
                tenant_config = result.scalar_one_or_none()
                if tenant_config:
                    value = self.encryption.decrypt_value(
                        tenant_config.value_encrypted, tenant_config.encrypted
                    )
                    return ConfigValue(
                        value=value,
                        source='db',
                        level='tenant',
                        level_id=user_context.tenant_id,
                        encrypted=tenant_config.encrypted,
                        updated_at=tenant_config.updated_at
                    )

            # 5. Global level
            result = await db.execute(
                select(ConfigGlobal).where(ConfigGlobal.key == key)
            )
            global_config = result.scalar_one_or_none()
            if global_config:
                value = self.encryption.decrypt_value(
                    global_config.value_encrypted, global_config.encrypted
                )
                return ConfigValue(
                    value=value,
                    source='db',
                    level='global',
                    encrypted=global_config.encrypted,
                    updated_at=global_config.updated_at
                )

        # 6. Built-in defaults
        if key in self.BUILT_IN_DEFAULTS:
            return ConfigValue(
                value=self.BUILT_IN_DEFAULTS[key],
                source='default'
            )

        # 7. .env fallback (only when DB is completely unavailable)
        # NOTE: Do not fall back to env for missing keys when DB is reachable.
        # Env fallback is permitted only under DB outage scenarios handled at provider bootstrap.

        # 8. Provided default
        if default is not None:
            return ConfigValue(value=default, source='default')

        # No value found
        raise KeyError(f"Configuration key '{key}' not found in hierarchy")

    async def set(self, key: str, value: Any, *, level: ConfigLevel = 'global',
                  level_id: Optional[str] = None, changed_by: str = 'system',
                  reason: str = '', ip_address: str = None, user_agent: str = None) -> ConfigValue:
        """Set configuration value at specified level"""

        # Validate safe edit keys for non-admin users
        if key not in self.SAFE_EDIT_KEYS:
            # Check if user has admin_capable trait (would need auth context)
            pass  # For now, allow all - add trait check in router

        # Determine if value should be encrypted
        should_encrypt = key in self.ALWAYS_ENCRYPT_KEYS
        encrypted_value = self.encryption.encrypt_value(value, should_encrypt)

        # Get current value for audit
        try:
            current = await self._get_raw_value(key, level, level_id)
            old_value = current.value if current else None
        except:
            old_value = None

        # Insert/update configuration
        async with AsyncSessionLocal() as db:
            try:
                if level == 'global':
                    config_record = ConfigGlobal(
                        key=key,
                        value_encrypted=encrypted_value,
                        value_type=type(value).__name__,
                        encrypted=should_encrypt,
                        updated_at=datetime.utcnow()
                    )
                    db.merge(config_record)

                elif level == 'tenant':
                    config_record = ConfigTenant(
                        tenant_id=level_id,
                        key=key,
                        value_encrypted=encrypted_value,
                        value_type=type(value).__name__,
                        encrypted=should_encrypt,
                        updated_at=datetime.utcnow()
                    )
                    db.merge(config_record)

                elif level == 'department':
                    tenant_id, department = level_id.split(':', 1)
                    config_record = ConfigDepartment(
                        tenant_id=tenant_id,
                        department=department,
                        key=key,
                        value_encrypted=encrypted_value,
                        value_type=type(value).__name__,
                        encrypted=should_encrypt,
                        updated_at=datetime.utcnow()
                    )
                    db.merge(config_record)

                elif level == 'group':
                    config_record = ConfigGroup(
                        group_id=level_id,
                        key=key,
                        value_encrypted=encrypted_value,
                        value_type=type(value).__name__,
                        encrypted=should_encrypt,
                        updated_at=datetime.utcnow()
                    )
                    db.merge(config_record)

                elif level == 'user':
                    config_record = ConfigUser(
                        user_id=level_id,
                        key=key,
                        value_encrypted=encrypted_value,
                        value_type=type(value).__name__,
                        encrypted=should_encrypt,
                        updated_at=datetime.utcnow()
                    )
                    db.merge(config_record)

                # Create audit record
                # Masked values + HMAC only in audit trail
                audit_record = ConfigAudit(
                    id=uuid.uuid4().hex,
                    level=level,
                    level_id=level_id,
                    key=key,
                    old_value_masked=("****" if old_value is not None else None),
                    new_value_masked="****",
                    value_hmac="<hmac_sha256_of_new_value>",
                    value_type=type(value).__name__,
                    changed_by=changed_by,
                    reason=reason,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                db.add(audit_record)

                await db.commit()

                # Invalidate cache
                if self.cache_manager:
                    await self._invalidate_cache(key, level, level_id)

                # Audit log
                self.audit_logger.log_event('config_changed', AuditLevel.STANDARD,
                    key=key, level=level, level_id=level_id, changed_by=changed_by,
                    has_old_value=(old_value is not None))

                return ConfigValue(
                    value=value,
                    source='db',
                    level=level,
                    level_id=level_id,
                    encrypted=should_encrypt,
                    updated_at=datetime.utcnow()
                )

            except Exception as e:
                await db.rollback()
                self.audit_logger.log_event('config_set_failed', AuditLevel.CRITICAL,
                    key=key, level=level, level_id=level_id, error=str(e))
                raise

    async def get_hierarchy(self, key: str, user_context: UserContext) -> List[ConfigValue]:
        """Get configuration hierarchy for a key"""
        hierarchy = []

        async with AsyncSessionLocal() as db:
            # Check each level and build hierarchy
            levels_to_check = [
                ('user', user_context.user_id),
                ('group', user_context.groups[0] if user_context.groups else None),
                ('department', f"{user_context.tenant_id}:{user_context.department}"
                 if user_context.tenant_id and user_context.department else None),
                ('tenant', user_context.tenant_id),
                ('global', None)
            ]

            for level, level_id in levels_to_check:
                if level == 'group' and not level_id:
                    continue
                if level in ['department', 'tenant'] and not level_id:
                    continue

                config_value = await self._get_raw_value(key, level, level_id)
                if config_value:
                    hierarchy.append(config_value)

        # Add built-in default if exists
        if key in self.BUILT_IN_DEFAULTS:
            hierarchy.append(ConfigValue(
                value=self.BUILT_IN_DEFAULTS[key],
                source='default'
            ))

        return hierarchy

    async def _get_raw_value(self, key: str, level: ConfigLevel,
                           level_id: Optional[str]) -> Optional[ConfigValue]:
        """Get raw configuration value from specific level"""
        async with AsyncSessionLocal() as db:
            if level == 'global':
                result = await db.execute(
                    select(ConfigGlobal).where(ConfigGlobal.key == key)
                )
                config = result.scalar_one_or_none()
                if config:
                    value = self.encryption.decrypt_value(
                        config.value_encrypted, config.encrypted
                    )
                    return ConfigValue(
                        value=value,
                        source='db',
                        level='global',
                        encrypted=config.encrypted,
                        updated_at=config.updated_at
                    )

            elif level == 'tenant':
                result = await db.execute(
                    select(ConfigTenant).where(
                        ConfigTenant.tenant_id == level_id,
                        ConfigTenant.key == key
                    )
                )
                config = result.scalar_one_or_none()
                if config:
                    value = self.encryption.decrypt_value(
                        config.value_encrypted, config.encrypted
                    )
                    return ConfigValue(
                        value=value,
                        source='db',
                        level='tenant',
                        level_id=level_id,
                        encrypted=config.encrypted,
                        updated_at=config.updated_at
                    )

            # Similar logic for department, group, user levels...
            # [Additional level implementations would go here]

        return None

    def _build_cache_key(self, prefix: str, user_context: UserContext, key: str) -> str:
        """Build cache key for hierarchical config"""
        context_parts = [
            user_context.tenant_id or 'null',
            user_context.department or 'null',
            user_context.user_id or 'null',
            ','.join(sorted(user_context.groups)) or 'null'
        ]
        return f"cfg:{prefix}:{':'.join(context_parts)}:{key}"

    async def _invalidate_cache(self, key: str, level: ConfigLevel, level_id: Optional[str]):
        """Invalidate relevant cache entries when config changes"""
        if not self.cache_manager:
            return

        # Pattern-based invalidation - remove all effective configs that might be affected
        if level == 'global':
            # Global changes affect all users
            pattern = f"cfg:effective:*:{key}"
        elif level == 'tenant':
            # Tenant changes affect all users in that tenant
            pattern = f"cfg:effective:{level_id}:*:{key}"
        elif level == 'department':
            # Department changes affect users in that tenant/department
            tenant_id, dept = level_id.split(':', 1)
            pattern = f"cfg:effective:{tenant_id}:{dept}:*:{key}"
        elif level == 'group':
            # Group changes affect users in that group (more complex invalidation needed)
            pattern = f"cfg:effective:*:*:*:*:{key}"  # Invalidate all for simplicity
        elif level == 'user':
            # User changes only affect that specific user
            pattern = f"cfg:effective:*:*:{level_id}:*:{key}"

        await self.cache_manager.delete_pattern(pattern)

    async def get_safe_edit_keys(self) -> Dict[str, Dict[str, Any]]:
        """Get keys that are safe to edit in Admin Console"""
        return self.SAFE_EDIT_KEYS.copy()

    async def validate_config_value(self, key: str, value: Any) -> bool:
        """Validate configuration value against constraints"""
        if key not in self.SAFE_EDIT_KEYS:
            return False

        constraints = self.SAFE_EDIT_KEYS[key]
        value_type = constraints['type']

        if value_type == 'boolean':
            return isinstance(value, bool)
        elif value_type == 'integer':
            if not isinstance(value, int):
                return False
            if 'min' in constraints and value < constraints['min']:
                return False
            if 'max' in constraints and value > constraints['max']:
                return False
        elif value_type == 'string':
            if not isinstance(value, str):
                return False
            if 'min_length' in constraints and len(value) < constraints['min_length']:
                return False
            if 'max_length' in constraints and len(value) > constraints['max_length']:
                return False

        return True
```

## Week 2-3: Redis Caching and Configuration Endpoints

### 4. Redis Cache Manager

**Create `api/app/services/cache_manager.py`**

```python
import json
import re
from typing import Any, Optional, Dict, List
from datetime import datetime, timedelta
import redis.asyncio as redis
from api.app.core.audit import AuditLevel

class CacheManager:
    """Redis-backed cache manager with local fallback"""

    def __init__(self, redis_url: str = None, audit_logger=None):
        self.audit_logger = audit_logger
        self.redis_client = None
        self.local_cache = {}  # Simple in-memory cache
        self.local_cache_ttl = {}
        self.redis_available = False

        if redis_url:
            try:
                self.redis_client = redis.from_url(redis_url)
                self.redis_available = True
            except Exception as e:
                if audit_logger:
                    audit_logger.log_event('redis_connection_failed', AuditLevel.HIGH,
                                         error=str(e))

    async def get(self, key: str) -> Optional[Any]:
        """Get value from cache (Redis first, then local)"""
        # Try Redis first
        if self.redis_available and self.redis_client:
            try:
                value = await self.redis_client.get(key)
                if value:
                    return json.loads(value)
            except Exception as e:
                if self.audit_logger:
                    self.audit_logger.log_event('redis_get_failed', AuditLevel.STANDARD,
                                              key=key[:50], error=str(e))

        # Fallback to local cache
        if key in self.local_cache:
            if key in self.local_cache_ttl:
                if datetime.utcnow() < self.local_cache_ttl[key]:
                    return self.local_cache[key]
                else:
                    # Expired, remove
                    del self.local_cache[key]
                    del self.local_cache_ttl[key]

        return None

    async def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        """Set value in cache (Redis and local)"""
        json_value = json.dumps(value, default=str)

        # Try Redis first
        if self.redis_available and self.redis_client:
            try:
                await self.redis_client.setex(key, ttl, json_value)
            except Exception as e:
                if self.audit_logger:
                    self.audit_logger.log_event('redis_set_failed', AuditLevel.STANDARD,
                                              key=key[:50], error=str(e))

        # Always set in local cache as fallback
        self.local_cache[key] = value
        self.local_cache_ttl[key] = datetime.utcnow() + timedelta(seconds=min(ttl, 60))

        # Cleanup expired local cache entries periodically
        await self._cleanup_local_cache()

        return True

    async def delete(self, key: str) -> bool:
        """Delete specific key from cache"""
        # Delete from Redis
        if self.redis_available and self.redis_client:
            try:
                await self.redis_client.delete(key)
            except Exception as e:
                if self.audit_logger:
                    self.audit_logger.log_event('redis_delete_failed', AuditLevel.STANDARD,
                                              key=key[:50], error=str(e))

        # Delete from local cache
        self.local_cache.pop(key, None)
        self.local_cache_ttl.pop(key, None)

        return True

    async def delete_pattern(self, pattern: str) -> int:
        """Delete keys matching pattern"""
        deleted_count = 0

        # Delete from Redis using SCAN
        if self.redis_available and self.redis_client:
            try:
                async for key in self.redis_client.scan_iter(match=pattern):
                    await self.redis_client.delete(key)
                    deleted_count += 1
            except Exception as e:
                if self.audit_logger:
                    self.audit_logger.log_event('redis_pattern_delete_failed',
                                              AuditLevel.STANDARD, pattern=pattern[:50], error=str(e))

        # Delete from local cache using regex
        regex_pattern = pattern.replace('*', '.*').replace('?', '.')
        compiled_pattern = re.compile(regex_pattern)

        keys_to_delete = [
            key for key in self.local_cache.keys()
            if compiled_pattern.match(key)
        ]

        for key in keys_to_delete:
            del self.local_cache[key]
            self.local_cache_ttl.pop(key, None)
            deleted_count += 1

        return deleted_count

    async def _cleanup_local_cache(self):
        """Clean up expired entries from local cache"""
        now = datetime.utcnow()
        expired_keys = [
            key for key, expiry in self.local_cache_ttl.items()
            if now >= expiry
        ]

        for key in expired_keys:
            self.local_cache.pop(key, None)
            self.local_cache_ttl.pop(key, None)

    async def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics"""
        stats = {
            'redis_available': self.redis_available,
            'local_cache_size': len(self.local_cache),
            'local_cache_keys': list(self.local_cache.keys())[:10]  # Sample
        }

        if self.redis_available and self.redis_client:
            try:
                info = await self.redis_client.info()
                stats['redis_used_memory'] = info.get('used_memory_human', 'unknown')
                stats['redis_connected_clients'] = info.get('connected_clients', 0)
            except:
                stats['redis_error'] = True

        return stats

    async def flush_all(self) -> bool:
        """Flush all cache entries (admin only)"""
        # Flush Redis
        if self.redis_available and self.redis_client:
            try:
                await self.redis_client.flushdb()
            except Exception as e:
                if self.audit_logger:
                    self.audit_logger.log_event('redis_flush_failed', AuditLevel.HIGH,
                                              error=str(e))

        # Flush local cache
        self.local_cache.clear()
        self.local_cache_ttl.clear()

        if self.audit_logger:
            self.audit_logger.log_event('cache_flushed', AuditLevel.STANDARD)

        return True
```

### 5. Configuration API Endpoints

**Create `api/app/routers/admin_config.py`**

```python
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import List, Optional, Any, Dict
from datetime import datetime

from api.app.config.hierarchical_provider import HierarchicalConfigProvider, UserContext, ConfigLevel
from api.app.core.traits import trait_engine
from api.app.middleware.auth import get_auth_context

router = APIRouter(prefix="/admin/config", tags=["Configuration"])

class ConfigSetRequest(BaseModel):
    key: str = Field(..., description="Configuration key")
    value: Any = Field(..., description="Configuration value")
    level: ConfigLevel = Field(default='global', description="Configuration level")
    level_id: Optional[str] = Field(None, description="Level identifier (tenant_id, group_id, etc.)")
    reason: str = Field(default='', description="Reason for change")

class ConfigResponse(BaseModel):
    key: str
    value: Any
    source: str
    level: Optional[str] = None
    level_id: Optional[str] = None
    encrypted: bool = False
    updated_at: Optional[datetime] = None

class EffectiveConfigResponse(BaseModel):
    values: Dict[str, ConfigResponse]
    user_context: Dict[str, Any]
    cache_stats: Dict[str, Any]

class HierarchyLayer(BaseModel):
    level: str
    level_id: Optional[str]
    value: Any
    encrypted: bool
    updated_at: Optional[datetime]

class HierarchyResponse(BaseModel):
    key: str
    layers: List[HierarchyLayer]
    effective: ConfigResponse

@router.get("/effective", response_model=EffectiveConfigResponse)
async def get_effective_config(
    request: Request,
    auth_context = Depends(get_auth_context),
    scope: Optional[str] = None
):
    """Get effective configuration for current user context"""

    # Require admin_capable trait for config access
    if 'admin_capable' not in auth_context.traits:
        raise HTTPException(403, "Admin access required")

    # Build user context from auth
    user_context = UserContext(
        user_id=auth_context.user_id,
        tenant_id=auth_context.metadata.get('tenant_id'),
        department=auth_context.metadata.get('department'),
        groups=auth_context.metadata.get('groups', []),
        traits=auth_context.traits
    )

    # Get hierarchical config provider
    hierarchical_config: HierarchicalConfigProvider = request.app.state.hierarchical_config

    # Get commonly used configuration keys
    common_keys = [
        'fax.timeout_seconds', 'fax.max_pages', 'fax.retry_attempts',
        'api.rate_limit_rpm', 'api.session_timeout_hours',
        'security.require_mfa', 'webhook.verify_signatures',
        'provider.health_check_interval', 'provider.circuit_breaker_threshold',
        'notifications.enable_sse', 'hipaa.enforce_compliance'
    ]

    # Add scope-specific keys
    if scope:
        if scope == 'fax':
            common_keys.extend(['fax.provider.endpoint', 'fax.provider.timeout'])
        elif scope == 'security':
            common_keys.extend(['security.password_min_length', 'security.session_timeout'])

    effective_config = {}

    for key in common_keys:
        try:
            config_value = await hierarchical_config.get_effective(key, user_context)
            effective_config[key] = ConfigResponse(
                key=key,
                value=config_value.value,
                source=config_value.source,
                level=config_value.level,
                level_id=config_value.level_id,
                encrypted=config_value.encrypted,
                updated_at=config_value.updated_at
            )
        except KeyError:
            # Key not found in hierarchy
            continue

    # Get cache stats if available
    cache_stats = {}
    if hasattr(hierarchical_config, 'cache_manager') and hierarchical_config.cache_manager:
        cache_stats = await hierarchical_config.cache_manager.get_stats()

    return EffectiveConfigResponse(
        values=effective_config,
        user_context={
            'user_id': user_context.user_id,
            'tenant_id': user_context.tenant_id,
            'department': user_context.department,
            'groups': user_context.groups,
            'traits': user_context.traits
        },
        cache_stats=cache_stats
    )

@router.get("/hierarchy", response_model=HierarchyResponse)
async def get_config_hierarchy(
    key: str,
    request: Request,
    auth_context = Depends(get_auth_context)
):
    """Get configuration hierarchy for a specific key"""

    # Require admin_capable trait
    if 'admin_capable' not in auth_context.traits:
        raise HTTPException(403, "Admin access required")

    # Build user context
    user_context = UserContext(
        user_id=auth_context.user_id,
        tenant_id=auth_context.metadata.get('tenant_id'),
        department=auth_context.metadata.get('department'),
        groups=auth_context.metadata.get('groups', []),
        traits=auth_context.traits
    )

    hierarchical_config: HierarchicalConfigProvider = request.app.state.hierarchical_config

    # Get hierarchy layers
    hierarchy_values = await hierarchical_config.get_hierarchy(key, user_context)

    layers = [
        HierarchyLayer(
            level=config_val.level or 'default',
            level_id=config_val.level_id,
            value=config_val.value,
            encrypted=config_val.encrypted,
            updated_at=config_val.updated_at
        )
        for config_val in hierarchy_values
    ]

    # Get effective value
    try:
        effective_value = await hierarchical_config.get_effective(key, user_context)
        effective = ConfigResponse(
            key=key,
            value=effective_value.value,
            source=effective_value.source,
            level=effective_value.level,
            level_id=effective_value.level_id,
            encrypted=effective_value.encrypted,
            updated_at=effective_value.updated_at
        )
    except KeyError:
        raise HTTPException(404, f"Configuration key '{key}' not found")

    return HierarchyResponse(
        key=key,
        layers=layers,
        effective=effective
    )

@router.post("/set", response_model=ConfigResponse)
async def set_config_value(
    config_request: ConfigSetRequest,
    request: Request,
    auth_context = Depends(get_auth_context)
):
    """Set configuration value at specified level"""

    # Require admin_capable trait
    if 'admin_capable' not in auth_context.traits:
        raise HTTPException(403, "Admin access required")

    hierarchical_config: HierarchicalConfigProvider = request.app.state.hierarchical_config

    # Validate that key is safe to edit (Phase 3 restriction)
    safe_keys = await hierarchical_config.get_safe_edit_keys()
    if config_request.key not in safe_keys:
        raise HTTPException(400, f"Key '{config_request.key}' is not safe to edit via Admin Console")

    # Validate value constraints
    is_valid = await hierarchical_config.validate_config_value(config_request.key, config_request.value)
    if not is_valid:
        constraints = safe_keys[config_request.key]
        raise HTTPException(400, f"Value does not meet constraints: {constraints}")

    # Set configuration
    try:
        config_value = await hierarchical_config.set(
            key=config_request.key,
            value=config_request.value,
            level=config_request.level,
            level_id=config_request.level_id,
            changed_by=auth_context.user_id,
            reason=config_request.reason,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get('user-agent', '')
        )

        return ConfigResponse(
            key=config_request.key,
            value=config_value.value,
            source=config_value.source,
            level=config_value.level,
            level_id=config_value.level_id,
            encrypted=config_value.encrypted,
            updated_at=config_value.updated_at
        )

    except Exception as e:
        raise HTTPException(500, f"Failed to set configuration: {str(e)}")

@router.get("/safe-keys", response_model=Dict[str, Dict[str, Any]])
async def get_safe_edit_keys(
    request: Request,
    auth_context = Depends(get_auth_context)
):
    """Get keys that are safe to edit in Admin Console"""

    # Require admin_capable trait
    if 'admin_capable' not in auth_context.traits:
        raise HTTPException(403, "Admin access required")

    hierarchical_config: HierarchicalConfigProvider = request.app.state.hierarchical_config
    safe_keys = await hierarchical_config.get_safe_edit_keys()

    return safe_keys

@router.post("/flush-cache")
async def flush_config_cache(
    request: Request,
    auth_context = Depends(get_auth_context),
    scope: Optional[str] = None
):
    """Flush configuration cache (admin only)"""

    # Require admin_capable trait
    if 'admin_capable' not in auth_context.traits:
        raise HTTPException(403, "Admin access required")

    hierarchical_config: HierarchicalConfigProvider = request.app.state.hierarchical_config

    if not hierarchical_config.cache_manager:
        raise HTTPException(503, "Cache manager not available")

    try:
        if scope:
            # Flush specific scope
            pattern = f"cfg:*:{scope}:*"
            deleted_count = await hierarchical_config.cache_manager.delete_pattern(pattern)
            return {"success": True, "scope": scope, "deleted_keys": deleted_count}
        else:
            # Flush all config cache
            await hierarchical_config.cache_manager.flush_all()
            return {"success": True, "scope": "all"}

    except Exception as e:
        raise HTTPException(500, f"Failed to flush cache: {str(e)}")
```

## Week 3-4: Admin Console Configuration Manager

### 6. Configuration Manager UI Component

**Create `api/admin_ui/src/components/ConfigurationManager.tsx`**

```typescript
import React, { useState, useEffect, useMemo } from 'react';
import {
  Paper, Typography, Stack, Alert, Button, Chip, Box, Card, CardContent,
  Tabs, Tab, Switch, FormControlLabel, Accordion, AccordionSummary, AccordionDetails,
  TextField, Select, MenuItem, FormControl, InputLabel, Divider, IconButton
} from '@mui/material';
import {
  ExpandMore as ExpandMoreIcon, Settings as SettingsIcon, Cache as CacheIcon,
  Visibility as VisibilityIcon, VisibilityOff as VisibilityOffIcon,
  Save as SaveIcon, Refresh as RefreshIcon
} from '@mui/icons-material';
import AdminAPIClient from '../api/client';
import { ResponsiveCard } from './common/ResponsiveCard';
import { ResponsiveFormSection, ResponsiveTextField, ResponsiveSelect } from './common/ResponsiveFormFields';

interface ConfigValue {
  key: string;
  value: any;
  source: string;
  level?: string;
  level_id?: string;
  encrypted: boolean;
  updated_at?: string;
}

interface HierarchyLayer {
  level: string;
  level_id?: string;
  value: any;
  encrypted: boolean;
  updated_at?: string;
}

interface SafeKey {
  type: string;
  min?: number;
  max?: number;
  min_length?: number;
  max_length?: number;
}

interface ConfigurationManagerProps {
  client: AdminAPIClient;
  docsBase?: string;
}

export default function ConfigurationManager({ client, docsBase }: ConfigurationManagerProps) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Configuration state
  const [effectiveConfig, setEffectiveConfig] = useState<Record<string, ConfigValue>>({});
  const [userContext, setUserContext] = useState<any>({});
  const [cacheStats, setCacheStats] = useState<any>({});
  const [safeKeys, setSafeKeys] = useState<Record<string, SafeKey>>({});
  const [hierarchy, setHierarchy] = useState<Record<string, HierarchyLayer[]>>({});

  // UI state
  const [selectedTab, setSelectedTab] = useState(0);
  const [selectedLevel, setSelectedLevel] = useState<string>('global');
  const [levelId, setLevelId] = useState<string>('');
  const [showSecrets, setShowSecrets] = useState(false);
  const [editingKey, setEditingKey] = useState<string | null>(null);
  const [editValue, setEditValue] = useState<any>(null);

  useEffect(() => {
    loadConfiguration();
    loadSafeKeys();
  }, []);

  const loadConfiguration = async () => {
    setLoading(true);
    try {
      const response = await client.get('/admin/config/effective');
      setEffectiveConfig(response.data.values);
      setUserContext(response.data.user_context);
      setCacheStats(response.data.cache_stats);
      setError(null);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load configuration');
    } finally {
      setLoading(false);
    }
  };

  const loadSafeKeys = async () => {
    try {
      const response = await client.get('/admin/config/safe-keys');
      setSafeKeys(response.data);
    } catch (err: any) {
      console.error('Failed to load safe keys:', err);
    }
  };

  const loadHierarchy = async (key: string) => {
    try {
      const response = await client.get(`/admin/config/hierarchy?key=${key}`);
      setHierarchy(prev => ({ ...prev, [key]: response.data.layers }));
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to load hierarchy');
    }
  };

  const saveConfigValue = async (key: string, value: any, reason: string = '') => {
    try {
      await client.post('/admin/config/set', {
        key,
        value,
        level: selectedLevel,
        level_id: levelId || undefined,
        reason
      });

      setSuccess(`Configuration '${key}' updated successfully`);
      setEditingKey(null);
      setEditValue(null);

      // Reload configuration
      await loadConfiguration();

      setTimeout(() => setSuccess(null), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to save configuration');
    }
  };

  const flushCache = async (scope?: string) => {
    try {
      const qs = scope ? `?scope=${encodeURIComponent(scope)}` : '';
      await client.post(`/admin/config/flush-cache${qs}`);
      setSuccess('Cache flushed successfully');
      setTimeout(() => setSuccess(null), 3000);
    } catch (err: any) {
      setError(err.response?.data?.detail || 'Failed to flush cache');
    }
  };

  const getSourceColor = (source: string) => {
    switch (source) {
      case 'db': return 'primary';
      case 'env': return 'warning';
      case 'default': return 'info';
      case 'cache': return 'success';
      default: return 'default';
    }
  };

  const getLevelColor = (level?: string) => {
    switch (level) {
      case 'user': return 'error';
      case 'group': return 'warning';
      case 'department': return 'info';
      case 'tenant': return 'primary';
      case 'global': return 'default';
      default: return 'default';
    }
  };

  const renderConfigValue = (config: ConfigValue) => {
    if (config.encrypted && !showSecrets) {
      return '••••••••';
    }

    if (typeof config.value === 'boolean') {
      return config.value ? 'true' : 'false';
    }

    if (typeof config.value === 'object') {
      return JSON.stringify(config.value, null, 2);
    }

    return String(config.value);
  };

  const renderEditor = (key: string, config: ConfigValue) => {
    const safeKey = safeKeys[key];
    if (!safeKey) return null;

    const handleSave = () => {
      if (editValue !== null) {
        saveConfigValue(key, editValue, `Updated via Admin Console`);
      }
    };

    if (safeKey.type === 'boolean') {
      return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <FormControlLabel
            control={
              <Switch
                checked={editValue ?? config.value}
                onChange={(e) => setEditValue(e.target.checked)}
              />
            }
            label={editValue ?? config.value ? 'Enabled' : 'Disabled'}
          />
          <Button size="small" variant="contained" onClick={handleSave} startIcon={<SaveIcon />}>
            Save
          </Button>
        </Box>
      );
    }

    if (safeKey.type === 'integer') {
      return (
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <TextField
            type="number"
            size="small"
            value={editValue ?? config.value}
            onChange={(e) => setEditValue(parseInt(e.target.value))}
            inputProps={{
              min: safeKey.min,
              max: safeKey.max
            }}
            helperText={`Range: ${safeKey.min} - ${safeKey.max}`}
          />
          <Button size="small" variant="contained" onClick={handleSave} startIcon={<SaveIcon />}>
            Save
          </Button>
        </Box>
      );
    }

    return null;
  };

  const configCategories = useMemo(() => {
    const categories: Record<string, ConfigValue[]> = {
      'Fax Configuration': [],
      'Security Settings': [],
      'Performance': [],
      'Notifications': [],
      'Provider Settings': []
    };

    Object.entries(effectiveConfig).forEach(([key, config]) => {
      if (key.startsWith('fax.')) {
        categories['Fax Configuration'].push(config);
      } else if (key.startsWith('security.') || key.startsWith('webhook.')) {
        categories['Security Settings'].push(config);
      } else if (key.startsWith('api.') || key.startsWith('redis.') || key.startsWith('provider.')) {
        categories['Performance'].push(config);
      } else if (key.startsWith('notifications.')) {
        categories['Notifications'].push(config);
      } else {
        categories['Provider Settings'].push(config);
      }
    });

    return categories;
  }, [effectiveConfig]);

  return (
    <ResponsiveCard title="Configuration Manager" subtitle="Hierarchical system configuration">
      {error && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>
          {error}
        </Alert>
      )}

      {success && (
        <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      )}

      {/* Cache Status Banner */}
      {!cacheStats.redis_available && (
        <Alert severity="warning" sx={{ mb: 2 }}>
          Redis cache unavailable - using local fallback only. Performance may be reduced.
        </Alert>
      )}

      {/* Controls */}
      <Box sx={{ mb: 3, display: 'flex', gap: 2, alignItems: 'center', flexWrap: 'wrap' }}>
        <Button
          variant="outlined"
          onClick={loadConfiguration}
          disabled={loading}
          startIcon={<RefreshIcon />}
        >
          Refresh
        </Button>

        <Button
          variant="outlined"
          onClick={() => flushCache()}
          startIcon={<CacheIcon />}
        >
          Flush Cache
        </Button>

        <FormControlLabel
          control={
            <Switch
              checked={showSecrets}
              onChange={(e) => setShowSecrets(e.target.checked)}
            />
          }
          label="Show Encrypted Values"
        />

        <Box sx={{ flexGrow: 1 }} />

        <Typography variant="body2" color="text.secondary">
          Cache: {cacheStats.local_cache_size || 0} local entries
          {cacheStats.redis_used_memory && `, ${cacheStats.redis_used_memory} Redis`}
        </Typography>
      </Box>

      {/* Level Selector */}
      <ResponsiveFormSection title="Configuration Scope">
        <Stack direction="row" spacing={2} sx={{ mb: 2 }}>
          <FormControl size="small" sx={{ minWidth: 120 }}>
            <InputLabel>Level</InputLabel>
            <Select
              value={selectedLevel}
              label="Level"
              onChange={(e) => setSelectedLevel(e.target.value)}
            >
              <MenuItem value="global">Global</MenuItem>
              <MenuItem value="tenant">Tenant</MenuItem>
              <MenuItem value="department">Department</MenuItem>
              <MenuItem value="group">Group</MenuItem>
              <MenuItem value="user">User</MenuItem>
            </Select>
          </FormControl>

          {selectedLevel !== 'global' && (
            <TextField
              size="small"
              label={`${selectedLevel.charAt(0).toUpperCase() + selectedLevel.slice(1)} ID`}
              value={levelId}
              onChange={(e) => setLevelId(e.target.value)}
              placeholder={selectedLevel === 'tenant' ? 'tenant_123' :
                         selectedLevel === 'department' ? 'tenant_123:cardiology' :
                         selectedLevel === 'group' ? 'medical_staff' : 'user_456'}
              sx={{ minWidth: 200 }}
            />
          )}
        </Stack>

        <Alert severity="info">
          Viewing configuration from <strong>{userContext.user_id}</strong>'s perspective
          {userContext.tenant_id && ` (Tenant: ${userContext.tenant_id})`}
          {userContext.department && ` (Department: ${userContext.department})`}
          {userContext.groups?.length > 0 && ` (Groups: ${userContext.groups.join(', ')})`}
        </Alert>
      </ResponsiveFormSection>

      {/* Configuration Tabs */}
      <Box sx={{ borderBottom: 1, borderColor: 'divider', mb: 3 }}>
        <Tabs value={selectedTab} onChange={(_, newValue) => setSelectedTab(newValue)}>
          <Tab label="Effective Configuration" />
          <Tab label="Hierarchy View" />
          <Tab label="Safe Edit" />
        </Tabs>
      </Box>

      {/* Tab Content */}
      {selectedTab === 0 && (
        <Stack spacing={3}>
          {Object.entries(configCategories).map(([category, configs]) => (
            configs.length > 0 && (
              <Card key={category}>
                <CardContent>
                  <Typography variant="h6" sx={{ mb: 2 }}>{category}</Typography>
                  <Stack spacing={2}>
                    {configs.map((config) => (
                      <Box key={config.key} sx={{ p: 2, border: 1, borderColor: 'divider', borderRadius: 1 }}>
                        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                          <Typography variant="subtitle2" sx={{ fontFamily: 'monospace' }}>
                            {config.key}
                          </Typography>
                          <Chip
                            size="small"
                            label={config.source}
                            color={getSourceColor(config.source)}
                          />
                          {config.level && (
                            <Chip
                              size="small"
                              label={config.level}
                              color={getLevelColor(config.level)}
                              variant="outlined"
                            />
                          )}
                          {config.encrypted && (
                            <Chip size="small" label="encrypted" color="warning" variant="outlined" />
                          )}
                        </Box>

                        <Typography
                          variant="body2"
                          sx={{
                            fontFamily: 'monospace',
                            bgcolor: 'grey.50',
                            p: 1,
                            borderRadius: 1,
                            wordBreak: 'break-all'
                          }}
                        >
                          {renderConfigValue(config)}
                        </Typography>

                        {config.updated_at && (
                          <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                            Updated: {new Date(config.updated_at).toLocaleString()}
                          </Typography>
                        )}

                        <Button
                          size="small"
                          onClick={() => loadHierarchy(config.key)}
                          sx={{ mt: 1 }}
                        >
                          View Hierarchy
                        </Button>
                      </Box>
                    ))}
                  </Stack>
                </CardContent>
              </Card>
            )
          ))}
        </Stack>
      )}

      {selectedTab === 1 && (
        <Stack spacing={3}>
          {Object.entries(hierarchy).map(([key, layers]) => (
            <Accordion key={key}>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography sx={{ fontFamily: 'monospace' }}>{key}</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Stack spacing={2}>
                  {layers.map((layer, index) => (
                    <Box
                      key={index}
                      sx={{
                        p: 2,
                        border: 1,
                        borderColor: index === 0 ? 'primary.main' : 'divider',
                        borderRadius: 1,
                        bgcolor: index === 0 ? 'primary.50' : 'transparent'
                      }}
                    >
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 1 }}>
                        <Chip
                          size="small"
                          label={layer.level}
                          color={getLevelColor(layer.level)}
                          variant={index === 0 ? 'filled' : 'outlined'}
                        />
                        {layer.level_id && (
                          <Chip size="small" label={layer.level_id} variant="outlined" />
                        )}
                        {index === 0 && (
                          <Chip size="small" label="EFFECTIVE" color="primary" />
                        )}
                      </Box>

                      <Typography
                        variant="body2"
                        sx={{ fontFamily: 'monospace', wordBreak: 'break-all' }}
                      >
                        {layer.encrypted && !showSecrets ? '••••••••' : JSON.stringify(layer.value)}
                      </Typography>

                      {layer.updated_at && (
                        <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                          Updated: {new Date(layer.updated_at).toLocaleString()}
                        </Typography>
                      )}
                    </Box>
                  ))}
                </Stack>
              </AccordionDetails>
            </Accordion>
          ))}
        </Stack>
      )}

      {selectedTab === 2 && (
        <Stack spacing={3}>
          <Alert severity="info">
            Only safe configuration keys can be edited through the Admin Console.
            Advanced configuration requires direct database access.
          </Alert>

          {Object.entries(safeKeys).map(([key, constraints]) => {
            const config = effectiveConfig[key];
            if (!config) return null;

            return (
              <Card key={key}>
                <CardContent>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                    <Typography variant="h6" sx={{ fontFamily: 'monospace' }}>
                      {key}
                    </Typography>
                    <Chip size="small" label={constraints.type} color="primary" variant="outlined" />
                    {editingKey === key && (
                      <Button
                        size="small"
                        onClick={() => {
                          setEditingKey(null);
                          setEditValue(null);
                        }}
                      >
                        Cancel
                      </Button>
                    )}
                  </Box>

                  <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
                    Current value: {renderConfigValue(config)}
                    {config.level && ` (from ${config.level} level)`}
                  </Typography>

                  {editingKey === key ? (
                    renderEditor(key, config)
                  ) : (
                    <Button
                      variant="outlined"
                      size="small"
                      onClick={() => {
                        setEditingKey(key);
                        setEditValue(config.value);
                      }}
                      startIcon={<SettingsIcon />}
                    >
                      Edit
                    </Button>
                  )}

                  <Typography variant="caption" color="text.secondary" sx={{ mt: 1, display: 'block' }}>
                    Constraints: {JSON.stringify(constraints)}
                  </Typography>
                </CardContent>
              </Card>
            );
          })}
        </Stack>
      )}

      {/* Documentation Links */}
      <Box sx={{ mt: 4, display: 'flex', gap: 2, flexWrap: 'wrap' }}>
        <Button
          variant="outlined"
          onClick={() => window.open(`${docsBase}/configuration/hierarchy`)}
        >
          📚 Configuration Hierarchy Guide
        </Button>
        <Button
          variant="outlined"
          onClick={() => window.open(`${docsBase}/configuration/caching`)}
        >
          ⚡ Caching & Performance
        </Button>
        <Button
          variant="outlined"
          onClick={() => window.open(`${docsBase}/configuration/security`)}
        >
          🔐 Security & Encryption
        </Button>
      </Box>
    </ResponsiveCard>
  );
}
```

### 7. Canonical Events System

**Create `api/app/services/events.py`**

```python
import uuid
import json
from datetime import datetime
from typing import Dict, Any, List, Optional, AsyncGenerator
from dataclasses import dataclass
from enum import Enum
from sqlalchemy import Column, String, DateTime, Text, Index
from sqlalchemy.sql import func
from api.app.db import Base
from api.app.db.async import AsyncSessionLocal
from api.app.core.audit import AuditLevel

class EventType(Enum):
    FAX_QUEUED = "FAX_QUEUED"
    FAX_SENT = "FAX_SENT"
    FAX_DELIVERED = "FAX_DELIVERED"
    FAX_FAILED = "FAX_FAILED"
    FAX_RETRYING = "FAX_RETRYING"
    CONFIG_CHANGED = "CONFIG_CHANGED"
    PROVIDER_HEALTH_CHANGED = "PROVIDER_HEALTH_CHANGED"
    USER_LOGIN = "USER_LOGIN"
    USER_LOGOUT = "USER_LOGOUT"
    WEBHOOK_RECEIVED = "WEBHOOK_RECEIVED"
    WEBHOOK_FAILED = "WEBHOOK_FAILED"

class DBEvent(Base):
    """Canonical events table"""
    __tablename__ = "events"

    id = Column(String(40), primary_key=True, nullable=False)
    type = Column(String(40), nullable=False)
    job_id = Column(String(40), nullable=True)
    provider_id = Column(String(40), nullable=True)
    external_id = Column(String(100), nullable=True)
    user_id = Column(String(40), nullable=True)
    occurred_at = Column(DateTime(), nullable=False, server_default=func.now())
    payload_meta = Column(Text(), nullable=True)  # JSON, no PHI
    correlation_id = Column(String(40), nullable=True)

    __table_args__ = (
        Index('idx_events_job_time', 'job_id', 'occurred_at'),
        Index('idx_events_provider_time', 'provider_id', 'occurred_at'),
        Index('idx_events_user_time', 'user_id', 'occurred_at'),
        Index('idx_events_type_time', 'type', 'occurred_at'),
        Index('idx_events_correlation', 'correlation_id'),
    )

@dataclass
class CanonicalEvent:
    """Canonical event with metadata"""
    id: str
    type: EventType
    job_id: Optional[str] = None
    provider_id: Optional[str] = None
    external_id: Optional[str] = None
    user_id: Optional[str] = None
    occurred_at: datetime = None
    payload_meta: Dict[str, Any] = None
    correlation_id: Optional[str] = None

    def __post_init__(self):
        if self.occurred_at is None:
            self.occurred_at = datetime.utcnow()
        if self.payload_meta is None:
            self.payload_meta = {}

class EventEmitter:
    """Canonical event emitter with SSE support"""

    def __init__(self, audit_logger=None):
        self.audit_logger = audit_logger
        self.sse_subscribers = set()  # Active SSE connections
        import asyncio
        self._lock = asyncio.Lock()

    async def emit_event(self, event_type: EventType, **kwargs) -> CanonicalEvent:
        """Emit a canonical event"""

        # Create event
        event = CanonicalEvent(
            id=uuid.uuid4().hex,
            type=event_type,
            job_id=kwargs.get('job_id'),
            provider_id=kwargs.get('provider_id'),
            external_id=kwargs.get('external_id'),
            user_id=kwargs.get('user_id'),
            correlation_id=kwargs.get('correlation_id'),
            payload_meta=self._sanitize_payload(kwargs.get('payload_meta', {}))
        )

        # Persist to database
        await self._persist_event(event)

        # Notify SSE subscribers (admin only, no PHI)
        await self._notify_sse_subscribers(event)

        # Audit log
        if self.audit_logger:
            self.audit_logger.log_event('canonical_event_emitted', AuditLevel.STANDARD,
                event_type=event_type.value, event_id=event.id,
                has_job_id=(event.job_id is not None),
                has_user_id=(event.user_id is not None))

        return event

    async def _persist_event(self, event: CanonicalEvent):
        """Persist event to database"""
        async with AsyncSessionLocal() as db:
            db_event = DBEvent(
                id=event.id,
                type=event.type.value,
                job_id=event.job_id,
                provider_id=event.provider_id,
                external_id=event.external_id,
                user_id=event.user_id,
                occurred_at=event.occurred_at,
                payload_meta=json.dumps(event.payload_meta) if event.payload_meta else None,
                correlation_id=event.correlation_id
            )
            db.add(db_event)
            await db.commit()

    def _sanitize_payload(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Remove PHI and sensitive data from event payload"""
        sanitized = {}

        safe_keys = {
            'pages_count', 'duration_seconds', 'retry_count', 'error_code',
            'provider_name', 'provider_type', 'status_code', 'attempt_number',
            'config_key', 'config_level', 'user_agent_hash', 'ip_hash'
        }

        for key, value in payload.items():
            if key in safe_keys:
                sanitized[key] = value
            elif key.endswith('_count') or key.endswith('_seconds'):
                sanitized[key] = value
            # Skip anything that might contain PHI

        return sanitized

    async def _notify_sse_subscribers(self, event: CanonicalEvent):
        """Notify SSE subscribers of new event"""
        if not self.sse_subscribers:
            return

        # Create sanitized event for SSE (admin diagnostics)
        sse_event = {
            'id': event.id,
            'type': event.type.value,
            'job_id': event.job_id,
            'provider_id': event.provider_id,
            'occurred_at': event.occurred_at.isoformat(),
            'payload_meta': event.payload_meta  # Already sanitized
        }

        # Send to all active SSE connections with concurrency guard
        disconnected = set()
        async with self._lock:
            subs = list(self.sse_subscribers)
        for subscriber in subs:
            try:
                await subscriber.send_event(sse_event)
            except:
                disconnected.add(subscriber)
        if disconnected:
            async with self._lock:
                self.sse_subscribers -= disconnected

    async def get_recent_events(self, limit: int = 100, event_type: Optional[EventType] = None,
                              user_id: Optional[str] = None, provider_id: Optional[str] = None) -> List[CanonicalEvent]:
        """Get recent events with filtering"""

        async with AsyncSessionLocal() as db:
            from sqlalchemy import select, desc

            query = select(DBEvent)

            if event_type:
                query = query.where(DBEvent.type == event_type.value)
            if user_id:
                query = query.where(DBEvent.user_id == user_id)
            if provider_id:
                query = query.where(DBEvent.provider_id == provider_id)

            query = query.order_by(desc(DBEvent.occurred_at)).limit(limit)

            result = await db.execute(query)
            db_events = result.scalars().all()

            events = []
            for db_event in db_events:
                events.append(CanonicalEvent(
                    id=db_event.id,
                    type=EventType(db_event.type),
                    job_id=db_event.job_id,
                    provider_id=db_event.provider_id,
                    external_id=db_event.external_id,
                    user_id=db_event.user_id,
                    occurred_at=db_event.occurred_at,
                    payload_meta=json.loads(db_event.payload_meta) if db_event.payload_meta else {},
                    correlation_id=db_event.correlation_id
                ))

            return events

    def add_sse_subscriber(self, subscriber):
        """Add SSE subscriber for real-time events"""
        # Guarded add to prevent concurrent modification
        # (In real code, make this async and use the lock; for plan clarity shown sync)
        self.sse_subscribers.add(subscriber)

    def remove_sse_subscriber(self, subscriber):
        """Remove SSE subscriber"""
        self.sse_subscribers.discard(subscriber)

class SSESubscriber:
    """SSE subscriber for admin diagnostics"""

    def __init__(self, queue):
        self.queue = queue
        self.connected = True

    async def send_event(self, event_data: Dict[str, Any]):
        """Send event to SSE client"""
        if not self.connected:
            raise ConnectionError("SSE connection closed")

        await self.queue.put({
            'event': 'message',
            'data': json.dumps(event_data)
        })

    def disconnect(self):
        """Mark subscriber as disconnected"""
        self.connected = False
```

### 8. SSE Diagnostics Endpoint

**Create `api/app/routers/admin_diagnostics.py`**

```python
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sse_starlette.sse import EventSourceResponse
import asyncio
import json
from typing import Optional

from api.app.services.events import EventEmitter, SSESubscriber
from api.app.middleware.auth import get_auth_context

router = APIRouter(prefix="/admin/diagnostics", tags=["Diagnostics"])

@router.get("/events")
async def events_sse_stream(
    request: Request,
    auth_context = Depends(get_auth_context),
    event_type: Optional[str] = None,
    provider_id: Optional[str] = None
):
    """SSE stream for real-time event diagnostics (admin only)"""

    # Require admin_capable trait
    if 'admin_capable' not in auth_context.traits:
        raise HTTPException(403, "Admin access required")

    event_emitter: EventEmitter = request.app.state.event_emitter

    async def event_stream():
        queue = asyncio.Queue()
        subscriber = SSESubscriber(queue)

        try:
            # Add subscriber
            event_emitter.add_sse_subscriber(subscriber)

            # Send recent events first
            recent_events = await event_emitter.get_recent_events(
                limit=10,
                provider_id=provider_id
            )

            for event in reversed(recent_events):  # Oldest first
                yield {
                    'event': 'message',
                    'data': json.dumps({
                        'id': event.id,
                        'type': event.type.value,
                        'job_id': event.job_id,
                        'provider_id': event.provider_id,
                        'occurred_at': event.occurred_at.isoformat(),
                        'payload_meta': event.payload_meta,
                        'historical': True
                    })
                }

            # Stream new events
            while True:
                try:
                    event_data = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield event_data
                except asyncio.TimeoutError:
                    # Send keepalive
                    yield {'event': 'ping', 'data': 'keepalive'}

        except asyncio.CancelledError:
            pass
        finally:
            event_emitter.remove_sse_subscriber(subscriber)
            subscriber.disconnect()

    return EventSourceResponse(event_stream())

@router.get("/events/recent")
async def get_recent_events(
    request: Request,
    auth_context = Depends(get_auth_context),
    limit: int = 50,
    event_type: Optional[str] = None,
    provider_id: Optional[str] = None
):
    """Get recent events (admin only)"""

    # Require admin_capable trait
    if 'admin_capable' not in auth_context.traits:
        raise HTTPException(403, "Admin access required")

    event_emitter: EventEmitter = request.app.state.event_emitter

    events = await event_emitter.get_recent_events(
        limit=limit,
        provider_id=provider_id
    )

    return {
        'events': [
            {
                'id': event.id,
                'type': event.type.value,
                'job_id': event.job_id,
                'provider_id': event.provider_id,
                'external_id': event.external_id,
                'user_id': event.user_id,
                'occurred_at': event.occurred_at.isoformat(),
                'payload_meta': event.payload_meta,
                'correlation_id': event.correlation_id
            }
            for event in events
        ],
        'total': len(events)
    }
```

## Week 4-5: Provider Health & Circuit Breaker

### 9. Provider Health Monitoring

**Create `api/app/services/provider_health.py`**

```python
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Literal
from dataclasses import dataclass, field
from enum import Enum
import json

from api.app.plugins.manager import PluginManager
from api.app.services.events import EventEmitter, EventType
from api.app.core.audit import AuditLevel

ProviderStatus = Literal['healthy', 'degraded', 'circuit_open', 'disabled']

@dataclass
class HealthCheck:
    """Provider health check result"""
    provider_id: str
    provider_type: str
    success: bool
    response_time_ms: float
    details: Dict[str, any] = field(default_factory=dict)
    error: Optional[str] = None
    checked_at: datetime = field(default_factory=datetime.utcnow)

@dataclass
class CircuitBreakerState:
    """Circuit breaker state for a provider"""
    provider_id: str
    status: ProviderStatus = 'healthy'
    failure_count: int = 0
    last_failure_time: Optional[datetime] = None
    last_success_time: Optional[datetime] = None
    circuit_opened_at: Optional[datetime] = None
    next_retry_at: Optional[datetime] = None
    failure_threshold: int = 5
    recovery_timeout_seconds: int = 60
    health_check_interval_seconds: int = 300

    def should_allow_request(self) -> bool:
        """Check if requests should be allowed through circuit breaker"""
        now = datetime.utcnow()

        if self.status == 'healthy':
            return True
        elif self.status == 'degraded':
            return True  # Allow with warnings
        elif self.status == 'circuit_open':
            # Check if we should try to recover
            if self.next_retry_at and now >= self.next_retry_at:
                return True  # Try one request
            return False
        elif self.status == 'disabled':
            return False

        return False

    def record_success(self):
        """Record successful request"""
        self.last_success_time = datetime.utcnow()
        if self.status == 'circuit_open':
            # Circuit breaker recovery
            self.status = 'healthy'
            self.failure_count = 0
            self.circuit_opened_at = None
            self.next_retry_at = None
        elif self.status == 'degraded' and self.failure_count > 0:
            self.failure_count = max(0, self.failure_count - 1)
            if self.failure_count == 0:
                self.status = 'healthy'

    def record_failure(self, error: str):
        """Record failed request"""
        now = datetime.utcnow()
        self.last_failure_time = now
        self.failure_count += 1

        if self.failure_count >= self.failure_threshold:
            if self.status != 'circuit_open':
                self.status = 'circuit_open'
                self.circuit_opened_at = now
                self.next_retry_at = now + timedelta(seconds=self.recovery_timeout_seconds)
        elif self.failure_count >= self.failure_threshold // 2:
            if self.status == 'healthy':
                self.status = 'degraded'

class ProviderHealthMonitor:
    """Monitor provider health with circuit breaker functionality"""

    def __init__(self, plugin_manager: PluginManager, event_emitter: EventEmitter,
                 config_provider, audit_logger=None):
        self.plugin_manager = plugin_manager
        self.event_emitter = event_emitter
        self.config_provider = config_provider
        self.audit_logger = audit_logger
        self.circuit_states: Dict[str, CircuitBreakerState] = {}
        self.health_check_task: Optional[asyncio.Task] = None
        self.running = False

    async def start_monitoring(self):
        """Start background health monitoring"""
        if self.running:
            return

        self.running = True
        self.health_check_task = asyncio.create_task(self._health_check_loop())

        if self.audit_logger:
            self.audit_logger.log_event('provider_health_monitoring_started', AuditLevel.STANDARD)

    async def stop_monitoring(self):
        """Stop background health monitoring"""
        self.running = False
        if self.health_check_task:
            self.health_check_task.cancel()
            try:
                await self.health_check_task
            except asyncio.CancelledError:
                pass

        if self.audit_logger:
            self.audit_logger.log_event('provider_health_monitoring_stopped', AuditLevel.STANDARD)

    async def _health_check_loop(self):
        """Background loop for health checks"""
        while self.running:
            try:
                await self._perform_health_checks()

                # Get check interval from config
                interval = await self._get_health_check_interval()
                await asyncio.sleep(interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                if self.audit_logger:
                    self.audit_logger.log_event('health_check_loop_error', AuditLevel.HIGH,
                                              error=str(e))
                await asyncio.sleep(60)  # Back off on error

    async def _perform_health_checks(self):
        """Perform health checks on all providers"""
        transport_plugins = self.plugin_manager.get_plugins_by_type('transport')

        for provider_id, plugin in transport_plugins.items():
            try:
                health_check = await self._check_provider_health(provider_id, plugin)
                await self._update_circuit_breaker(health_check)

            except Exception as e:
                if self.audit_logger:
                    self.audit_logger.log_event('provider_health_check_error', AuditLevel.HIGH,
                                              provider_id=provider_id, error=str(e))

    async def _check_provider_health(self, provider_id: str, plugin) -> HealthCheck:
        """Check health of a specific provider"""
        start_time = datetime.utcnow()

        try:
            # Check if provider has health check method
            if hasattr(plugin, 'check_health'):
                result = await plugin.check_health()
                response_time = (datetime.utcnow() - start_time).total_seconds() * 1000

                return HealthCheck(
                    provider_id=provider_id,
                    provider_type=plugin.plugin_type,
                    success=result.get('ok', False),
                    response_time_ms=response_time,
                    details=result.get('details', {}),
                    error=result.get('error')
                )
            else:
                # No health check method - assume healthy if plugin loaded
                return HealthCheck(
                    provider_id=provider_id,
                    provider_type=plugin.plugin_type,
                    success=True,
                    response_time_ms=0,
                    details={'method': 'plugin_loaded_check'}
                )

        except Exception as e:
            response_time = (datetime.utcnow() - start_time).total_seconds() * 1000
            return HealthCheck(
                provider_id=provider_id,
                provider_type=plugin.plugin_type,
                success=False,
                response_time_ms=response_time,
                error=str(e)
            )

    async def _update_circuit_breaker(self, health_check: HealthCheck):
        """Update circuit breaker state based on health check"""
        provider_id = health_check.provider_id

        # Get or create circuit breaker state
        if provider_id not in self.circuit_states:
            self.circuit_states[provider_id] = CircuitBreakerState(
                provider_id=provider_id,
                failure_threshold=await self._get_circuit_breaker_threshold(provider_id),
                recovery_timeout_seconds=await self._get_circuit_breaker_timeout(provider_id)
            )

        circuit_state = self.circuit_states[provider_id]
        old_status = circuit_state.status

        if health_check.success:
            circuit_state.record_success()
        else:
            circuit_state.record_failure(health_check.error or 'Health check failed')

        # Emit event if status changed
        if circuit_state.status != old_status:
            await self.event_emitter.emit_event(
                EventType.PROVIDER_HEALTH_CHANGED,
                provider_id=provider_id,
                payload_meta={
                    'old_status': old_status,
                    'new_status': circuit_state.status,
                    'failure_count': circuit_state.failure_count,
                    'response_time_ms': health_check.response_time_ms
                }
            )

            if self.audit_logger:
                self.audit_logger.log_event('provider_status_changed', AuditLevel.HIGH,
                    provider_id=provider_id, old_status=old_status,
                    new_status=circuit_state.status, failure_count=circuit_state.failure_count)

    async def _get_health_check_interval(self) -> int:
        """Get health check interval from configuration"""
        try:
            system_ctx = {'user_id': 'system', 'groups': [], 'department': None, 'tenant_id': None}
            return await self.config_provider.get_effective('provider.health_check_interval', system_ctx) or 300
        except:
            return 300  # 5 minutes default

    async def _get_circuit_breaker_threshold(self, provider_id: str) -> int:
        """Get circuit breaker threshold for provider"""
        try:
            system_ctx = {'user_id': 'system', 'groups': [], 'department': None, 'tenant_id': None}
            key = f'provider.{provider_id}.circuit_breaker_threshold'
            return await self.config_provider.get_effective(key, system_ctx) or 5
        except:
            return 5  # Default threshold

    async def _get_circuit_breaker_timeout(self, provider_id: str) -> int:
        """Get circuit breaker recovery timeout for provider"""
        try:
            system_ctx = {'user_id': 'system', 'groups': [], 'department': None, 'tenant_id': None}
            key = f'provider.{provider_id}.circuit_breaker_timeout'
            return await self.config_provider.get_effective(key, system_ctx) or 60
        except:
            return 60  # Default 1 minute

    def should_allow_request(self, provider_id: str) -> bool:
        """Check if provider should receive requests"""
        if provider_id not in self.circuit_states:
            return True  # No circuit breaker info, allow by default

        return self.circuit_states[provider_id].should_allow_request()

    def record_request_result(self, provider_id: str, success: bool, error: str = None):
        """Record result of provider request (for circuit breaker)"""
        if provider_id not in self.circuit_states:
            self.circuit_states[provider_id] = CircuitBreakerState(provider_id=provider_id)

        circuit_state = self.circuit_states[provider_id]
        old_status = circuit_state.status

        if success:
            circuit_state.record_success()
        else:
            circuit_state.record_failure(error or 'Request failed')

        # Emit event if status changed (async fire-and-forget)
        if circuit_state.status != old_status:
            asyncio.create_task(self.event_emitter.emit_event(
                EventType.PROVIDER_HEALTH_CHANGED,
                provider_id=provider_id,
                payload_meta={
                    'old_status': old_status,
                    'new_status': circuit_state.status,
                    'trigger': 'request_result'
                }
            ))

    async def get_provider_statuses(self) -> Dict[str, Dict]:
        """Get current status of all providers"""
        statuses = {}
        transport_plugins = self.plugin_manager.get_plugins_by_type('transport')

        for provider_id, plugin in transport_plugins.items():
            circuit_state = self.circuit_states.get(provider_id)

            status_info = {
                'provider_id': provider_id,
                'provider_type': plugin.plugin_type,
                'status': circuit_state.status if circuit_state else 'healthy',
                'failure_count': circuit_state.failure_count if circuit_state else 0,
                'last_success': circuit_state.last_success_time.isoformat() if circuit_state and circuit_state.last_success_time else None,
                'last_failure': circuit_state.last_failure_time.isoformat() if circuit_state and circuit_state.last_failure_time else None,
            }

            if circuit_state and circuit_state.status == 'circuit_open':
                status_info['next_retry_at'] = circuit_state.next_retry_at.isoformat() if circuit_state.next_retry_at else None

            statuses[provider_id] = status_info

        return statuses

    async def manual_enable_provider(self, provider_id: str):
        """Manually enable a provider (admin action)"""
        if provider_id in self.circuit_states:
            old_status = self.circuit_states[provider_id].status
            self.circuit_states[provider_id].status = 'healthy'
            self.circuit_states[provider_id].failure_count = 0
            self.circuit_states[provider_id].circuit_opened_at = None
            self.circuit_states[provider_id].next_retry_at = None

            await self.event_emitter.emit_event(
                EventType.PROVIDER_HEALTH_CHANGED,
                provider_id=provider_id,
                payload_meta={
                    'old_status': old_status,
                    'new_status': 'healthy',
                    'trigger': 'manual_enable'
                }
            )

            if self.audit_logger:
                self.audit_logger.log_event('provider_manually_enabled', AuditLevel.STANDARD,
                    provider_id=provider_id, old_status=old_status)

    async def manual_disable_provider(self, provider_id: str):
        """Manually disable a provider (admin action)"""
        if provider_id not in self.circuit_states:
            self.circuit_states[provider_id] = CircuitBreakerState(provider_id=provider_id)

        old_status = self.circuit_states[provider_id].status
        self.circuit_states[provider_id].status = 'disabled'

        await self.event_emitter.emit_event(
            EventType.PROVIDER_HEALTH_CHANGED,
            provider_id=provider_id,
            payload_meta={
                'old_status': old_status,
                'new_status': 'disabled',
                'trigger': 'manual_disable'
            }
        )

        if self.audit_logger:
            self.audit_logger.log_event('provider_manually_disabled', AuditLevel.HIGH,
                provider_id=provider_id, old_status=old_status)
```

## Week 5-6: Testing Strategy & Acceptance Criteria

### 10. Comprehensive Testing Plan

**Unit Testing Requirements:**

```python
# test_hierarchical_config.py
import pytest
from api.app.config.hierarchical_provider import HierarchicalConfigProvider, UserContext

@pytest.mark.asyncio
class TestHierarchicalConfig:
    async def test_hierarchy_resolution_order(self):
        """Test that config resolves in correct hierarchy order"""
        # User > Group > Department > Tenant > Global > Default

    async def test_cache_invalidation_patterns(self):
        """Test cache invalidation works for all levels"""

    async def test_encryption_roundtrip(self):
        """Test config encryption/decryption works correctly"""

    async def test_safe_key_validation(self):
        """Test safe key constraints are enforced"""

# test_circuit_breaker.py
@pytest.mark.asyncio
class TestCircuitBreaker:
    async def test_failure_threshold_triggers(self):
        """Test circuit opens after threshold failures"""

    async def test_recovery_after_success(self):
        """Test circuit closes after successful recovery"""

    async def test_degraded_state_behavior(self):
        """Test degraded state allows requests with warnings"""

# test_canonical_events.py
@pytest.mark.asyncio
class TestCanonicalEvents:
    async def test_event_sanitization(self):
        """Test PHI is removed from event payloads"""

    async def test_sse_subscriber_cleanup(self):
        """Test SSE subscribers are cleaned up on disconnect"""

    async def test_event_persistence(self):
        """Test events are persisted correctly"""
```

**Integration Testing Requirements:**

```python
# test_config_integration.py
@pytest.mark.asyncio
class TestConfigIntegration:
    async def test_config_change_cache_invalidation(self):
        """Test config changes invalidate relevant caches"""

    async def test_hierarchical_resolution_with_real_db(self):
        """Test full hierarchy with database"""

    async def test_admin_console_safe_edit_flow(self):
        """Test Admin Console can edit safe keys only"""

# test_provider_health_integration.py
@pytest.mark.asyncio
class TestProviderHealthIntegration:
    async def test_health_check_triggers_circuit_breaker(self):
        """Test health checks update circuit breaker state"""

    async def test_failed_requests_update_circuit_state(self):
        """Test request failures trigger circuit breaker"""

    async def test_sse_events_on_status_change(self):
        """Test SSE events emitted on provider status changes"""
```

**Security Testing Requirements:**

```python
# test_security.py
@pytest.mark.asyncio
class TestPhase3Security:
    async def test_config_encryption_at_rest(self):
        """Test sensitive config values encrypted in database"""

    async def test_admin_trait_required_for_config(self):
        """Test admin_capable trait required for config access"""

    async def test_no_phi_in_events(self):
        """Test no PHI appears in canonical events"""

    async def test_sse_admin_only_access(self):
        """Test SSE diagnostics require admin access"""

    async def test_safe_keys_constraint_enforcement(self):
        """Test unsafe config keys rejected via API"""
```

### 11. Acceptance Criteria Checklist

**✅ Configuration Management:**
- [ ] Hierarchical config resolution: User → Group → Department → Tenant → Global → Default
- [ ] Admin Console shows effective values with source badges (db/env/default/cache)
- [ ] Configuration changes persist without service restart
- [ ] Audit trail created for all config changes
- [ ] Safe keys editable via Admin Console with constraint validation
- [ ] Secrets masked in UI, encrypted at rest, never logged

**✅ Caching & Performance:**
- [ ] Redis cache implemented with local fallback
- [ ] Cache invalidation works for pattern-based deletions
- [ ] Service remains functional when Redis unavailable
- [ ] Cache statistics visible in Admin Console
- [ ] Configuration resolution ≤ 5ms p95 with cache hits

**✅ Canonical Events:**
- [ ] Events emitted consistently across all providers
- [ ] Event persistence with no PHI in payload_meta
- [ ] SSE diagnostics stream available to admin users
- [ ] Event correlation IDs for request tracing
- [ ] Recent events accessible via API with filtering

**✅ Provider Health & Circuit Breaker:**
- [ ] Provider health checks run automatically
- [ ] Circuit breaker triggers after configured failure threshold
- [ ] Provider status visible in Admin Console diagnostics
- [ ] Manual enable/disable controls for providers
- [ ] Failed requests blocked when circuit open

**✅ Security & Compliance:**
- [ ] All configuration access requires admin_capable trait
- [ ] No PHI in events, SSE streams, or diagnostics
- [ ] Secrets encrypted at rest with Fernet (AES‑CBC + HMAC) using 44‑char `CONFIG_MASTER_KEY`
- [ ] Audit logging for all administrative actions
- [ ] CSRF protection for Admin Console configuration changes

**✅ Admin Console Integration:**
- [ ] Configuration Manager integrated into Settings
- [ ] Provider status cards in Diagnostics panel
- [ ] SSE event stream with real-time updates
- [ ] Responsive design across xs/sm/md breakpoints
- [ ] Documentation links for all features

## Timeline Summary (5-6 weeks)

**Week 1:** Database migrations, hierarchical config provider, Redis cache manager
**Week 2:** Configuration API endpoints, Admin Console configuration manager (read-only)
**Week 3:** Safe key editing, canonical events system, SSE diagnostics endpoints
**Week 4:** Provider health monitoring, circuit breaker implementation
**Week 5:** Integration testing, security hardening, performance optimization
**Week 6:** Documentation, acceptance testing, deployment preparation

## File Structure Summary

```
api/app/
├── config/
│   ├── hierarchical_provider.py     # Enhanced config with hierarchy
│   └── models/
│       └── config.py               # DB models for config tables
├── services/
│   ├── cache_manager.py           # Redis + local cache
│   ├── events.py                  # Canonical events system
│   └── provider_health.py         # Health monitoring & circuit breaker
├── routers/
│   ├── admin_config.py            # Config management endpoints
│   └── admin_diagnostics.py       # SSE diagnostics endpoints
├── models/
│   └── config.py                  # Config database models
└── db/migrations/
    └── 003_hierarchical_config.py # Schema migrations

admin_ui/src/components/
├── ConfigurationManager.tsx       # Full config management UI
└── diagnostics/
    └── EventsStream.tsx           # SSE events component
```

This comprehensive Phase 3 plan provides enterprise-grade configuration management, reliability monitoring, and diagnostic capabilities while maintaining HIPAA compliance and backward compatibility.

All plugin discovery is manifest‑first (validate with `plugin-dev-kit/manifest.schema.json`) and class validation at import (must inherit correct typed base).

## Architecture Workstreams

### 1) Hierarchical Configuration

Objective: Replace flat `.env` assumptions with a hierarchical, multi‑tenant configuration that resolves effectively per user context and is safely editable in the Admin Console.

#### 1.1 DB Schema (minimum viable, aligned with migration doc)

```sql
-- Global defaults (single row per key)
CREATE TABLE IF NOT EXISTS config_global (
  key               VARCHAR(200) PRIMARY KEY,
  value_encrypted   TEXT NOT NULL,
  value_type        VARCHAR(20) NOT NULL DEFAULT 'string',
  encrypted         BOOLEAN NOT NULL DEFAULT TRUE,
  description       TEXT,
  category          VARCHAR(50),
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Tenant level
CREATE TABLE IF NOT EXISTS config_tenant (
  tenant_id         VARCHAR(100) NOT NULL,
  key               VARCHAR(200) NOT NULL,
  value_encrypted   TEXT NOT NULL,
  value_type        VARCHAR(20) NOT NULL DEFAULT 'string',
  encrypted         BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(tenant_id, key)
);

-- Department level
CREATE TABLE IF NOT EXISTS config_department (
  tenant_id         VARCHAR(100) NOT NULL,
  department        VARCHAR(100) NOT NULL,
  key               VARCHAR(200) NOT NULL,
  value_encrypted   TEXT NOT NULL,
  value_type        VARCHAR(20) NOT NULL DEFAULT 'string',
  encrypted         BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(tenant_id, department, key)
);

-- Group level
CREATE TABLE IF NOT EXISTS config_group (
  group_id          VARCHAR(100) NOT NULL,
  key               VARCHAR(200) NOT NULL,
  value_encrypted   TEXT NOT NULL,
  value_type        VARCHAR(20) NOT NULL DEFAULT 'string',
  encrypted         BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(group_id, key)
);

-- User level
CREATE TABLE IF NOT EXISTS config_user (
  user_id           VARCHAR(100) NOT NULL,
  key               VARCHAR(200) NOT NULL,
  value_encrypted   TEXT NOT NULL,
  value_type        VARCHAR(20) NOT NULL DEFAULT 'string',
  encrypted         BOOLEAN NOT NULL DEFAULT TRUE,
  updated_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id, key)
);

-- Audit trail
CREATE TABLE IF NOT EXISTS config_audit (
  id                VARCHAR(40) PRIMARY KEY,
  level             VARCHAR(20) NOT NULL,           -- global|tenant|department|group|user
  level_id          VARCHAR(200),                   -- e.g., tenant id, user id
  key               VARCHAR(200) NOT NULL,
  old_value         TEXT,
  new_value         TEXT NOT NULL,                  -- decrypted snapshot
  changed_by        VARCHAR(100) NOT NULL,          -- user id/key id
  changed_at        TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reason            TEXT
);

CREATE INDEX IF NOT EXISTS idx_cfg_tenant_key ON config_tenant(tenant_id, key);
CREATE INDEX IF NOT EXISTS idx_cfg_dept_key   ON config_department(tenant_id, department, key);
CREATE INDEX IF NOT EXISTS idx_cfg_group_key  ON config_group(group_id, key);
CREATE INDEX IF NOT EXISTS idx_cfg_user_key   ON config_user(user_id, key);
```

Encryption at rest uses Fernet (AES‑CBC + HMAC) with `CONFIG_MASTER_KEY` (44‑char base64); boot fails fast if missing/invalid. Values are decrypted in‑process only; no secret values are ever logged or sent to the UI unmasked. AES‑GCM can be adopted later without plan changes.

#### 1.2 HybridConfigProvider Extensions

```python
# api/app/config/provider.py
from abc import ABC, abstractmethod
from typing import Optional, Literal, Any, Dict, List

Source = Literal['db','env','default']

class HybridConfigProvider(ABC):
    @abstractmethod
    def get(self, key: str, default: Optional[Any] = None) -> Any: ...

    @abstractmethod
    def set(self, key: str, value: Any, *, level: str = 'global', level_id: Optional[str] = None,
            changed_by: str = 'system', reason: str = '') -> None: ...

    @abstractmethod
    def source(self, key: str) -> Source: ...

    @abstractmethod
    def get_effective(self, key: str, user_context: Dict[str, Any], default: Optional[Any] = None) -> Any: ...

    @abstractmethod
    def get_hierarchy(self, key: str, user_context: Dict[str, Any]) -> List[Dict[str, Any]]: ...

    @abstractmethod
    def get_provider_config(self, provider_id: str, user_context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]: ...
```

Resolution order: User → Group(s) (first match wins by configured priority) → Department → Tenant → Global → default → `.env` fallback only when DB absent. All reads go through a Redis + local cache (see 2).

### 2) Redis Caching + Invalidation

#### 2.1 Cache Shape

- Local in‑process cache (LRU) for hottest keys (TTL 60s)
- Redis keys:
  - Effective value: `cfg:eff:<tenant>:<dept>:<user>:<groups>:<key>` (TTL 300s)
  - Raw level entries: `cfg:raw:<level>:<level_id>:<key>` (TTL 600s)

Helpers (use these for both setting and invalidation to avoid drift):
```python
def eff_key(ctx, key):
    groups = ','.join(sorted(ctx.groups or [])) or 'null'
    return f"cfg:eff:{ctx.tenant_id or 'null'}:{ctx.department or 'null'}:{ctx.user_id or 'null'}:{groups}:{key}"

def eff_pattern_all(key):
    return f"cfg:eff:*:*:*:*:{key}"

def eff_pattern_tenant(tenant_id, key):
    return f"cfg:eff:{tenant_id}:*:*:*:{key}"
```

#### 2.2 Invalidation

- On `set(...)`:
  - Compute invalidation pattern(s) using helpers above
  - Delete matching Redis keys
  - Clear local cache entries with same composite key
- Provide `POST /admin/config/flush-cache?scope=` for targeted admin invalidation (trait‑gated)

### 3) Admin Console Configuration Manager (UI)

#### 3.1 Screen Skeleton

```tsx
// api/admin_ui/src/components/ConfigurationManager.tsx
import React, { useMemo, useState } from 'react';
import { Box, Typography, Stack, Alert, Button, Chip } from '@mui/material';
import AdminAPIClient from '../api/client';
import { ResponsiveCard } from './common/ResponsiveCard';
import { ResponsiveFormSection, ResponsiveTextField, ResponsiveSelect } from './common/ResponsiveFormFields';

type Props = { client: AdminAPIClient; docsBase?: string };

export default function ConfigurationManager({ client, docsBase }: Props) {
  // State: selected level/scope, effective config, hierarchy view
  // Actions: save safe keys, test provider connection
  // Trait‑gated controls (admin_capable)
  return (
    <ResponsiveCard title="Configuration" subtitle="Hierarchical, safe, and live">
      {/* Level selector */}
      {/* Effective config with source badges */}
      {/* Hierarchy panel: show layered values */}
      {/* Safe edit section: only non‑secret toggles or numeric thresholds */}
      {/* Learn more links via docsBase */}
    </ResponsiveCard>
  );
}
```

#### 3.2 UX Requirements

- Level selector: Global/Tenant/Department/Group/User (trait‑gated)
- Effective config list with source badges (`db`, `env`, `default`)
- Safe edit section (Phase 3): booleans/ints only (e.g., rate limits, feature flags). Secrets remain masked read‑only.
- “Test connection” button for current outbound provider (calls `/admin/providers/test`)
- Diagnostics banner when DB empty (“Using .env fallback”)
- At least one “Learn more” link per section via `docsBase`

### 4) Canonical Events Lifecycle

#### 4.1 Events Table and Emitter

```sql
CREATE TABLE IF NOT EXISTS events (
  id             VARCHAR(40) PRIMARY KEY,
  type           VARCHAR(40) NOT NULL,     -- FAX_QUEUED|FAX_SENT|FAX_DELIVERED|FAX_FAILED|FAX_RETRYING
  job_id         VARCHAR(40) NOT NULL,
  provider_id    VARCHAR(40) NOT NULL,
  external_id    VARCHAR(100),
  occurred_at    TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  payload_meta   TEXT                     -- JSON, metadata only (no PHI)
);
CREATE INDEX IF NOT EXISTS idx_events_job_time ON events(job_id, occurred_at DESC);
```

```python
# api/app/services/events.py
from typing import Dict, Any

def emit_event(evt_type: str, job_id: str, provider_id: str, external_id: str | None, payload_meta: Dict[str, Any] | None = None):
    """Persist canonical event and optionally notify SSE diagnostics."""
    # Insert into events table (payload_meta json.dumps)
    # Publish to internal bus for admin SSE (IDs/metadata only)
    pass
```

#### 4.2 SSE Diagnostics (Admin‑only)

- Endpoint: `/admin/diagnostics/events` (SSE). Streams last N events and new ones (no PHI).
- Surface: event type, job id, provider id, timestamps, meta (e.g., pages count if non‑PHI) 

### 5) Provider Health + Circuit Breaker

#### 5.1 Health Interface

```python
# Optional method on transport plugins
class TransportPlugin(FaxbotPlugin, ABC):
    ...
    def check_health(self) -> dict:
        """Fast provider health probe. Return { ok: bool, details?: {...} }"""
        return { 'ok': True }
```

#### 5.2 Failure Accounting

- Track failures per plugin with sliding window counters
- Thresholds configurable via config (e.g., `providers.transport.<id>.breaker`)
- States: `ok` → `degraded` → `disabled` (with manual re‑enable)
- Admin Diagnostics: show state, last error, auto‑disable toggle

### 6) Webhook/Callback Hardening (keep existing routes)

#### 6.1 Routing Rules

- Persist `job.provider_id` and `job.external_id` at send time
- Callback routes (e.g., `/callbacks/phaxio`, `/callbacks/sinch`) perform:
  1) `plugin.verify_webhook(headers, body)` → 401/403 on fail
  2) Parse payload → extract `external_id`
  3) Lookup job by `(provider_id, external_id)`
  4) Call `plugin.handle_status_callback(data)` which sets canonical status and emits events
  5) On failure: retry/backoff; after max attempts, add to DLQ

- Unified inbound detection:
  - Autodetect provider by signature headers for unified handlers: `X-Phaxio-Signature` vs `X-Sinch-Signature`.
  - Sinch inbound Basic auth is enforced when configured (user/pass); prefer `application/json`, accept multipart.

```sql
CREATE TABLE IF NOT EXISTS webhook_dlq (
  id            VARCHAR(40) PRIMARY KEY,
  provider_id   VARCHAR(40) NOT NULL,
  external_id   VARCHAR(100),
  received_at   TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  status        VARCHAR(20) NOT NULL,     -- queued|retrying|failed
  error         TEXT,
  headers_meta  TEXT                      -- JSON; ALLOWLIST ONLY (no Authorization)
);
```

Header allowlist for DLQ persistence (server logic):
```python
ALLOW = {"user-agent","content-type","x-request-id","x-signature","x-timestamp"}
safe_headers = {k:v for k,v in headers.items() if k.lower() in ALLOW}
# Never persist Authorization or secrets; never persist full bodies
```

### 7) Rate Limiting (per key/endpoint)

#### 7.1 Middleware

```python
# api/app/middleware/ratelimit.py
from time import time
from typing import Optional

class RateLimiter:
    def __init__(self, redis, default_rpm: int = 60):
        self.redis = redis
        self.default_rpm = default_rpm

    async def allow(self, key: str, rpm: Optional[int] = None) -> bool:
        # Token bucket or fixed window in Redis
        # Key shape: rl:<minute>:<key>
        return True
```

Enforcement semantics:
- Honor `MAX_REQUESTS_PER_MINUTE=0` (disabled).
- Enforce on: `POST /fax/send`, `POST /admin/config/set`.
- Do NOT rate‑limit inbound callbacks.
- Return `429` with `Retry-After` and surface a diagnostics banner.

### Env → DB Importer & Migration Flag (prevent fallback regressions)

- Provide a one‑shot importer to write env keys into hierarchical config, then flip `admin.migration.env_to_db_done=true` in global config.
- Until the flag is set, Admin Console shows a banner “Using .env fallback; import to DB recommended.”
- After import, `.env` fallback is disabled except when DB is unavailable.

Example operator flow:
```bash
python - <<'PY'
from api.app.config.migrate import import_env_to_db
import_env_to_db(prefixes=["PHAXIO_","SINCH_","S3_","AWS_","STORAGE_"])
PY
# mark migration complete
curl -sS -X POST 'http://localhost:8080/admin/config/set?key=admin.migration.env_to_db_done&value=true&level=global'
```

Enforcement points (return 429 + `Retry-After` with an actionable hint in Admin Diagnostics):
- POST `/fax/send`
- POST `/admin/config/set`
- POST `/callbacks/*` (provider‑specific limits)

Wire in FastAPI middleware; read limits from hierarchical config (e.g., `security.ratelimit.fax_send_rpm`). Return 429 with `Retry-After`.

### 8) MCP SSE + OAuth (HIPAA path)

- Validate SSE transport with OAuth2/JWT using MCP Inspector
- Admin Console Diagnostics panel shows: SSE status, issuer, audience, token TTL (no tokens displayed)
- Docs links via `docsBase` → Apps → SSE guidance

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

## Server Endpoints (Detailed)

### Config

```http
GET /admin/config/effective
Headers: X-API-Key or Authorization: Bearer <token>
200 { values: { key: { value, source: 'db'|'env'|'default' } }, userContext: {...} }

GET /admin/config/hierarchy?key=<key>
200 { key, layers: [ { level, level_id, value, encrypted, updated_at }, ... ], effective: { value, source } }

POST /admin/config/set
Body: { key, value, level: 'global'|'tenant'|'department'|'group'|'user', level_id?, reason }
200 { success: true, effective: { value, source } }
Errors: 400 invalid, 403 insufficient traits, 409 unsafe secret write (Phase 3 blocks secrets)
```

### Providers

```http
GET /admin/providers
200 { providers: [ { id, name, type, traits:[], status: 'ok'|'degraded'|'disabled' } ] }

POST /admin/providers/test
Body: { id }
200 { ok: true, details: {...} } | 503 { ok: false, error }
```

### Events SSE (Admin only)

```http
GET /admin/diagnostics/events  (text/event-stream)
Event: message\nData: { id, type, job_id, provider_id, occurred_at, payload_meta }
```

### Webhooks

```http
POST /callbacks/phaxio
Headers include provider signature; body is forwarded to plugin.verify_webhook()
202 on accepted; 401/403 on signature fail; 200/202 for idempotent replays
```

## UI Components (Detailed)

### ConfigurationManager Controls

- Level selector (buttons or segmented control)
- Scope selector (tenant/department/group/user pickers; debounced, server‑filtered)
- Effective list with source chips
- Hierarchy accordion per key
- Safe key editor with type‑aware inputs (boolean switch, integer stepper)
- “Test connection” button and inline results

### Diagnostics Panel Enhancements

- Provider status chips (ok/degraded/disabled)
- SSE status card (issuer, audience, TTL, connection state)
- Recent canonical events list (IDs only)

## Security & HIPAA

- No PHI in logs, SSE, events, or UI
- Secrets masked in UI; encrypted at rest; never logged
- Webhook verification mandatory (HMAC/signature) when provider supports it
- SSE is the only HIPAA‑compliant MCP transport

## Testing Strategy

### Unit

- Config resolution tests for each level and merging rules
- Cache hit/miss and invalidation
- Rate limiter boundaries and `Retry-After`

### Integration

- Set values at different levels; verify effective resolution
- Send fax with `Idempotency-Key`; replay; verify same job returned
- Receive webhook: verify signature, route by provider/external id, emit events
- Circuit breaker: simulate N failures, verify degraded/disabled states

### MCP Validation

- Use MCP Inspector for SSE + OAuth token flows and expiry

### UI

- xs/sm/md layout checks, loaders, actionable errors, `docsBase` links
- Trait‑gated elements hidden for insufficient roles

## Acceptance Criteria

1) Hierarchical config resolves User → Group → Department → Tenant → Global → default, with `.env` fallback only when DB absent
2) Admin Console `ConfigurationManager` shows effective values with `source` badges, layered hierarchy, and supports writing a curated set of safe keys
3) Redis cache + local cache implemented with precise invalidation; service remains functional if Redis absent
4) Canonical events persisted and available via admin SSE diagnostics; no PHI
5) Webhooks verified, routed by `(provider_id, external_id)`, with DLQ for hard failures
6) Provider health checks + circuit breaker surfaced in Diagnostics; optional auto‑disable/enable
7) Rate limiting returns 429 with `Retry-After`; limits configurable via hierarchical config
8) MCP SSE OAuth path validated with MCP Inspector; Admin Console shows SSE status (no sensitive values)
9) Traits‑first gating throughout; no backend‑name conditionals; secrets masked; CSP unchanged

## File/Module Map

- Server
  - `api/app/config/provider.py` (hierarchy methods)
  - `api/app/routers/admin_config.py` (effective/hierarchy/set)
  - `api/app/routers/admin_providers.py` (list/test)
  - `api/app/services/events.py` (emitter + SSE adapter)
  - `api/app/middleware/ratelimit.py` (per key/endpoint)
  - `api/app/services/webhooks/common.py` (verify/route/DLQ)
- UI
  - `api/admin_ui/src/components/ConfigurationManager.tsx`
  - Diagnostics enhancements in existing panels

## Timeline (4–6 weeks)

- Week 1: DB migrations; provider extensions; config endpoints; cache layer
- Week 2: Admin Config Manager (read) + hierarchy; SSE diagnostics skeleton
- Week 3: Safe write path; canonical events persistence; provider health checks; DLQ
- Week 4: Circuit breaker + rate limiting; webhook verify/route; UI polish
- Week 5: MCP SSE OAuth validation; test coverage; docs anchors
- Week 6: Hardening; QA; acceptance runbook

# Phase 3: Hierarchical Configuration, Diagnostics, and Reliability

**Branch**: `auto-tunnel` (CRITICAL - all v4 work stays here)

## Executive Summary

Phase 3 delivers enterprise‑grade configuration and reliability: hierarchical config (Global → Tenant → Department → Group → User), Admin Console configuration management, Redis caching with precise invalidation, canonical events, webhook/callback hardening, provider health + circuit breaker, and MCP SSE OAuth validation. All work remains Admin Console‑first, traits‑first, and HIPAA‑aligned (no PHI in logs or streams).

Dependencies: Phase 1 (typed plugin bases, manifest discovery, HybridConfigProvider DB→.env, idempotency + canonical events, Admin diagnostics baseline) and Phase 2 (trait-based auth + sessions) must be complete.

## Goals

- Hierarchical config with DB‑first reads, `.env` fallback only when unset
- Admin Console: configuration manager (read/write) with trait‑gated scope
- Redis caching layer for configs with safe invalidation
- Canonical events lifecycle emitted consistently; SSE diagnostics (no PHI)
- Provider health checks + circuit breaker with Admin visibility
- Webhook/callback hardening with plugin `verify_webhook` and routed dispatch
- Rate limiting (per key, per endpoint) with safe defaults
- MCP SSE OAuth testing and surface status in Admin Console

## Non‑Goals (explicitly deferred)

- Full plugin marketplace/remote install (design only)
- Email Gateway HIPAA enablement (future phase)
- Cross‑tenant live migrations (manual tooling acceptable)

## Architecture Workstreams

### 1) Hierarchical Configuration (DB model + provider)

- Migrations: implement core tables from `v4_plans/config-hierarchy-migration.md` (global/tenant/department/group/user + audit). Keep minimal viable set for Phase 3; advanced templates remain optional.
- Provider: extend `HybridConfigProvider` with hierarchy aware getters:
  - `get_effective(key, user_context)` resolves User → Group(s) → Department → Tenant → Global → default
  - `get_hierarchy(key, user_context)` returns the layered values with `source` and `updated_at`
  - `set(key, value, *, level, level_id)` persists with audit and cache invalidation
- Encryption: encrypt sensitive values at rest (AES‑GCM via `CONFIG_MASTER_KEY`); never log secrets.
- `.env` import helper: optional CLI/API tool to import safe keys to DB (flags for target level).

Endpoints (server):
- `GET /admin/config/effective` → effective config for current user context (includes `source` badges)
- `GET /admin/config/hierarchy?key=` → layered view with metadata
- `POST /admin/config/set` → write scoped value (trait‑gated; limit to safe keys in Phase 3)

### 2) Redis Caching + Invalidation

- Add Redis-backed cache with local in‑process tier for hot keys
- Keys: namespaced by level, scope, and key (e.g., `cfg:eff:<tenant>:<dept>:<user>:<key>`) to allow precise invalidation
- Invalidate on writes (pattern-based + local clear); TTL defaults: 5m effective, 1m local
- Fallback cleanly when Redis absent (local only)

### 3) Admin Console Configuration Manager (UI)

- New screen `ConfigurationManager` (Settings area):
  - Level selector (Global/Tenant/Department/Group/User) with trait‑gated access
  - Read/write editor for a small curated set of safe keys in Phase 3 (feature toggles, non‑secret ints/booleans)
  - Hierarchy panel: shows layered values with `source` badges (db/env/default)
  - Effective preview for a selected user context
  - “Learn more” links built from `docsBase`; secrets masked
- Diagnostics banner when DB config empty (“Using .env fallback”)

### 4) Canonical Events Lifecycle

- Expand Phase 1 canonical events: emit from a central mapper regardless of backend
  - `FAX_QUEUED`, `FAX_SENT`, `FAX_DELIVERED`, `FAX_FAILED`, `FAX_RETRYING`
- Persistence: append‑only `events` table with `type`, `job_id`, `provider_id`, `external_id`, `occurred_at`, `payload_meta` (no PHI)
- SSE diagnostics stream (admin only) to surface recent events and provider health (IDs/metadata only; no PHI)

### 5) Provider Health + Circuit Breaker

- Health checks: pluggable `check_health()` on provider plugins (fast, read‑only)
- Failure accounting: if a plugin throws N times in M minutes, mark `status="degraded"`; auto‑disable after threshold if configured
- Admin Console: Diagnostics lists status, last error time, disable/enable controls (trait‑gated)

### 6) Webhook/Callback Hardening

- Route by persisted `provider_id`/`external_id`; never guess by “active provider”
- Use plugin `verify_webhook(headers, body)` before accept; return 401/403 on failure
- Retry/backoff with dead‑letter queue (DLQ) table for unprocessable callbacks
- Structured audit logs for webhook outcomes (no PHI)

### 7) Rate Limiting (Phase 3 scope)

- Implement simple token‑bucket limiter with per‑API‑key and per‑endpoint knobs
- Configurable via hierarchical config keys (e.g., `security.ratelimit.fax_send_rpm`)
- Return `429` with `Retry-After`; surface helpful UI guidance

### 8) MCP SSE + OAuth (HIPAA path)

- Validate SSE transport with OAuth2/JWT per `AGENTS.md` using the MCP Inspector
- Admin Console diagnostics: show SSE status, token lifetime, and issuer/audience metadata; no token values
- Docs links via `docsBase` to Apps → SSE guidance

## Admin Console Deliverables

- ConfigurationManager (Settings)
- Providers list (Tools/Diagnostics): provider name/type/traits/status + “Test connection”
- Diagnostics panel: active provider, trait snapshot, config source (db|env), SSE health, last events (IDs only)

All UI uses responsive kits, trait gating, masked secrets, and `docsBase` links.

## Server/API Deliverables

- Config endpoints: `GET /admin/config/effective`, `GET /admin/config/hierarchy`, `POST /admin/config/set`
- Providers endpoints: `GET /admin/providers` (traits + status), `POST /admin/providers/test`
- Events: internal append + admin SSE stream (IDs/metadata only)
- Webhook routes per provider with verify + DLQ
- Rate limiting middleware (per key/endpoint) with safe defaults

## Data Model Changes (minimum viable)

- `config_global`, `config_tenant`, `config_department`, `config_group`, `config_user` (per plan)
- `config_audit(id, key, old_value_masked?, new_value_masked, value_hmac, level, level_id, changed_by, changed_at, reason)`
- `events(id, type, job_id, provider_id, external_id, occurred_at, payload_meta)`
- `webhook_dlq(id, provider_id, external_id, received_at, status, error, headers_meta)`

## Security & Compliance

- No PHI in logs, events, SSE, or diagnostics
- Secrets encrypted at rest; masked in UI; never logged
- Webhook signature verification mandatory when provider supports it
- SSE is the only HIPAA‑compliant MCP transport; validate prior to completion

## Testing Plan

- Unit: config resolution across hierarchy; cache hit/miss; invalidation; rate limiter
- Integration: send with `Idempotency-Key`; receive webhook → verify → route → event persisted
- Reliability: simulate provider errors; verify circuit breaker; Admin status reflects transitions
- SSE: MCP Inspector validation; token expiry handling; no PHI leakage
- UI: xs/sm/md breakpoints, loaders, actionable errors, `docsBase` links

### Quick Audits (dev hygiene)

Run these one‑liners periodically to catch common pitfalls:

```bash
# Async ORM anti‑patterns (should not await .merge())
rg -n "await\s+.*\.merge\(" api/app || true

# Env fallback used where DB is available (should be gated by DB outage only)
rg -n "os\.getenv\(" api/app/config || true

# Cache keys and patterns consistency
rg -n "cfg:eff" api/app | sort || true

# Event/SSE unsafe access
rg -n "sse_subscribers|EventSourceResponse|StreamingResponse" api/app || true

# DLQ header persistence (ensure allowlist is used)
rg -n "headers_meta|Authorization" api/app/services || true

# Rate limiter wiring
rg -n "RateLimiter|ratelimit" api/app || true
```

## Acceptance Criteria

1) Hierarchical config works end‑to‑end: DB‑first reads; `.env` fallback only when DB is unavailable; writes persist without restart; audit entries created
2) Admin Console `ConfigurationManager` shows hierarchy, effective values with `source` badges, and allows editing of safe keys (trait‑gated)
3) Redis cache in place with correct invalidation; service continues with local cache if Redis absent
4) Canonical events emitted for lifecycle; admin SSE diagnostics stream shows recent events (IDs only)
5) Webhook routing by `provider_id`/`external_id` with signature verification; DLQ captures failures
6) Provider health checks and circuit breaker reflected in Admin Diagnostics; optional auto‑disable configurable
7) Rate limiting returns `429` with `Retry-After`, configurable via hierarchical config
8) MCP SSE OAuth path validated via MCP Inspector; status visible in Admin Console
9) No backend‑name string checks; all gating via traits and manifests; no PHI in logs/streams/UI

## File/Module Map (proposed)

- Server
  - `api/app/config/provider.py` (HybridConfigProvider extensions)
  - `api/app/routers/admin_config.py` (effective/hierarchy/set)
  - `api/app/routers/admin_providers.py` (list/test)
  - `api/app/services/events.py` (canonical event emitter + SSE adapter)
  - `api/app/middleware/ratelimit.py` (per key/endpoint)
  - `api/app/services/webhooks/common.py` (verify/route/DLQ helpers)
  - `api/app/plugins/*/*/plugin.py` (optional `check_health()`)
  - Reuse existing:
    - `api/app/plugins/registry/{service,validator,signature}.py` for manifest ingest/validation (do not replace)
    - `api/app/events/{bus,webhooks,delivery}.py` for event routing and delivery
    - `api/app/plugins/storage/{local,s3,azure,gcs}/` (local storage must remain available by default)
- UI
  - `api/admin_ui/src/components/ConfigurationManager.tsx`
  - Wire into `App.tsx` Settings; responsive kits + `docsBase`

## Timeline (4–6 weeks)

- Week 1: DB migrations, HybridConfigProvider hierarchy, Redis cache, config endpoints
- Week 2: Admin Console ConfigurationManager (read), effective/hierarchy views, source badges; SSE diagnostics skeleton
- Week 3: Write path for safe keys; canonical events persistence; provider health checks; DLQ
- Week 4: Circuit breaker, rate limiting, webhook verification & routing; UI diagnostics polish
- Week 5: MCP SSE OAuth validation, tests, docs anchors; performance pass
- Week 6: Hardening, QA, acceptance checklist
