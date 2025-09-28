# Runbook 02: Phase 2 - Core Services Implementation

## Objective
Build out essential core services: Identity & Authentication, Trait-Based Policy Engine, Configuration Management, and enhance plugin management with security. Integrate these services to enforce authorization and provide admin APIs.

## Prerequisites
- Phase 1 completed successfully
- PostgreSQL database running
- Core service operational
- Plugin registration working

## Tasks

### 1. Identity & Authentication Service

#### 1.1 Database Schema
```sql
-- core/identity/schema.sql
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    mfa_secret VARCHAR(255),
    mfa_enabled BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Roles table
CREATE TABLE roles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    traits JSONB NOT NULL DEFAULT '[]',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User roles junction table
CREATE TABLE user_roles (
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role_id UUID REFERENCES roles(id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by UUID REFERENCES users(id),
    PRIMARY KEY (user_id, role_id)
);

-- API Keys table for service-to-service auth
CREATE TABLE api_keys (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key_hash VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    owner_id UUID REFERENCES users(id),
    plugin_id VARCHAR(255),
    scopes JSONB DEFAULT '[]',
    last_used TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit log for authentication events
CREATE TABLE auth_audit (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id),
    event_type VARCHAR(50) NOT NULL, -- login, logout, failed_login, password_change
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL,
    details JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_auth_audit_user_id ON auth_audit(user_id);
CREATE INDEX idx_auth_audit_created_at ON auth_audit(created_at);

-- Default roles
INSERT INTO roles (name, description, traits) VALUES 
    ('admin', 'System Administrator', '["admin", "audit_viewer", "config_manager"]'),
    ('operator', 'System Operator', '["plugin_manager", "audit_viewer"]'),
    ('viewer', 'Read-only Access', '["viewer"]'),
    ('phi_handler', 'PHI Data Handler', '["handles_phi", "audit_required"]');
```

#### 1.2 Identity Service Implementation
```python
# core/identity/service.py
from typing import Optional, Dict, List
from datetime import datetime, timedelta
import bcrypt
import jwt
import secrets
import pyotp
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
import logging

logger = logging.getLogger(__name__)

class IdentityService:
    """Handles user authentication and authorization."""
    
    def __init__(self, db_session: AsyncSession, jwt_secret: str):
        self.db = db_session
        self.jwt_secret = jwt_secret
        self.token_expiry = timedelta(minutes=15)
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=30)
    
    async def create_user(
        self, 
        username: str, 
        email: str, 
        password: str,
        roles: List[str] = None,
        created_by: str = None
    ) -> Dict:
        """Create a new user with secure password hashing."""
        # Hash password with bcrypt
        salt = bcrypt.gensalt()
        password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
        
        # Create user record
        user = {
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "mfa_secret": pyotp.random_base32() if self._requires_mfa(roles) else None
        }
        
        # Insert into database
        result = await self.db.execute(
            "INSERT INTO users (username, email, password_hash, mfa_secret) VALUES (%s, %s, %s, %s) RETURNING id",
            (username, email, password_hash, user["mfa_secret"])
        )
        user_id = result.fetchone()[0]
        
        # Assign roles
        if roles:
            await self._assign_roles(user_id, roles, created_by)
        
        # Audit log
        await self._audit_log(user_id, "user_created", True, {"created_by": created_by})
        
        logger.info(f"User created: {username}", extra={"trace_id": user_id})
        return {"id": user_id, "username": username}
    
    async def authenticate(
        self, 
        username: str, 
        password: str,
        mfa_token: Optional[str] = None,
        ip_address: str = None
    ) -> Optional[Dict]:
        """Authenticate user and return JWT token."""
        # Fetch user
        user = await self.db.fetchone(
            "SELECT id, password_hash, mfa_secret, mfa_enabled, failed_login_attempts, locked_until FROM users WHERE username = %s AND is_active = TRUE",
            (username,)
        )
        
        if not user:
            await self._audit_log(None, "failed_login", False, {"username": username, "reason": "user_not_found"})
            return None
        
        # Check if account is locked
        if user["locked_until"] and user["locked_until"] > datetime.utcnow():
            await self._audit_log(user["id"], "failed_login", False, {"reason": "account_locked"})
            return None
        
        # Verify password
        if not bcrypt.checkpw(password.encode('utf-8'), user["password_hash"].encode('utf-8')):
            await self._handle_failed_login(user["id"], user["failed_login_attempts"])
            return None
        
        # Verify MFA if enabled
        if user["mfa_enabled"]:
            if not mfa_token or not self._verify_mfa(user["mfa_secret"], mfa_token):
                await self._audit_log(user["id"], "failed_login", False, {"reason": "invalid_mfa"})
                return None
        
        # Generate JWT token
        token = self._generate_jwt(user["id"], await self._get_user_traits(user["id"]))
        
        # Update login info
        await self.db.execute(
            "UPDATE users SET last_login = %s, failed_login_attempts = 0 WHERE id = %s",
            (datetime.utcnow(), user["id"])
        )
        
        # Audit log
        await self._audit_log(user["id"], "login", True, {"ip_address": ip_address})
        
        return {
            "token": token,
            "expires_in": self.token_expiry.total_seconds(),
            "user_id": str(user["id"])
        }
    
    def _generate_jwt(self, user_id: str, traits: List[str]) -> str:
        """Generate JWT token with user claims."""
        payload = {
            "sub": str(user_id),
            "traits": traits,
            "exp": datetime.utcnow() + self.token_expiry,
            "iat": datetime.utcnow(),
            "jti": secrets.token_hex(16)
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")
    
    async def verify_token(self, token: str) -> Optional[Dict]:
        """Verify and decode JWT token."""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
            # Check if token is blacklisted (if implementing blacklist)
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    def _verify_mfa(self, secret: str, token: str) -> bool:
        """Verify TOTP MFA token."""
        totp = pyotp.TOTP(secret)
        return totp.verify(token, valid_window=1)
    
    def _requires_mfa(self, roles: List[str]) -> bool:
        """Check if roles require MFA."""
        mfa_required_roles = ["admin", "phi_handler"]
        return any(role in mfa_required_roles for role in (roles or []))
    
    async def _handle_failed_login(self, user_id: str, current_attempts: int):
        """Handle failed login attempt."""
        new_attempts = current_attempts + 1
        
        if new_attempts >= self.max_failed_attempts:
            locked_until = datetime.utcnow() + self.lockout_duration
            await self.db.execute(
                "UPDATE users SET failed_login_attempts = %s, locked_until = %s WHERE id = %s",
                (new_attempts, locked_until, user_id)
            )
            await self._audit_log(user_id, "account_locked", True, {"attempts": new_attempts})
        else:
            await self.db.execute(
                "UPDATE users SET failed_login_attempts = %s WHERE id = %s",
                (new_attempts, user_id)
            )
        
        await self._audit_log(user_id, "failed_login", False, {"attempt": new_attempts})
```

### 2. Trait-Based Policy Engine

#### 2.1 Policy Engine Implementation
```python
# core/policy/engine.py
from typing import Dict, List, Set, Tuple
from dataclasses import dataclass
import logging
import json

logger = logging.getLogger(__name__)

@dataclass
class PolicyRule:
    """Represents a security policy rule."""
    name: str
    source_traits: Set[str]
    target_traits: Set[str]
    data_traits: Set[str]
    action: str  # allow, deny, sanitize
    priority: int = 0

class PolicyEngine:
    """Evaluates trait-based security policies."""
    
    def __init__(self):
        self.rules: List[PolicyRule] = []
        self._load_default_rules()
        self.decision_cache = {}  # Cache recent decisions
        
    def _load_default_rules(self):
        """Load default security rules."""
        # PHI handling rules
        self.rules.append(PolicyRule(
            name="phi_protection",
            source_traits={"handles_phi"},
            target_traits={"handles_phi"},
            data_traits={"phi"},
            action="allow",
            priority=100
        ))
        
        self.rules.append(PolicyRule(
            name="phi_block_unauthorized",
            source_traits=set(),
            target_traits=set(),
            data_traits={"phi"},
            action="deny",
            priority=99
        ))
        
        # PII handling rules
        self.rules.append(PolicyRule(
            name="pii_protection",
            source_traits={"handles_pii"},
            target_traits={"handles_pii"},
            data_traits={"pii"},
            action="allow",
            priority=90
        ))
        
        # External service rules
        self.rules.append(PolicyRule(
            name="external_service_restriction",
            source_traits=set(),
            target_traits={"external_service"},
            data_traits={"confidential", "phi", "pii"},
            action="sanitize",
            priority=80
        ))
        
        # Admin access rules
        self.rules.append(PolicyRule(
            name="admin_full_access",
            source_traits={"admin"},
            target_traits=set(),
            data_traits=set(),
            action="allow",
            priority=50
        ))
    
    def evaluate_plugin_interaction(
        self,
        source_plugin: Dict,
        target_plugin: Dict,
        data: Dict
    ) -> Tuple[str, str]:
        """Evaluate if plugin interaction is allowed."""
        source_traits = set(source_plugin.get("traits", []))
        target_traits = set(target_plugin.get("traits", []))
        data_traits = set(data.get("traits", []))
        
        # Check cache
        cache_key = f"{source_plugin['id']}:{target_plugin['id']}:{','.join(sorted(data_traits))}"
        if cache_key in self.decision_cache:
            return self.decision_cache[cache_key]
        
        # Evaluate rules in priority order
        applicable_rules = []
        for rule in sorted(self.rules, key=lambda r: r.priority, reverse=True):
            if self._rule_applies(rule, source_traits, target_traits, data_traits):
                applicable_rules.append(rule)
        
        # Determine final decision
        decision = "deny"  # Default deny
        reason = "no_matching_rule"
        
        for rule in applicable_rules:
            if rule.action in ["allow", "deny", "sanitize"]:
                decision = rule.action
                reason = rule.name
                break
        
        # Audit decision
        self._audit_decision(source_plugin, target_plugin, data, decision, reason)
        
        # Cache decision
        self.decision_cache[cache_key] = (decision, reason)
        
        return decision, reason
    
    def evaluate_user_action(
        self,
        user_traits: List[str],
        action: str,
        resource_traits: List[str]
    ) -> Tuple[bool, str]:
        """Evaluate if user action is allowed."""
        user_traits_set = set(user_traits)
        resource_traits_set = set(resource_traits)
        
        # Check for admin override
        if "admin" in user_traits_set:
            return True, "admin_privilege"
        
        # Check PHI access
        if "phi" in resource_traits_set and "handles_phi" not in user_traits_set:
            return False, "unauthorized_phi_access"
        
        # Check PII access
        if "pii" in resource_traits_set and "handles_pii" not in user_traits_set:
            return False, "unauthorized_pii_access"
        
        # Check specific action permissions
        action_map = {
            "read": ["viewer", "operator", "admin"],
            "write": ["operator", "admin"],
            "delete": ["admin"],
            "configure": ["config_manager", "admin"]
        }
        
        required_traits = action_map.get(action, [])
        if any(trait in user_traits_set for trait in required_traits):
            return True, f"authorized_{action}"
        
        return False, f"unauthorized_{action}"
    
    def evaluate_data_access(
        self,
        consumer_traits: List[str],
        data_traits: List[str]
    ) -> Tuple[str, str]:
        """Evaluate if a consumer with given traits may access data with given traits.
        Returns (decision, reason) where decision is one of: allow, deny, sanitize.
        """
        consumer = set(consumer_traits or [])
        data = set(data_traits or [])
        
        # PHI requires handles_phi
        if "phi" in data and "handles_phi" not in consumer:
            return "deny", "unauthorized_phi_access"
        
        # PII requires handles_pii
        if "pii" in data and "handles_pii" not in consumer:
            return "deny", "unauthorized_pii_access"
        
        # Default allow
        return "allow", "allowed"
    
    def _rule_applies(
        self,
        rule: PolicyRule,
        source_traits: Set[str],
        target_traits: Set[str],
        data_traits: Set[str]
    ) -> bool:
        """Check if a rule applies to the given traits."""
        # If rule specifies traits, they must be present
        if rule.source_traits and not rule.source_traits.issubset(source_traits):
            return False
        if rule.target_traits and not rule.target_traits.issubset(target_traits):
            return False
        if rule.data_traits and not rule.data_traits.intersection(data_traits):
            return False
        return True
    
    def _audit_decision(
        self,
        source: Dict,
        target: Dict,
        data: Dict,
        decision: str,
        reason: str
    ):
        """Audit policy decision."""
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "source": source.get("id"),
            "target": target.get("id"),
            "data_traits": data.get("traits", []),
            "decision": decision,
            "reason": reason
        }
        logger.info(f"Policy decision: {json.dumps(audit_entry)}")
```

### 3. Configuration Service

#### 3.1 Configuration Schema
```sql
-- core/config/schema.sql
CREATE TABLE configurations (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    key VARCHAR(255) NOT NULL,
    value JSONB NOT NULL,
    plugin_id VARCHAR(255),
    environment VARCHAR(50) DEFAULT 'default',
    is_encrypted BOOLEAN DEFAULT FALSE,
    is_sensitive BOOLEAN DEFAULT FALSE,
    version INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_by UUID REFERENCES users(id),
    UNIQUE(key, plugin_id, environment)
);

CREATE TABLE config_history (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_id UUID REFERENCES configurations(id),
    old_value JSONB,
    new_value JSONB,
    changed_by UUID REFERENCES users(id),
    change_reason TEXT,
    changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_configurations_key ON configurations(key);
CREATE INDEX idx_configurations_plugin_id ON configurations(plugin_id);
CREATE INDEX idx_config_history_config_id ON config_history(config_id);
```

#### 3.2 Configuration Service Implementation
```python
# core/config/service.py
from typing import Dict, Any, Optional, List
import json
from cryptography.fernet import Fernet
import os
import logging

logger = logging.getLogger(__name__)

class ConfigurationService:
    """Manages hierarchical configuration with encryption support."""
    
    def __init__(self, db_session, encryption_key: Optional[str] = None):
        self.db = db_session
        self.cipher = Fernet(encryption_key.encode()) if encryption_key else None
        self.cache = {}
        self._load_defaults()
    
    def _load_defaults(self):
        """Load default configuration from file."""
        defaults_file = os.getenv("CONFIG_DEFAULTS_FILE", "config.defaults.json")
        if os.path.exists(defaults_file):
            with open(defaults_file) as f:
                self.defaults = json.load(f)
        else:
            self.defaults = {
                "core": {
                    "jwt_expiry": 900,
                    "max_plugin_retries": 3,
                    "audit_retention_days": 2555,  # 7 years for HIPAA
                    "session_timeout": 1800,
                    "rate_limit": {
                        "requests_per_minute": 60,
                        "burst": 100
                    }
                },
                "security": {
                    "mfa_required_roles": ["admin", "phi_handler"],
                    "password_policy": {
                        "min_length": 12,
                        "require_uppercase": True,
                        "require_lowercase": True,
                        "require_numbers": True,
                        "require_special": True,
                        "history_count": 5
                    }
                }
            }
    
    async def get_config(
        self,
        key: str,
        plugin_id: Optional[str] = None,
        environment: str = "default"
    ) -> Any:
        """Get configuration value with hierarchical override."""
        cache_key = f"{plugin_id or 'core'}:{environment}:{key}"
        
        # Check cache
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # Check database
        result = await self.db.fetchone(
            "SELECT value, is_encrypted FROM configurations WHERE key = %s AND plugin_id = %s AND environment = %s",
            (key, plugin_id, environment)
        )
        
        if result:
            value = result["value"]
            if result["is_encrypted"] and self.cipher:
                value = self._decrypt_value(value)
            self.cache[cache_key] = value
            return value
        
        # Check environment variable override
        env_key = f"{plugin_id or 'CORE'}_{key}".upper().replace(".", "_")
        if env_value := os.getenv(env_key):
            return env_value
        
        # Fall back to defaults
        if plugin_id:
            return self.defaults.get("plugins", {}).get(plugin_id, {}).get(key)
        return self._get_nested_default(key)
    
    async def get_all_config(
        self,
        plugin_id: Optional[str] = None,
        environment: str = "default"
    ) -> Dict[str, Any]:
        """Get all configuration key-values for a plugin (or core) in an environment."""
        result: Dict[str, Any] = {}
        rows = await self.db.fetch(
            "SELECT key, value, is_encrypted FROM configurations WHERE plugin_id = %s AND environment = %s",
            (plugin_id, environment)
        )
        for row in rows:
            value = row["value"]
            if row["is_encrypted"] and self.cipher:
                value = self._decrypt_value(value)
            result[row["key"]] = value
        return result
    
    async def set_config(
        self,
        key: str,
        value: Any,
        plugin_id: Optional[str] = None,
        environment: str = "default",
        is_sensitive: bool = False,
        updated_by: str = None,
        reason: str = None
    ) -> bool:
        """Set configuration value with audit trail."""
        # Get current value for history
        current = await self.db.fetchone(
            "SELECT id, value FROM configurations WHERE key = %s AND plugin_id = %s AND environment = %s",
            (key, plugin_id, environment)
        )
        
        # Encrypt sensitive values
        encrypted = False
        if is_sensitive and self.cipher:
            value = self._encrypt_value(value)
            encrypted = True
        
        if current:
            # Update existing
            await self.db.execute(
                "UPDATE configurations SET value = %s, is_encrypted = %s, is_sensitive = %s, updated_at = CURRENT_TIMESTAMP, updated_by = %s, version = version + 1 WHERE id = %s",
                (json.dumps(value), encrypted, is_sensitive, updated_by, current["id"])
            )
            
            # Add to history
            await self.db.execute(
                "INSERT INTO config_history (config_id, old_value, new_value, changed_by, change_reason) VALUES (%s, %s, %s, %s, %s)",
                (current["id"], current["value"], json.dumps(value), updated_by, reason)
            )
        else:
            # Insert new
            result = await self.db.execute(
                "INSERT INTO configurations (key, value, plugin_id, environment, is_encrypted, is_sensitive, updated_by) VALUES (%s, %s, %s, %s, %s, %s, %s) RETURNING id",
                (key, json.dumps(value), plugin_id, environment, encrypted, is_sensitive, updated_by)
            )
            config_id = result.fetchone()[0]
            
            # Add to history
            await self.db.execute(
                "INSERT INTO config_history (config_id, old_value, new_value, changed_by, change_reason) VALUES (%s, NULL, %s, %s, %s)",
                (config_id, json.dumps(value), updated_by, reason or "initial_configuration")
            )
        
        # Clear cache
        cache_key = f"{plugin_id or 'core'}:{environment}:{key}"
        self.cache.pop(cache_key, None)
        
        # Audit log
        logger.info(f"Configuration updated: {key}", extra={
            "trace_id": updated_by,
            "plugin_id": plugin_id,
            "key": key,
            "sensitive": is_sensitive
        })
        
        return True
    
    def _encrypt_value(self, value: Any) -> str:
        """Encrypt sensitive configuration value."""
        json_value = json.dumps(value)
        return self.cipher.encrypt(json_value.encode()).decode()
    
    def _decrypt_value(self, encrypted: str) -> Any:
        """Decrypt sensitive configuration value."""
        decrypted = self.cipher.decrypt(encrypted.encode()).decode()
        return json.loads(decrypted)
```

### 4. Enhanced Plugin Manager

#### 4.1 Secure Plugin Manager
```python
# core/plugin_manager/manager.py
from typing import Dict, Optional, List
import asyncio
import httpx
import jwt
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class SecurePluginManager:
    """Enhanced plugin manager with security features."""
    
    def __init__(self, registry, policy_engine, config_service, jwt_secret):
        self.registry = registry
        self.policy = policy_engine
        self.config = config_service
        self.jwt_secret = jwt_secret
        self.health_check_interval = 30  # seconds
        self.unhealthy_threshold = 3
        self.plugin_health = {}
        
    async def register_plugin(self, manifest: Dict, auth_token: Optional[str] = None) -> Dict:
        """Register plugin with enhanced security validation."""
        # Validate authentication
        if auth_token:
            if not self._validate_registration_token(auth_token):
                raise HTTPException(status_code=401, detail="Invalid registration token")
        
        # Validate manifest
        validation_errors = self._validate_manifest_security(manifest)
        if validation_errors:
            raise HTTPException(status_code=400, detail=f"Manifest validation failed: {validation_errors}")
        
        # Check dependencies
        missing_deps = await self._check_dependencies(manifest.get("dependencies", []))
        if missing_deps:
            logger.warning(f"Missing dependencies for {manifest['id']}: {missing_deps}")
        
        # Generate plugin-specific JWT
        plugin_token = self._generate_plugin_token(manifest["id"], manifest.get("traits", []))
        
        # Store in registry
        registration = await self.registry.register_plugin(manifest)
        registration["token"] = plugin_token
        
        # Initialize plugin health monitoring
        self.plugin_health[manifest["id"]] = {
            "status": "registered",
            "consecutive_failures": 0,
            "last_check": datetime.utcnow()
        }
        
        # Start health monitoring
        asyncio.create_task(self._monitor_plugin_health(manifest["id"]))
        
        logger.info(f"Plugin registered securely: {manifest['id']}", extra={
            "trace_id": manifest["id"],
            "traits": manifest.get("traits", [])
        })
        
        return registration
    
    def _validate_manifest_security(self, manifest: Dict) -> List[str]:
        """Validate security aspects of plugin manifest."""
        errors = []
        
        # Check required security fields
        if "security" not in manifest:
            errors.append("Missing security section")
        else:
            security = manifest["security"]
            if not security.get("authentication_required", True):
                errors.append("Authentication must be required")
            
            data_classes = security.get("data_classification", [])
            if "phi" in data_classes and "handles_phi" not in manifest.get("traits", []):
                errors.append("Plugin handling PHI must declare handles_phi trait")
            
            if "pii" in data_classes and "handles_pii" not in manifest.get("traits", []):
                errors.append("Plugin handling PII must declare handles_pii trait")
        
        # Check compliance section
        if "compliance" not in manifest:
            errors.append("Missing compliance section")
        else:
            compliance = manifest["compliance"]
            if "audit_level" not in compliance:
                errors.append("Audit level must be specified")
            
            if manifest.get("traits", []) and "handles_phi" in manifest["traits"]:
                if not compliance.get("hipaa_controls"):
                    errors.append("HIPAA controls must be specified for PHI handling plugins")
        
        # Validate allowed domains
        if allowed_domains := manifest.get("allowed_domains"):
            for domain in allowed_domains:
                if not self._is_safe_domain(domain):
                    errors.append(f"Unsafe domain: {domain}")
        
        return errors
    
    def _generate_plugin_token(self, plugin_id: str, traits: List[str]) -> str:
        """Generate JWT token for plugin authentication."""
        payload = {
            "plugin_id": plugin_id,
            "type": "plugin",
            "traits": traits,
            "iat": datetime.utcnow(),
            "exp": datetime.utcnow() + timedelta(days=30)
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")
    
    async def _monitor_plugin_health(self, plugin_id: str):
        """Monitor plugin health status."""
        while plugin_id in self.plugin_health:
            try:
                plugin_info = self.registry.plugins.get(plugin_id)
                if not plugin_info:
                    break
                
                # Call plugin health endpoint
                health_endpoint = plugin_info["manifest"].get("endpoints", {}).get("health")
                if health_endpoint:
                    async with httpx.AsyncClient() as client:
                        response = await client.get(
                            f"http://{plugin_id}:8080{health_endpoint}",
                            timeout=5.0
                        )
                        
                        if response.status_code == 200:
                            self.plugin_health[plugin_id]["status"] = "healthy"
                            self.plugin_health[plugin_id]["consecutive_failures"] = 0
                        else:
                            await self._handle_unhealthy_plugin(plugin_id)
                else:
                    # No health endpoint, assume healthy if recently registered
                    pass
                
            except Exception as e:
                logger.error(f"Health check failed for {plugin_id}: {e}")
                await self._handle_unhealthy_plugin(plugin_id)
            
            self.plugin_health[plugin_id]["last_check"] = datetime.utcnow()
            await asyncio.sleep(self.health_check_interval)
    
    async def _handle_unhealthy_plugin(self, plugin_id: str):
        """Handle unhealthy plugin detection."""
        self.plugin_health[plugin_id]["consecutive_failures"] += 1
        
        if self.plugin_health[plugin_id]["consecutive_failures"] >= self.unhealthy_threshold:
            self.plugin_health[plugin_id]["status"] = "unhealthy"
            
            # Disable plugin if critical
            plugin_info = self.registry.plugins.get(plugin_id)
            if plugin_info and "critical" in plugin_info["manifest"].get("traits", []):
                await self.disable_plugin(plugin_id, reason="health_check_failure")
                
                # Send alert
                logger.critical(f"Critical plugin {plugin_id} disabled due to health failures")
    
    async def disable_plugin(self, plugin_id: str, reason: str = None):
        """Disable a plugin."""
        if plugin_id in self.registry.plugins:
            self.registry.plugins[plugin_id]["status"] = "disabled"
            self.registry.plugins[plugin_id]["disabled_at"] = datetime.utcnow().isoformat()
            self.registry.plugins[plugin_id]["disabled_reason"] = reason
            
            logger.warning(f"Plugin disabled: {plugin_id}", extra={
                "trace_id": plugin_id,
                "reason": reason
            })
            
            # Notify dependent plugins
            await self._notify_dependents(plugin_id, "disabled")
    
    def _is_safe_domain(self, domain: str) -> bool:
        """Check if domain is safe for proxy access."""
        blocked_domains = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "169.254",  # Link-local
            "10.",      # Private ranges
            "172.16",
            "192.168"
        ]
        return not any(domain.startswith(blocked) for blocked in blocked_domains)
```

### 5. Admin API Implementation

#### 5.1 Admin API Routes
```python
# core/api/admin.py
from fastapi import APIRouter, Depends, HTTPException, Query
from typing import List, Optional
import logging

router = APIRouter(prefix="/admin", tags=["admin"])
logger = logging.getLogger(__name__)

def mask_sensitive_config(config):
    """Mask sensitive values in config response (best-effort example)."""
    sensitive_keys = {"secret", "password", "token", "key"}
    def _mask(obj):
        if isinstance(obj, dict):
            masked = {}
            for k, v in obj.items():
                if any(s in k.lower() for s in sensitive_keys):
                    masked[k] = "***"
                else:
                    masked[k] = _mask(v)
            return masked
        if isinstance(obj, list):
            return [_mask(v) for v in obj]
        if isinstance(obj, str):
            return obj if len(obj) <= 4 else f"{obj[:2]}***{obj[-2:]}"
        return obj
    return _mask(config)

@router.get("/plugins")
@require_auth(traits=["admin", "operator"])
async def list_plugins(
    status: Optional[str] = Query(None, description="Filter by status"),
    current_user: Dict = Depends(get_current_user)
):
    """List all registered plugins with their status."""
    plugins = await plugin_manager.list_plugins(status=status)
    
    # Filter based on user permissions
    if "admin" not in current_user["traits"]:
        # Non-admins don't see sensitive plugin details
        plugins = [{k: v for k, v in p.items() if k not in ["token", "config"]} for p in plugins]
    
    return {
        "plugins": plugins,
        "total": len(plugins)
    }

@router.post("/plugins/{plugin_id}/enable")
@require_auth(traits=["admin", "plugin_manager"])
@audit_log("plugin_enabled")
async def enable_plugin(
    plugin_id: str,
    current_user: Dict = Depends(get_current_user)
):
    """Enable a disabled plugin."""
    success = await plugin_manager.enable_plugin(plugin_id)
    if not success:
        raise HTTPException(status_code=404, detail="Plugin not found")
    
    return {"status": "enabled", "plugin_id": plugin_id}

@router.post("/plugins/{plugin_id}/disable")
@require_auth(traits=["admin", "plugin_manager"])
@audit_log("plugin_disabled")
async def disable_plugin(
    plugin_id: str,
    reason: Optional[str] = None,
    current_user: Dict = Depends(get_current_user)
):
    """Disable a plugin."""
    await plugin_manager.disable_plugin(plugin_id, reason=reason)
    return {"status": "disabled", "plugin_id": plugin_id}

@router.get("/users")
@require_auth(traits=["admin", "user_manager"])
async def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    current_user: Dict = Depends(get_current_user)
):
    """List system users."""
    users = await identity_service.list_users(
        page=page,
        page_size=page_size,
        exclude_sensitive="admin" not in current_user["traits"]
    )
    return users

@router.post("/users")
@require_auth(traits=["admin"])
@audit_log("user_created")
async def create_user(
    user_data: UserCreateRequest,
    current_user: Dict = Depends(get_current_user)
):
    """Create a new user."""
    user = await identity_service.create_user(
        username=user_data.username,
        email=user_data.email,
        password=user_data.password,
        roles=user_data.roles,
        created_by=current_user["sub"]
    )
    return user

@router.get("/config")
@require_auth(traits=["admin", "config_manager"])
async def get_configuration(
    plugin_id: Optional[str] = None,
    current_user: Dict = Depends(get_current_user)
):
    """Get configuration settings."""
    config = await config_service.get_all_config(plugin_id=plugin_id)
    
    # Mask sensitive values for non-admins
    if "admin" not in current_user["traits"]:
        config = mask_sensitive_config(config)
    
    return config

@router.put("/config")
@require_auth(traits=["admin", "config_manager"])
@audit_log("config_updated")
async def update_configuration(
    config_update: ConfigUpdateRequest,
    current_user: Dict = Depends(get_current_user)
):
    """Update configuration settings."""
    success = await config_service.set_config(
        key=config_update.key,
        value=config_update.value,
        plugin_id=config_update.plugin_id,
        is_sensitive=config_update.is_sensitive,
        updated_by=current_user["sub"],
        reason=config_update.reason
    )
    
    if not success:
        raise HTTPException(status_code=500, detail="Failed to update configuration")
    
    return {"status": "updated", "key": config_update.key}

@router.get("/audit")
@require_auth(traits=["admin", "audit_viewer"])
async def get_audit_logs(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    event_type: Optional[str] = None,
    page: int = Query(1, ge=1),
    current_user: Dict = Depends(get_current_user)
):
    """Retrieve audit logs."""
    logs = await audit_service.get_logs(
        start_date=start_date,
        end_date=end_date,
        event_type=event_type,
        page=page,
        page_size=50
    )
    return logs

@router.get("/traits")
@require_auth
async def list_traits(current_user: Dict = Depends(get_current_user)):
    """List all known traits and their descriptions."""
    return {
        "traits": [
            {"name": "admin", "description": "Full system administration"},
            {"name": "handles_phi", "description": "Can process Protected Health Information"},
            {"name": "handles_pii", "description": "Can process Personally Identifiable Information"},
            {"name": "external_service", "description": "Connects to external services"},
            {"name": "audit_required", "description": "All actions must be audited"},
            {"name": "config_manager", "description": "Can modify system configuration"},
            {"name": "plugin_manager", "description": "Can manage plugins"},
            {"name": "viewer", "description": "Read-only access"}
        ]
    }
```

#### 5.2 Admin Console UI Parity (Phase 2)
- Map Identity, Config, and Plugin management endpoints to Admin Console views.
- Ensure trait‑aware rendering (admin, config_manager, plugin_manager) is enforced both server and client side.
- Provide `/admin/user/traits` and `/admin/ui-config` for UI feature flags and trait discovery.
- In development, allow `bootstrap_admin_only` API key to access Admin Console without terminal steps (`DEV_MODE=true`).


### 6. Update Example Plugins

#### 6.1 Enhanced User Management Plugin
```python
# plugins/user_management/main.py
import os
import httpx
from fastapi import FastAPI, Header, HTTPException
import logging

app = FastAPI(title="User Management Plugin")
logger = logging.getLogger(__name__)

CORE_URL = os.getenv("CORE_URL", "http://vivified-core:8000")
PLUGIN_TOKEN = None

@app.on_event("startup")
async def startup():
    """Initialize plugin and register with core."""
    global PLUGIN_TOKEN
    
    # Register with core
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{CORE_URL}/plugins/register",
            json=MANIFEST,
            headers={"Authorization": f"Bearer {os.getenv('REGISTRATION_TOKEN', '')}"}
        )
        
        if response.status_code == 200:
            data = response.json()
            PLUGIN_TOKEN = data["token"]
            logger.info("Successfully registered with core")
            
            # Fetch configuration
            await fetch_configuration()
        else:
            logger.error(f"Registration failed: {response.text}")
            raise RuntimeError("Failed to register with core")

async def fetch_configuration():
    """Fetch plugin configuration from core."""
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{CORE_URL}/config/user-management",
            headers={"Authorization": f"Bearer {PLUGIN_TOKEN}"}
        )
        
        if response.status_code == 200:
            config = response.json()
            # Apply configuration
            logger.info(f"Configuration loaded: {config}")

@app.post("/api/users/extended")
async def create_extended_profile(
    user_id: str,
    profile_data: Dict,
    authorization: str = Header(None)
):
    """Create extended user profile."""
    # Verify caller authorization
    if not await verify_caller_auth(authorization):
        raise HTTPException(status_code=401, detail="Unauthorized")
    
    # Check if profile contains PII
    if contains_pii(profile_data):
        # Ensure caller has handles_pii trait
        caller_traits = await get_caller_traits(authorization)
        if "handles_pii" not in caller_traits:
            raise HTTPException(status_code=403, detail="Caller not authorized for PII")
    
    # Store extended profile (implementation depends on storage choice)
    # ...
    
    # Emit event
    await emit_event("UserProfileUpdated", {
        "user_id": user_id,
        "updated_fields": list(profile_data.keys()),
        "traits": ["pii"] if contains_pii(profile_data) else []
    })
    
    return {"status": "created", "user_id": user_id}
```

## Validation Checklist

### Phase 2 Completion Criteria
- [ ] Identity service operational with JWT authentication
- [ ] User creation and login working
- [ ] MFA implementation for sensitive roles
- [ ] Account lockout after failed attempts
- [ ] Policy engine evaluating trait-based rules
- [ ] PHI/PII protection rules enforced
- [ ] Configuration service with hierarchical overrides
- [ ] Sensitive config values encrypted
- [ ] Plugin authentication tokens issued
- [ ] Plugin health monitoring active
- [ ] Admin APIs secured with role-based access
- [ ] Audit logging for all sensitive operations
- [ ] Example plugins using core services
- [ ] Database schema migrations applied
- [ ] All tests passing with >80% coverage

## Security Validation
- [ ] No passwords stored in plain text
- [ ] JWT tokens expire after 15 minutes
- [ ] Failed login attempts tracked and limited
- [ ] MFA required for admin and PHI handlers
- [ ] All admin endpoints require authentication
- [ ] Audit trail complete for user actions
- [ ] Configuration changes logged with user ID
- [ ] Plugin tokens unique and cryptographically secure

## Next Steps
Proceed to Runbook 03 for implementing inter-plugin communication (Event Bus, RPC Gateway, and Proxy Service).
