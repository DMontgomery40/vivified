# User Management Plugin System - Finally Real Users!

## Executive Summary

Faxbot evolves from **API key-only authentication** to **full user management** while maintaining complete backward compatibility. User management is implemented as a **replaceable plugin**, allowing customers to integrate their existing identity systems (LDAP, SAML, weird ERPs) while preserving all core security guarantees.

**Revolutionary Aspect**: After 2+ years of API key-only operation, we finally have real users, groups, and sessions - but as a plugin that customers can completely replace.

## Current State Analysis

### What We Have Today
```python
# Current auth.py - API key only
class APIKey(Base):
    id = Column(String(40), primary_key=True)
    key_id = Column(String(32), unique=True)
    key_hash = Column(String(200))
    scopes = Column(String(200))  # Simple scope strings
    name = Column(String(100))    # Optional name
    owner = Column(String(100))   # Optional owner (not a real user!)

def verify_db_key(x_api_key: str) -> Optional[Dict[str, Any]]:
    # Returns basic info dict, not a real user object
    return {"key_id": "abc", "scopes": ["fax:send"], "name": "Test Key"}
```

### Problems with Current System
1. **No Real Users**: Only API keys with optional "owner" strings
2. **No Sessions**: Every request requires API key
3. **No Groups**: Cannot organize users or delegate permissions
4. **No Hierarchy**: All API keys are equal, no administrative structure
5. **No Integration**: Cannot connect to existing identity systems
6. **Limited Scopes**: Simple string-based permissions

## User Management Plugin Architecture

### Core Plugin Interface
```python
# api/app/plugins/identity/base.py
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
from datetime import datetime

class IdentityProvider(Plugin):
    """Base interface for user management plugins"""

    @abstractmethod
    def authenticate(self, credentials: Dict[str, Any]) -> Optional['AuthResult']:
        """Authenticate user with credentials"""
        pass

    @abstractmethod
    def get_user(self, user_id: str) -> Optional['User']:
        """Get user by ID"""
        pass

    @abstractmethod
    def get_user_by_email(self, email: str) -> Optional['User']:
        """Get user by email"""
        pass

    @abstractmethod
    def get_user_groups(self, user_id: str) -> List['Group']:
        """Get all groups user belongs to"""
        pass

    @abstractmethod
    def get_user_permissions(self, user_id: str) -> List[str]:
        """Get effective permissions for user"""
        pass

    @abstractmethod
    def create_session(self, user_id: str, metadata: Dict) -> 'Session':
        """Create authenticated session"""
        pass

    @abstractmethod
    def validate_session(self, session_token: str) -> Optional['Session']:
        """Validate existing session"""
        pass

    @abstractmethod
    def revoke_session(self, session_token: str) -> bool:
        """Revoke session"""
        pass

    # Administrative operations (optional)
    def create_user(self, user_data: Dict) -> Optional['User']:
        """Create new user (if supported)"""
        return None

    def update_user(self, user_id: str, updates: Dict) -> bool:
        """Update user (if supported)"""
        return False

    def delete_user(self, user_id: str) -> bool:
        """Delete user (if supported)"""
        return False

    # Trait integration
    @abstractmethod
    def get_user_traits(self, user_id: str) -> List[str]:
        """Get user's current traits"""
        pass

    @abstractmethod
    def set_user_traits(self, user_id: str, traits: List[str]) -> bool:
        """Set user's traits (if supported)"""
        pass
```

### Canonical User Models
```python
# api/app/canonical/identity.py
from dataclasses import dataclass
from typing import List, Dict, Optional, Any
from datetime import datetime

@dataclass
class CanonicalUser:
    """Universal user representation across all identity providers"""
    id: str
    username: str
    email: Optional[str]
    display_name: str
    traits: List[str]
    groups: List[str]
    permissions: List[str]
    metadata: Dict[str, Any]
    created_at: datetime
    last_login: Optional[datetime]
    active: bool

    # Core integration fields
    compliance_mode: str  # 'hipaa', 'standard'
    ui_preferences: Dict[str, Any]
    session_preferences: Dict[str, Any]

@dataclass
class CanonicalGroup:
    """Universal group representation"""
    id: str
    name: str
    description: str
    traits: List[str]
    permissions: List[str]
    members: List[str]  # User IDs
    parent_groups: List[str]
    metadata: Dict[str, Any]

@dataclass
class CanonicalSession:
    """Universal session representation"""
    token: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    last_activity: datetime
    ip_address: str
    user_agent: str
    traits: List[str]  # Computed from user + context
    permissions: List[str]  # Effective permissions
    metadata: Dict[str, Any]

@dataclass
class AuthResult:
    """Result of authentication attempt"""
    success: bool
    user: Optional[CanonicalUser]
    session: Optional[CanonicalSession]
    error: Optional[str]
    requires_mfa: bool = False
    mfa_methods: List[str] = None
    audit_data: Dict[str, Any] = None
```

## Default Implementation - SQLAlchemy Plugin

### Enhanced Database Schema
```python
# api/app/plugins/identity/builtin/models.py
class User(Base):
    """Enhanced user model - replaces API key-only system"""
    __tablename__ = "users"

    # Core identity
    id = Column(String(40), primary_key=True)
    username = Column(String(100), unique=True, nullable=False)
    email = Column(String(255), unique=True, nullable=True)
    display_name = Column(String(200), nullable=False)

    # Authentication
    password_hash = Column(String(500), nullable=True)  # Nullable for SSO users
    mfa_enabled = Column(Boolean, default=False)
    mfa_secret = Column(String(100), nullable=True)

    # Status
    active = Column(Boolean, default=True)
    email_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    last_activity = Column(DateTime, nullable=True)

    # Relationships
    group_memberships = relationship("UserGroupMembership", back_populates="user")
    sessions = relationship("Session", back_populates="user")
    api_keys = relationship("APIKey", back_populates="user")  # Enhanced API keys

class Group(Base):
    """User groups for organization and permission management"""
    __tablename__ = "groups"

    id = Column(String(40), primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    # Hierarchy support
    parent_group_id = Column(String(40), ForeignKey("groups.id"), nullable=True)
    parent = relationship("Group", remote_side=[id])

    # Relationships
    memberships = relationship("UserGroupMembership", back_populates="group")
    permissions = relationship("GroupPermission", back_populates="group")

class UserGroupMembership(Base):
    """Many-to-many relationship between users and groups"""
    __tablename__ = "user_group_memberships"

    id = Column(String(40), primary_key=True)
    user_id = Column(String(40), ForeignKey("users.id"), nullable=False)
    group_id = Column(String(40), ForeignKey("groups.id"), nullable=False)
    added_by = Column(String(40), ForeignKey("users.id"), nullable=True)
    added_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="group_memberships")
    group = relationship("Group", back_populates="memberships")

class Session(Base):
    """User sessions for web/API access"""
    __tablename__ = "sessions"

    token = Column(String(128), primary_key=True)
    user_id = Column(String(40), ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=datetime.utcnow)

    # Security tracking
    ip_address = Column(String(45), nullable=True)  # IPv6 compatible
    user_agent = Column(Text, nullable=True)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)

    # Relationships
    user = relationship("User", back_populates="sessions")

class Permission(Base):
    """Available permissions in the system"""
    __tablename__ = "permissions"

    id = Column(String(40), primary_key=True)
    name = Column(String(100), unique=True, nullable=False)
    description = Column(Text, nullable=True)
    category = Column(String(50), nullable=True)  # 'fax', 'email', 'admin'
    scope_pattern = Column(String(200), nullable=True)  # For backward compatibility

class GroupPermission(Base):
    """Permissions assigned to groups"""
    __tablename__ = "group_permissions"

    id = Column(String(40), primary_key=True)
    group_id = Column(String(40), ForeignKey("groups.id"), nullable=False)
    permission_id = Column(String(40), ForeignKey("permissions.id"), nullable=False)
    granted_by = Column(String(40), ForeignKey("users.id"), nullable=True)
    granted_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    group = relationship("Group", back_populates="permissions")
    permission = relationship("Permission")

# Enhanced API Key - now belongs to users
class APIKey(Base):
    """API keys now belong to real users"""
    __tablename__ = "api_keys"

    # Existing fields
    id = Column(String(40), primary_key=True)
    key_id = Column(String(32), unique=True, nullable=False)
    key_hash = Column(String(200), nullable=False)
    name = Column(String(100), nullable=True)

    # New user relationship
    user_id = Column(String(40), ForeignKey("users.id"), nullable=False)
    user = relationship("User", back_populates="api_keys")

    # Enhanced permissions
    permissions = Column(Text, nullable=True)  # JSON array
    traits = Column(Text, nullable=True)       # JSON array from user + overrides

    # Lifecycle
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
```

### Built-in Identity Provider Implementation
```python
# api/app/plugins/identity/builtin/provider.py
class BuiltinIdentityProvider(IdentityProvider):
    """Default SQLAlchemy-based identity provider"""

    def authenticate(self, credentials: Dict[str, Any]) -> Optional[AuthResult]:
        """Support username/password and API key authentication"""
        auth_type = credentials.get('type', 'password')

        if auth_type == 'password':
            return self._authenticate_password(credentials)
        elif auth_type == 'api_key':
            return self._authenticate_api_key(credentials)
        elif auth_type == 'session':
            return self._authenticate_session(credentials)
        else:
            return AuthResult(success=False, error="Unknown auth type")

    def _authenticate_password(self, credentials: Dict) -> AuthResult:
        """Traditional username/password authentication"""
        username = credentials.get('username')
        password = credentials.get('password')

        with SessionLocal() as db:
            user = db.query(User).filter(
                User.username == username,
                User.active == True
            ).first()

            if not user or not self._verify_password(password, user.password_hash):
                audit_event('authentication_failed', username=username)
                return AuthResult(success=False, error="Invalid credentials")

            # Check if MFA required
            if user.mfa_enabled:
                mfa_code = credentials.get('mfa_code')
                if not mfa_code or not self._verify_mfa(user, mfa_code):
                    return AuthResult(
                        success=False,
                        requires_mfa=True,
                        mfa_methods=['totp'],
                        error="MFA required"
                    )

            # Create session
            session = self.create_session(user.id, {
                'ip_address': credentials.get('ip_address'),
                'user_agent': credentials.get('user_agent')
            })

            # Update last login
            user.last_login = datetime.utcnow()
            db.commit()

            canonical_user = self._to_canonical_user(user)
            audit_event('authentication_success', user_id=user.id)

            return AuthResult(
                success=True,
                user=canonical_user,
                session=session
            )

    def _authenticate_api_key(self, credentials: Dict) -> AuthResult:
        """API key authentication - backward compatible"""
        api_key = credentials.get('api_key')
        key_id, secret = parse_header_token(api_key)

        if not key_id or not secret:
            return AuthResult(success=False, error="Invalid API key format")

        with SessionLocal() as db:
            key_record = db.query(APIKey).filter(
                APIKey.key_id == key_id,
                APIKey.revoked_at.is_(None)
            ).first()

            if not key_record or not verify_secret(secret, key_record.key_hash):
                audit_event('api_key_authentication_failed', key_id=key_id)
                return AuthResult(success=False, error="Invalid API key")

            # Check expiration
            if key_record.expires_at and key_record.expires_at < datetime.utcnow():
                return AuthResult(success=False, error="API key expired")

            # Get associated user
            user = key_record.user
            if not user.active:
                return AuthResult(success=False, error="User account disabled")

            # Update last used
            key_record.last_used_at = datetime.utcnow()
            db.commit()

            canonical_user = self._to_canonical_user(user)
            audit_event('api_key_authentication_success',
                       key_id=key_id, user_id=user.id)

            return AuthResult(success=True, user=canonical_user)

    def get_user_traits(self, user_id: str) -> List[str]:
        """Get user traits from database and compute dynamic traits"""
        with SessionLocal() as db:
            # Base traits from user_traits table
            base_traits = db.query(UserTrait.trait_name).filter(
                UserTrait.user_id == user_id,
                or_(UserTrait.expires_at.is_(None),
                    UserTrait.expires_at > datetime.utcnow())
            ).all()

            traits = [t.trait_name for t in base_traits]

            # Add computed traits based on group membership
            user = db.query(User).filter(User.id == user_id).first()
            if user:
                for membership in user.group_memberships:
                    group_traits = db.query(GroupTrait.trait_name).filter(
                        GroupTrait.group_id == membership.group_id
                    ).all()
                    traits.extend([t.trait_name for t in group_traits])

            # Add contextual traits
            if self._is_business_hours():
                traits.append('business_hours')

            return list(set(traits))  # Remove duplicates

    def _to_canonical_user(self, user: User) -> CanonicalUser:
        """Convert database user to canonical format"""
        return CanonicalUser(
            id=user.id,
            username=user.username,
            email=user.email,
            display_name=user.display_name,
            traits=self.get_user_traits(user.id),
            groups=[m.group.name for m in user.group_memberships],
            permissions=self.get_user_permissions(user.id),
            metadata={
                'mfa_enabled': user.mfa_enabled,
                'email_verified': user.email_verified,
                'account_type': 'builtin'
            },
            created_at=user.created_at,
            last_login=user.last_login,
            active=user.active,
            compliance_mode='hipaa' if 'hipaa_compliant' in self.get_user_traits(user.id) else 'standard',
            ui_preferences={},
            session_preferences={}
        )
```

## Custom Identity Provider Examples

### LDAP/Active Directory Plugin
```python
# api/app/plugins/identity/ldap/provider.py
class LDAPIdentityProvider(IdentityProvider):
    """LDAP/Active Directory integration"""

    def __init__(self):
        self.ldap_server = os.getenv('LDAP_SERVER')
        self.ldap_base_dn = os.getenv('LDAP_BASE_DN')
        self.ldap_bind_user = os.getenv('LDAP_BIND_USER')
        self.ldap_bind_password = os.getenv('LDAP_BIND_PASSWORD')

    def authenticate(self, credentials: Dict[str, Any]) -> Optional[AuthResult]:
        """Authenticate against LDAP"""
        username = credentials.get('username')
        password = credentials.get('password')

        try:
            # LDAP connection and authentication
            server = Server(self.ldap_server)
            conn = Connection(
                server,
                user=f"{username}@{self.ldap_domain}",
                password=password,
                auto_bind=True
            )

            # Search for user details
            conn.search(
                self.ldap_base_dn,
                f'(&(objectClass=user)(sAMAccountName={username}))',
                attributes=['cn', 'mail', 'memberOf', 'department']
            )

            if not conn.entries:
                return AuthResult(success=False, error="User not found")

            user_entry = conn.entries[0]

            # Map LDAP attributes to canonical user
            canonical_user = CanonicalUser(
                id=f"ldap:{username}",
                username=username,
                email=str(user_entry.mail) if user_entry.mail else None,
                display_name=str(user_entry.cn),
                traits=self._map_ldap_groups_to_traits(user_entry.memberOf),
                groups=[str(group) for group in user_entry.memberOf],
                permissions=self._compute_permissions_from_groups(user_entry.memberOf),
                metadata={
                    'department': str(user_entry.department),
                    'source': 'ldap',
                    'dn': str(user_entry.entry_dn)
                },
                created_at=datetime.utcnow(),  # We don't know actual creation date
                last_login=datetime.utcnow(),
                active=True,
                compliance_mode=self._determine_compliance_mode(user_entry.memberOf),
                ui_preferences={},
                session_preferences={}
            )

            audit_event('ldap_authentication_success',
                       username=username, dn=str(user_entry.entry_dn))

            return AuthResult(success=True, user=canonical_user)

        except Exception as e:
            audit_event('ldap_authentication_failed',
                       username=username, error=str(e))
            return AuthResult(success=False, error="Authentication failed")

    def _map_ldap_groups_to_traits(self, ldap_groups: List[str]) -> List[str]:
        """Map LDAP group membership to Faxbot traits"""
        trait_mapping = {
            'CN=Medical_Staff,OU=Groups,DC=hospital,DC=com': ['hipaa_compliant', 'fax_capable', 'phi_authorized'],
            'CN=Marketing,OU=Groups,DC=hospital,DC=com': ['non_hipaa', 'email_capable'],
            'CN=IT_Admins,OU=Groups,DC=hospital,DC=com': ['admin_capable', 'hipaa_compliant'],
            'CN=Doctors,OU=Groups,DC=hospital,DC=com': ['hipaa_compliant', 'fax_capable', 'phi_authorized', 'prescriber']
        }

        traits = []
        for group in ldap_groups:
            group_str = str(group)
            if group_str in trait_mapping:
                traits.extend(trait_mapping[group_str])

        return list(set(traits))
```

### Customer's Weird ERP Plugin
```python
# Customer provides this plugin
class WeirdERPIdentityProvider(IdentityProvider):
    """Customer's weird ERP system integration"""

    def authenticate(self, credentials: Dict[str, Any]) -> Optional[AuthResult]:
        """Integrate with customer's bizarre authentication system"""
        username = credentials.get('username')
        password = credentials.get('password')

        # They have some weird SOAP API or whatever
        try:
            erp_client = WeirdERPClient(
                endpoint=self.erp_endpoint,
                api_key=self.erp_api_key
            )

            # Their authentication method (ROT13 password?!)
            auth_result = erp_client.authenticate_user(
                user_id=username,
                password_hash=self._rot13(password),  # They do weird stuff
                system_code='FAXBOT_INTEGRATION'
            )

            if not auth_result.success:
                return AuthResult(success=False, error="ERP authentication failed")

            # Map their user data to our canonical format
            erp_user = auth_result.user_data
            canonical_user = CanonicalUser(
                id=f"erp:{erp_user.employee_id}",
                username=erp_user.login_name,
                email=erp_user.work_email,
                display_name=f"{erp_user.first_name} {erp_user.last_name}",
                traits=self._map_erp_roles_to_traits(erp_user.roles),
                groups=erp_user.departments,
                permissions=self._map_erp_permissions(erp_user.permissions),
                metadata={
                    'employee_id': erp_user.employee_id,
                    'department': erp_user.primary_department,
                    'hire_date': erp_user.hire_date,
                    'source': 'weird_erp'
                },
                created_at=erp_user.hire_date,
                last_login=datetime.utcnow(),
                active=erp_user.employment_status == 'ACTIVE',
                compliance_mode='hipaa' if 'MEDICAL' in erp_user.roles else 'standard',
                ui_preferences=erp_user.ui_settings or {},
                session_preferences={}
            )

            return AuthResult(success=True, user=canonical_user)

        except Exception as e:
            return AuthResult(success=False, error=f"ERP integration error: {e}")

    def _map_erp_roles_to_traits(self, erp_roles: List[str]) -> List[str]:
        """Map their weird role system to our traits"""
        trait_mapping = {
            'DOCTOR_PRIMARY': ['hipaa_compliant', 'fax_capable', 'phi_authorized', 'prescriber'],
            'NURSE_RN': ['hipaa_compliant', 'fax_capable', 'phi_authorized'],
            'ADMIN_IT': ['admin_capable', 'hipaa_compliant'],
            'MARKETING_STAFF': ['non_hipaa', 'email_capable'],
            'BILLING_CLERK': ['hipaa_compliant', 'phi_authorized']  # They can see PHI for billing
        }

        traits = []
        for role in erp_roles:
            if role in trait_mapping:
                traits.extend(trait_mapping[role])

        return list(set(traits))
```

## Core Integration Points

### Enhanced Authentication Middleware
```python
# api/app/middleware/auth.py
class EnhancedAuthMiddleware:
    """Enhanced authentication supporting both users and API keys"""

    def __init__(self, identity_provider: IdentityProvider):
        self.identity_provider = identity_provider

    async def __call__(self, request: Request, call_next):
        # Try different authentication methods in order
        auth_result = None

        # 1. Session-based authentication (cookies)
        session_token = request.cookies.get('session_token')
        if session_token:
            auth_result = self.identity_provider.authenticate({
                'type': 'session',
                'session_token': session_token
            })

        # 2. API key authentication (headers)
        if not auth_result or not auth_result.success:
            api_key = request.headers.get('X-API-Key')
            if api_key:
                auth_result = self.identity_provider.authenticate({
                    'type': 'api_key',
                    'api_key': api_key
                })

        # 3. Basic authentication (for compatibility)
        if not auth_result or not auth_result.success:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Basic '):
                username, password = parse_basic_auth(auth_header)
                auth_result = self.identity_provider.authenticate({
                    'type': 'password',
                    'username': username,
                    'password': password,
                    'ip_address': str(request.client.host),
                    'user_agent': request.headers.get('User-Agent')
                })

        if auth_result and auth_result.success:
            # Add user context to request
            request.state.user = auth_result.user
            request.state.session = auth_result.session
            request.state.auth_method = 'session' if auth_result.session else 'api_key'

            # Update last activity
            if auth_result.session:
                self.identity_provider.update_session_activity(
                    auth_result.session.token,
                    datetime.utcnow()
                )

        response = await call_next(request)

        # Add security headers
        if hasattr(request.state, 'user'):
            response.headers['X-User-ID'] = request.state.user.id
            if request.state.user.traits:
                response.headers['X-User-Traits'] = ','.join(request.state.user.traits)

        return response
```

### Trait-Aware Authorization
```python
# api/app/middleware/authorization.py
def require_user_traits(*required_traits: str):
    """Decorator to require specific user traits"""
    def decorator(func):
        def wrapper(request: Request, *args, **kwargs):
            if not hasattr(request.state, 'user'):
                raise HTTPException(401, "Authentication required")

            user = request.state.user
            missing_traits = [
                trait for trait in required_traits
                if not user.has_trait(trait)
            ]

            if missing_traits:
                audit_event('authorization_failed',
                           user_id=user.id,
                           required_traits=required_traits,
                           missing_traits=missing_traits)
                raise HTTPException(
                    403,
                    f"Missing required traits: {', '.join(missing_traits)}"
                )

            return func(request, *args, **kwargs)
        return wrapper
    return decorator

# Usage in endpoints
@require_user_traits('fax_capable')
def send_fax(request: Request):
    user = request.state.user
    # User is guaranteed to have 'fax_capable' trait
    pass

@require_user_traits('hipaa_compliant', 'phi_authorized')
def access_phi_data(request: Request):
    user = request.state.user
    # User can access PHI data
    pass

@require_user_traits('email_capable')
@require_user_traits('admin_capable')  # Can stack decorators
def configure_email_gateway(request: Request):
    user = request.state.user
    # User can configure email AND has admin privileges
    pass
```

## Migration Strategy

### Phase 1: Parallel Systems (Week 1-2)
```python
# Run both systems simultaneously
class MigrationAuthMiddleware:
    def __init__(self):
        self.legacy_auth = LegacyAPIKeyAuth()  # Current system
        self.new_auth = EnhancedAuthMiddleware(builtin_identity_provider)

    async def __call__(self, request: Request, call_next):
        # Try new system first
        try:
            return await self.new_auth(request, call_next)
        except:
            # Fall back to legacy system
            return await self.legacy_auth(request, call_next)
```

### Phase 2: API Key Migration (Week 3-4)
```python
# Migrate existing API keys to be owned by users
def migrate_api_keys():
    """Create default users for existing API keys"""
    with SessionLocal() as db:
        # Create default admin user
        admin_user = User(
            id=generate_uuid(),
            username='admin',
            email=os.getenv('ADMIN_EMAIL', 'admin@faxbot.local'),
            display_name='System Administrator',
            active=True
        )
        db.add(admin_user)

        # Assign all existing API keys to admin user
        existing_keys = db.query(APIKeyLegacy).all()
        for legacy_key in existing_keys:
            new_key = APIKey(
                id=legacy_key.id,
                key_id=legacy_key.key_id,
                key_hash=legacy_key.key_hash,
                name=legacy_key.name or f"Migrated Key {legacy_key.key_id}",
                user_id=admin_user.id,
                permissions=legacy_key.scopes.split(',') if legacy_key.scopes else [],
                created_at=legacy_key.created_at or datetime.utcnow()
            )
            db.add(new_key)

        # Assign default traits to admin user
        admin_traits = [
            UserTrait(user_id=admin_user.id, trait_name='admin_capable'),
            UserTrait(user_id=admin_user.id, trait_name='fax_capable'),
        ]

        # Determine HIPAA mode from environment
        if os.getenv('HIPAA_MODE', 'false').lower() == 'true':
            admin_traits.extend([
                UserTrait(user_id=admin_user.id, trait_name='hipaa_compliant'),
                UserTrait(user_id=admin_user.id, trait_name='phi_authorized')
            ])
        else:
            admin_traits.extend([
                UserTrait(user_id=admin_user.id, trait_name='non_hipaa'),
                UserTrait(user_id=admin_user.id, trait_name='email_capable')
            ])

        db.add_all(admin_traits)
        db.commit()
```

### Phase 3: UI Migration (Week 5-6)
```typescript
// Add user management to Admin Console
function UserManagementTab({ userContext }: { userContext: TraitAwareUIContext }) {
  const canManageUsers = userContext.user_traits.includes('admin_capable');

  if (!canManageUsers) {
    return <AccessDenied feature="User Management" />;
  }

  return (
    <ResponsiveCard title="User Management">
      <UserList />
      <CreateUserForm />
      <BulkUserActions />
      <UserImportExport />
    </ResponsiveCard>
  );
}
```

## Benefits of Plugin Architecture

### For Platform Evolution
1. **Backward Compatibility**: Existing API keys continue to work
2. **Gradual Migration**: Can deploy alongside existing system
3. **Future-Proof**: Easy to add new authentication methods
4. **Testability**: Can easily mock different identity providers

### For Customers
1. **Integration Freedom**: Use existing LDAP, SAML, ERP systems
2. **No Lock-in**: Can replace identity provider without changing Faxbot
3. **Compliance Options**: Choose identity system that meets their requirements
4. **Customization**: Adapt user experience to their organizational structure

### For Operations
1. **Real Users**: Finally have proper user management and sessions
2. **Better Auditing**: Track actions by actual users, not just API keys
3. **Scalable Permissions**: Groups and roles instead of flat API key scopes
4. **Session Management**: Web-like experience with proper login/logout

## Expected Outcomes

After implementation:

1. **Admin Console Login**: Users can log in with username/password
2. **Session Management**: Proper web sessions with timeouts and security
3. **User Administration**: Create/edit/delete users through GUI
4. **Group Management**: Organize users into departments/roles
5. **Trait Assignment**: Visual interface for assigning user traits
6. **API Key Management**: API keys belong to users, inherit their permissions
7. **Custom Integration**: Customers can replace with their identity systems
8. **Backward Compatibility**: Existing API keys continue working unchanged

## Conclusion

This user management plugin system finally gives Faxbot **real user management** while maintaining the flexibility that makes the platform unique. Customers get modern identity features while retaining the ability to integrate with their existing systems.

**Key Innovation**: Moving from API key-only to full user management, but as a plugin that customers can completely replace with their own systems while preserving all security and compliance guarantees.