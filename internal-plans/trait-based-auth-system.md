# Trait-Based Authentication & Authorization System

## Executive Summary

Faxbot uses a **trait-based access control (TBAC)** system where every entity (users, plugins, resources, messages) has traits that determine their capabilities, restrictions, and compatibility with other entities. This enables dynamic UX adaptation, granular permissions, and compliance enforcement.

**Primary Innovation**: HIPAA vs non-HIPAA as fundamental system trait that transforms the entire platform experience.

## Core Trait Philosophy

### Universal Trait Assignment
```python
# EVERYTHING has traits
class TraitBearer:
    def __init__(self):
        self.traits: List[str] = []

    def has_trait(self, trait: str) -> bool:
        return trait in self.traits

    def requires_trait(self, trait: str) -> bool:
        return trait in self.required_traits

    def compatible_with(self, other: 'TraitBearer') -> bool:
        return TraitEngine.check_compatibility(self.traits, other.traits)

# Users have traits
class User(TraitBearer):
    traits = ['hipaa_compliant', 'email_capable', 'fax_operator']

# Plugins have traits
class Plugin(TraitBearer):
    traits = ['requires_hipaa', 'handles_phi', 'async_processing']

# Messages have traits
class Message(TraitBearer):
    traits = ['contains_phi', 'encrypted', 'urgent']

# Resources have traits
class Resource(TraitBearer):
    traits = ['phi_data', 'public_config', 'audit_required']
```

## Primary Trait Categories

### 1. Compliance Traits
**Purpose**: Determine regulatory and security requirements

```python
COMPLIANCE_TRAITS = {
    # Primary compliance mode - mutually exclusive
    'hipaa_compliant': {
        'description': 'Entity operates under HIPAA requirements',
        'incompatible_with': ['non_hipaa'],
        'requires': ['audit_logging', 'encryption_at_rest'],
        'ui_adaptations': {
            'theme': 'medical',
            'terminology': 'clinical',
            'show_compliance_warnings': True,
            'color_scheme': 'medical_blues'
        }
    },

    'non_hipaa': {
        'description': 'Entity operates without HIPAA restrictions',
        'incompatible_with': ['hipaa_compliant', 'handles_phi'],
        'ui_adaptations': {
            'theme': 'business',
            'terminology': 'standard',
            'show_compliance_warnings': False,
            'color_scheme': 'neutral_grays'
        }
    },

    # Secondary compliance traits
    'phi_authorized': {
        'description': 'Can access PHI data',
        'requires': ['hipaa_compliant', 'mfa_enabled'],
        'audit_level': 'high'
    },

    'audit_exempt': {
        'description': 'Limited audit logging (non-PHI only)',
        'requires': ['non_hipaa'],
        'incompatible_with': ['phi_authorized']
    }
}
```

### 2. Capability Traits
**Purpose**: Define what actions/features are available

```python
CAPABILITY_TRAITS = {
    'fax_capable': {
        'description': 'Can send/receive faxes',
        'provides': ['document_transmission'],
        'permissions': ['send_fax', 'view_fax_jobs']
    },

    'email_capable': {
        'description': 'Can use email gateway features',
        'provides': ['email_transmission'],
        'permissions': ['configure_email', 'send_via_email'],
        'conflicts_with_compliance': {
            'hipaa_compliant': 'requires_additional_review'  # Email + HIPAA = careful!
        }
    },

    'admin_capable': {
        'description': 'Can perform administrative tasks',
        'provides': ['user_management', 'system_config'],
        'permissions': ['create_users', 'modify_settings', 'view_audit_logs']
    },

    'read_only': {
        'description': 'Can only view, cannot modify',
        'provides': ['data_viewing'],
        'incompatible_with': ['admin_capable'],
        'permissions': ['view_*']  # Wildcard for all view permissions
    }
}
```

### 3. Context Traits
**Purpose**: Dynamic traits based on current situation

```python
CONTEXT_TRAITS = {
    'business_hours': {
        'description': 'Additional permissions during business hours',
        'temporal': True,
        'provides': ['extended_access'],
        'active_when': lambda: datetime.now().hour in range(8, 18)
    },

    'high_risk_operation': {
        'description': 'Currently performing sensitive operation',
        'temporary': True,
        'requires': ['mfa_verified', 'supervisor_approval'],
        'duration_minutes': 30
    },

    'multi_tenant_access': {
        'description': 'Can access multiple tenants',
        'provides': ['cross_tenant_operations'],
        'audit_level': 'maximum'
    }
}
```

## The HIPAA/Non-HIPAA UX Revolution

### Problem Statement
> "As a non-HIPAA user, our admin console can be annoying as hell. No sysadmin likes to see the color red all over a dashboard."

### Solution: Trait-Driven UI Adaptation

```typescript
// Core trait-based UI system
interface TraitAwareUIContext {
  user_traits: string[];
  system_mode: 'hipaa' | 'standard' | 'mixed';
  ui_adaptations: UIAdaptations;
}

interface UIAdaptations {
  theme: 'medical' | 'business' | 'neutral';
  color_scheme: 'medical_blues' | 'business_grays' | 'neutral';
  show_compliance_warnings: boolean;
  terminology: 'clinical' | 'standard';
  security_level: 'high' | 'standard' | 'relaxed';
}

// Dynamic UI adaptation hook
export function useTraitBasedUI(user: User): TraitAwareUIContext {
  const isHIPAAUser = user.has_trait('hipaa_compliant');
  const isEmailCapable = user.has_trait('email_capable');

  return {
    user_traits: user.traits,
    system_mode: isHIPAAUser ? 'hipaa' : 'standard',
    ui_adaptations: {
      theme: isHIPAAUser ? 'medical' : 'business',
      color_scheme: isHIPAAUser ? 'medical_blues' : 'business_grays',
      show_compliance_warnings: isHIPAAUser,
      terminology: isHIPAAUser ? 'clinical' : 'standard',
      security_level: isHIPAAUser ? 'high' : 'standard'
    }
  };
}
```

### UI Component Examples

#### Dashboard Colors - No More Red for Non-HIPAA!
```typescript
function DashboardAlert({ message, level, userContext }: AlertProps) {
  const colors = userContext.ui_adaptations.color_scheme === 'medical_blues'
    ? {
        error: 'red.600',    // Medical users see red for critical issues
        warning: 'orange.500',
        info: 'blue.500'
      }
    : {
        error: 'gray.700',   // Business users see neutral colors
        warning: 'gray.600',
        info: 'gray.500'
      };

  return (
    <Alert status={level} colorScheme={colors[level]}>
      {message}
    </Alert>
  );
}
```

#### Terminology Adaptation
```typescript
function TerminologyProvider({ userContext, children }) {
  const terms = userContext.ui_adaptations.terminology === 'clinical'
    ? {
        user: 'Practitioner',
        message: 'Patient Document',
        send: 'Transmit Securely',
        error: 'Clinical Alert',
        configure: 'Configure Medical Settings'
      }
    : {
        user: 'User',
        message: 'Document',
        send: 'Send',
        error: 'System Notice',
        configure: 'Settings'
      };

  return (
    <TermsContext.Provider value={terms}>
      {children}
    </TermsContext.Provider>
  );
}
```

#### Feature Gating
```typescript
function EmailGatewaySettings({ userContext }: SettingsProps) {
  const canUseEmail = userContext.user_traits.includes('email_capable');
  const isHIPAAUser = userContext.user_traits.includes('hipaa_compliant');

  if (!canUseEmail) {
    return <FeatureNotAvailable feature="Email Gateway" />;
  }

  if (isHIPAAUser) {
    return (
      <Alert severity="warning" sx={{ mb: 2 }}>
        Email Gateway disabled in HIPAA mode. Available in Phase 2 with enhanced security.
      </Alert>
    );
  }

  return <EmailGatewayConfiguration />;
}
```

## Hybrid Permission Model

### Unix-Style Permissions (Power Users)
```python
class UnixPermissions:
    """Traditional rwx/755 permissions for Linux users"""

    def __init__(self, owner: str, group: str, permissions: str):
        self.owner = owner
        self.group = group
        self.permissions = permissions  # '755', '644', etc.

    def can_read(self, user: User) -> bool:
        return self._check_permission(user, 'r')

    def can_write(self, user: User) -> bool:
        return self._check_permission(user, 'w')

    def can_execute(self, user: User) -> bool:
        return self._check_permission(user, 'x')

    def to_windows_style(self) -> List[str]:
        """Convert to Windows-friendly descriptions"""
        perms = []
        if self.can_read(None): perms.append('Read')
        if self.can_write(None): perms.append('Write')
        if self.can_execute(None): perms.append('Execute')
        return perms
```

### Windows-Style Permissions (Business Users)
```python
class WindowsPermissions:
    """Windows-friendly permission descriptions"""

    PERMISSION_LEVELS = {
        'full_control': '777',
        'modify': '755',
        'read_execute': '555',
        'read_only': '444',
        'write_only': '222',
        'no_access': '000'
    }

    def __init__(self, level: str):
        self.level = level
        self.numeric = self.PERMISSION_LEVELS[level]

    def to_checkboxes(self) -> Dict[str, bool]:
        """Convert to checkbox states for UI"""
        numeric = self.numeric[0]  # Owner permissions
        return {
            'read': int(numeric) & 4 != 0,
            'write': int(numeric) & 2 != 0,
            'execute': int(numeric) & 1 != 0
        }
```

### Trait-Based Access Control Layer
```python
class TraitBasedAccessControl:
    """Overlay TBAC on top of Unix/Windows permissions"""

    def check_access(self, user: User, resource: Resource, action: str) -> bool:
        # 1. Check traditional permissions first
        unix_allowed = self.unix_permissions.check(user, resource, action)

        # 2. Check trait compatibility
        trait_allowed = self.check_trait_compatibility(user, resource)

        # 3. Check action-specific trait requirements
        action_allowed = self.check_action_traits(user, action)

        # 4. All must pass
        return unix_allowed and trait_allowed and action_allowed

    def check_trait_compatibility(self, user: User, resource: Resource) -> bool:
        """Can this user access this resource based on traits?"""

        # HIPAA user accessing non-HIPAA resource = OK
        # Non-HIPAA user accessing HIPAA resource = BLOCKED
        if resource.has_trait('requires_hipaa') and not user.has_trait('hipaa_compliant'):
            audit_event('access_denied', reason='hipaa_requirement_not_met')
            return False

        # PHI data requires PHI authorization
        if resource.has_trait('contains_phi') and not user.has_trait('phi_authorized'):
            audit_event('access_denied', reason='phi_authorization_required')
            return False

        # Email features require email capability
        if resource.has_trait('email_feature') and not user.has_trait('email_capable'):
            return False

        return True

    def check_action_traits(self, user: User, action: str) -> bool:
        """Does user have required traits for this action?"""
        action_requirements = {
            'send_fax': ['fax_capable'],
            'configure_email': ['email_capable', 'admin_capable'],
            'access_phi': ['phi_authorized', 'hipaa_compliant'],
            'create_user': ['admin_capable'],
            'modify_retention': ['hipaa_compliant', 'admin_capable']
        }

        required_traits = action_requirements.get(action, [])
        return all(user.has_trait(trait) for trait in required_traits)
```

## Admin Console Permission Editor

### Visual Permission Interface
```typescript
function PermissionEditor({ resource, userContext }: PermissionEditorProps) {
  const [viewMode, setViewMode] = useState<'simple' | 'advanced'>('simple');
  const isLinuxUser = userContext.user_traits.includes('linux_comfortable');
  const defaultMode = isLinuxUser ? 'advanced' : 'simple';

  return (
    <Card>
      <CardHeader>
        <Typography variant="h6">Permissions: {resource.name}</Typography>
        <Toggle value={viewMode} onChange={setViewMode}>
          <ToggleButton value="simple">Simple</ToggleButton>
          <ToggleButton value="advanced">Advanced</ToggleButton>
        </Toggle>
      </CardHeader>

      <CardContent>
        {viewMode === 'simple' ? (
          <WindowsStylePermissions resource={resource} />
        ) : (
          <UnixStylePermissions resource={resource} />
        )}

        <TraitBasedRestrictions resource={resource} />
      </CardContent>
    </Card>
  );
}

function WindowsStylePermissions({ resource }: { resource: Resource }) {
  return (
    <Box>
      <Typography variant="subtitle1">Permission Level</Typography>
      <Select value={resource.permission_level}>
        <MenuItem value="full_control">Full Control</MenuItem>
        <MenuItem value="modify">Modify</MenuItem>
        <MenuItem value="read_execute">Read & Execute</MenuItem>
        <MenuItem value="read_only">Read Only</MenuItem>
      </Select>

      <Typography variant="subtitle2" sx={{ mt: 2 }}>
        Current Permissions ({resource.numeric_permissions}):
      </Typography>
      <Stack direction="row" spacing={2}>
        <Checkbox checked={resource.can_read} label="Read" />
        <Checkbox checked={resource.can_write} label="Write" />
        <Checkbox checked={resource.can_execute} label="Execute" />
      </Stack>
    </Box>
  );
}

function UnixStylePermissions({ resource }: { resource: Resource }) {
  return (
    <Box>
      <TextField
        label="Numeric Permissions"
        value={resource.numeric_permissions}
        placeholder="755"
        helperText="rwx format: 755 = rwxr-xr-x"
      />

      <Grid container spacing={2} sx={{ mt: 1 }}>
        <Grid item xs={4}>
          <Typography variant="subtitle2">Owner</Typography>
          <PermissionCheckboxes permissions={resource.owner_permissions} />
        </Grid>
        <Grid item xs={4}>
          <Typography variant="subtitle2">Group</Typography>
          <PermissionCheckboxes permissions={resource.group_permissions} />
        </Grid>
        <Grid item xs={4}>
          <Typography variant="subtitle2">Others</Typography>
          <PermissionCheckboxes permissions={resource.other_permissions} />
        </Grid>
      </Grid>

      <Alert severity="info" sx={{ mt: 2 }}>
        <Typography variant="body2">
          Symbolic: {resource.symbolic_permissions} |
          Windows: {resource.windows_description}
        </Typography>
      </Alert>
    </Box>
  );
}

function TraitBasedRestrictions({ resource }: { resource: Resource }) {
  return (
    <Box sx={{ mt: 3 }}>
      <Typography variant="subtitle1">Trait-Based Access</Typography>

      <Alert severity="warning" sx={{ mb: 2 }}>
        <Typography variant="body2">
          Traditional permissions are overridden by trait requirements.
          Users must have compatible traits regardless of rwx permissions.
        </Typography>
      </Alert>

      <Stack spacing={1}>
        {resource.required_traits.map(trait => (
          <Chip
            key={trait}
            label={`Requires: ${trait}`}
            color="error"
            variant="outlined"
          />
        ))}

        {resource.prohibited_traits.map(trait => (
          <Chip
            key={trait}
            label={`Blocks: ${trait}`}
            color="warning"
            variant="outlined"
          />
        ))}
      </Stack>
    </Box>
  );
}
```

## API Integration with Scopes & Traits

### Enhanced API Key System
```python
class APIKey(Base):
    """Extended API key with trait support"""

    # Existing fields
    id = Column(String(40), primary_key=True)
    key_id = Column(String(32), unique=True)
    key_hash = Column(String(200))
    scopes = Column(String(500))  # Existing comma-separated scopes

    # New trait-based fields
    user_traits = Column(Text)  # JSON array of user traits
    allowed_operations = Column(Text)  # JSON array of allowed operations
    compliance_mode = Column(String(20))  # 'hipaa', 'standard', 'mixed'
    trait_restrictions = Column(Text)  # JSON object of trait-based restrictions

    def has_scope(self, scope: str) -> bool:
        """Traditional scope checking"""
        return scope in (self.scopes or '').split(',')

    def has_trait(self, trait: str) -> bool:
        """Trait-based checking"""
        traits = json.loads(self.user_traits or '[]')
        return trait in traits

    def can_perform_action(self, action: str, resource_traits: List[str]) -> bool:
        """Combined scope and trait checking"""
        # Traditional scope check
        if not self.has_scope(f"{action}:*"):
            return False

        # Trait compatibility check
        user_traits = json.loads(self.user_traits or '[]')
        restrictions = json.loads(self.trait_restrictions or '{}')

        # Check if user traits are compatible with resource traits
        return TraitEngine.check_compatibility(user_traits, resource_traits)

# Usage in middleware
def verify_request_authorization(request, required_action: str, resource: Resource):
    api_key_info = verify_db_key(request.headers.get('X-API-Key'))
    if not api_key_info:
        raise HTTPException(401, "Invalid API key")

    # Enhanced authorization with traits
    if not api_key_info.can_perform_action(required_action, resource.traits):
        audit_event('authorization_failed',
                   key_id=api_key_info.key_id,
                   action=required_action,
                   resource_traits=resource.traits,
                   user_traits=api_key_info.user_traits)
        raise HTTPException(403, "Insufficient permissions or incompatible traits")

    return api_key_info
```

### Granular Email Permissions Example
```python
# Different users, different email capabilities
HOSPITAL_API_KEYS = {
    # Doctor - can fax, cannot email (PHI security)
    'doctor_key': {
        'scopes': ['fax:send', 'fax:status'],
        'traits': ['hipaa_compliant', 'fax_capable', 'phi_authorized'],
        'restrictions': {
            'email_gateway': 'blocked',  # No email for PHI
            'external_integrations': 'audit_required'
        }
    },

    # Marketing team - can email, cannot access PHI
    'marketing_key': {
        'scopes': ['email:send', 'email:configure'],
        'traits': ['non_hipaa', 'email_capable', 'external_communications'],
        'restrictions': {
            'phi_data': 'blocked',
            'patient_records': 'blocked'
        }
    },

    # IT Admin - can configure email, but not send PHI via email
    'admin_key': {
        'scopes': ['*'],  # All scopes
        'traits': ['hipaa_compliant', 'admin_capable', 'email_capable'],
        'restrictions': {
            'phi_via_email': 'blocked',  # Can configure email, but PHI must use fax
            'audit_bypass': 'never'
        }
    }
}
```

## Database Schema Extensions

### Trait Storage Tables
```sql
-- Users and their traits
CREATE TABLE user_traits (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id),
    trait_name VARCHAR(100) NOT NULL,
    granted_by UUID REFERENCES users(id),
    granted_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NULL,
    context JSONB,  -- Additional context for conditional traits
    UNIQUE(user_id, trait_name)
);

-- Resources and their trait requirements
CREATE TABLE resource_traits (
    id UUID PRIMARY KEY,
    resource_type VARCHAR(50) NOT NULL,  -- 'endpoint', 'data', 'feature'
    resource_id VARCHAR(200) NOT NULL,
    required_traits TEXT[],  -- Array of required traits
    prohibited_traits TEXT[],  -- Array of prohibited traits
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(resource_type, resource_id)
);

-- Trait definitions and rules
CREATE TABLE trait_definitions (
    name VARCHAR(100) PRIMARY KEY,
    category VARCHAR(50) NOT NULL,
    description TEXT,
    incompatible_with TEXT[],
    requires TEXT[],
    provides TEXT[],
    ui_adaptations JSONB,
    audit_level VARCHAR(20) DEFAULT 'standard',
    created_at TIMESTAMP DEFAULT NOW()
);

-- Trait compatibility matrix
CREATE TABLE trait_compatibility (
    source_trait VARCHAR(100) NOT NULL,
    target_trait VARCHAR(100) NOT NULL,
    relationship VARCHAR(20) NOT NULL,  -- 'requires', 'conflicts', 'enhances'
    context JSONB,
    PRIMARY KEY(source_trait, target_trait, relationship)
);
```

## Migration Strategy

### Phase 1: Trait Infrastructure (Weeks 1-2)
```python
# 1. Create trait storage tables
# 2. Implement TraitEngine core
# 3. Add trait fields to existing models
# 4. Create trait assignment APIs

class TraitMigration:
    def migrate_existing_users(self):
        """Add default traits to existing users"""
        for user in User.query.all():
            # Default traits based on existing data
            if user.is_admin:
                user.traits.append('admin_capable')

            # HIPAA determination - could be env var, manual assignment
            if os.getenv('DEFAULT_HIPAA_MODE', 'false') == 'true':
                user.traits.append('hipaa_compliant')
            else:
                user.traits.append('non_hipaa')
```

### Phase 2: UI Adaptation (Weeks 3-4)
```typescript
// 1. Create trait-aware UI components
// 2. Implement dynamic theming
// 3. Add terminology adaptation
// 4. Update all existing components

function migrateUIComponents() {
  // Wrap all existing components with trait-aware providers
  return (
    <TraitContextProvider user={currentUser}>
      <DynamicThemeProvider>
        <TerminologyProvider>
          <ExistingApp />
        </TerminologyProvider>
      </DynamicThemeProvider>
    </TraitContextProvider>
  );
}
```

### Phase 3: Permission Integration (Weeks 5-6)
```python
# 1. Extend existing permission checks with traits
# 2. Create hybrid Unix/Windows permission UI
# 3. Update API authorization middleware
# 4. Add trait-based resource protection

@requires_traits(['fax_capable'])
@requires_unix_permission('644')  # Read/write for owner and group
def send_fax_endpoint(request):
    # Both traditional permissions AND traits required
    pass
```

## Expected Outcomes

### For Non-HIPAA Users
- **Clean Dashboard**: No red alerts or medical warnings
- **Simplified Interface**: Business terminology and neutral colors
- **Full Email Access**: Can use email gateway without restrictions
- **Streamlined Workflow**: Focus on productivity, not compliance

### For HIPAA Users
- **Compliance-First UX**: Medical terminology and appropriate warnings
- **Enhanced Security**: PHI protection and audit trails
- **Controlled Access**: Email features gated behind additional security
- **Clinical Workflow**: Interface adapted for healthcare environment

### For Mixed Organizations
- **User-Specific Experience**: Each user sees appropriate interface
- **Flexible Permissions**: Granular control over who can do what
- **Seamless Integration**: Marketing team doesn't see medical workflows
- **Unified Platform**: Single system serving multiple user types

## Conclusion

The trait-based system transforms Faxbot from a one-size-fits-all platform into a **dynamic, adaptive system** that provides the right experience for the right user. Non-HIPAA users get a clean, business-focused interface while HIPAA users get appropriate compliance controls and clinical workflows.

**Key Innovation**: Traits don't just control permissions - they control the entire user experience, making the platform feel native to each user's context and requirements.