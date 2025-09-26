# Configuration Hierarchy Migration Plan - From .env to Enterprise Scale

## Executive Summary

Migrate Faxbot from flat .env configuration to a **hierarchical, multi-tenant configuration system** that scales to hundreds of users across multiple hospitals. The new system provides configuration inheritance (Global → Tenant → Group → User) while maintaining backward compatibility and implementing configuration as a plugin.

**Critical Need**: Current .env approach breaks down with 5 hospitals, hundreds of users, and complex permission requirements.

## Current State Problems

### .env Configuration Limitations
```bash
# Current approach - flat, single-tenant
FAX_BACKEND=phaxio
PHAXIO_API_KEY=global_key_for_everyone
HIPAA_MODE=true  # All users get same setting
EMAIL_GATEWAY_ENABLED=false  # Global on/off for entire platform

# Problems at scale:
# 1. Hospital A needs Phaxio, Hospital B needs SIP
# 2. Marketing team needs non-HIPAA, Doctors need HIPAA
# 3. No per-user customization
# 4. No delegation of configuration management
# 5. Restart required for config changes
# 6. No audit trail of configuration changes
```

### Backend Isolation Issues
Current provider isolation in Admin Console breaks because:
- All users see same backend configuration
- Cannot show different settings based on user context
- Marketing team sees medical provider settings
- No tenant-specific branding or terminology

### Scale Failure Scenarios
```
❌ Hospital Network Use Case:
   ├── Mercy Hospital (5000 users, HIPAA, Phaxio)
   ├── General Hospital (3000 users, HIPAA, SIP/Asterisk)
   ├── Marketing Dept (50 users, non-HIPAA, email enabled)
   └── IT Department (20 users, admin access, all features)

   Current system: ALL users get same .env config
   Required system: Each group gets appropriate config
```

## Hierarchical Configuration Architecture

### Configuration Hierarchy Levels
```
Global (Platform Defaults)
├── Tenant (Hospital/Organization)
│   ├── Department (Marketing, Medical, IT)
│   │   ├── Group (Doctors, Nurses, Admins)
│   │   │   └── User (Individual Overrides)
```

### Configuration Inheritance Model
```python
# Configuration resolution with cascading overrides
class ConfigResolution:
    def resolve_config(self, key: str, user_context: UserContext) -> ConfigValue:
        """
        Resolve configuration with inheritance:
        User → Group → Department → Tenant → Global
        More specific settings override general ones
        """

        # Start with global default
        value = self.get_global_default(key)

        # Apply tenant override
        if user_context.tenant_id:
            tenant_override = self.get_tenant_config(user_context.tenant_id, key)
            if tenant_override:
                value = tenant_override

        # Apply department override
        if user_context.department:
            dept_override = self.get_department_config(
                user_context.tenant_id,
                user_context.department,
                key
            )
            if dept_override:
                value = dept_override

        # Apply group overrides
        for group in user_context.groups:
            group_override = self.get_group_config(group, key)
            if group_override:
                value = group_override

        # Apply user-specific override
        user_override = self.get_user_config(user_context.user_id, key)
        if user_override:
            value = user_override

        return value

# Example configuration resolution
user_context = UserContext(
    user_id='user123',
    tenant_id='mercy_hospital',
    department='medical',
    groups=['doctors', 'emergency_dept']
)

# Resolving 'fax_backend' setting:
# Global: 'phaxio'
# Tenant (mercy_hospital): 'phaxio' (inherits)
# Department (medical): 'phaxio' (inherits)
# Group (doctors): 'sip' (override for emergency response)
# User (user123): null (inherits group)
# Result: 'sip'
```

## Database Schema Design

### Core Configuration Tables
```sql
-- Global configuration defaults
CREATE TABLE config_global (
    key VARCHAR(200) PRIMARY KEY,
    value TEXT NOT NULL,
    value_type VARCHAR(20) NOT NULL DEFAULT 'string',  -- string, number, boolean, json
    encrypted BOOLEAN DEFAULT FALSE,
    description TEXT,
    category VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);

-- Tenant-level configuration
CREATE TABLE config_tenant (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(100) NOT NULL,
    key VARCHAR(200) NOT NULL,
    value TEXT NOT NULL,
    value_type VARCHAR(20) NOT NULL DEFAULT 'string',
    encrypted BOOLEAN DEFAULT FALSE,
    overrides_global BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    UNIQUE(tenant_id, key)
);

-- Department-level configuration
CREATE TABLE config_department (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id VARCHAR(100) NOT NULL,
    department VARCHAR(100) NOT NULL,
    key VARCHAR(200) NOT NULL,
    value TEXT NOT NULL,
    value_type VARCHAR(20) NOT NULL DEFAULT 'string',
    encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    UNIQUE(tenant_id, department, key)
);

-- Group-level configuration
CREATE TABLE config_group (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID NOT NULL REFERENCES groups(id),
    key VARCHAR(200) NOT NULL,
    value TEXT NOT NULL,
    value_type VARCHAR(20) NOT NULL DEFAULT 'string',
    encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    UNIQUE(group_id, key)
);

-- User-level configuration
CREATE TABLE config_user (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    key VARCHAR(200) NOT NULL,
    value TEXT NOT NULL,
    value_type VARCHAR(20) NOT NULL DEFAULT 'string',
    encrypted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    UNIQUE(user_id, key)
);

-- Configuration change audit trail
CREATE TABLE config_audit (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    config_table VARCHAR(50) NOT NULL,  -- 'global', 'tenant', 'group', 'user'
    config_id VARCHAR(100),  -- Reference ID in that table
    key VARCHAR(200) NOT NULL,
    old_value TEXT,
    new_value TEXT,
    change_type VARCHAR(20) NOT NULL,  -- 'create', 'update', 'delete'
    changed_by UUID NOT NULL REFERENCES users(id),
    changed_at TIMESTAMP DEFAULT NOW(),
    ip_address INET,
    user_agent TEXT,
    reason TEXT
);

-- Configuration templates for quick setup
CREATE TABLE config_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    target_level VARCHAR(20) NOT NULL,  -- 'tenant', 'department', 'group'
    template_data JSONB NOT NULL,
    traits TEXT[],  -- Required traits to use this template
    created_at TIMESTAMP DEFAULT NOW(),
    created_by UUID REFERENCES users(id)
);
```

### Example Hierarchical Configuration
```sql
-- Global defaults (platform-wide)
INSERT INTO config_global (key, value, description) VALUES
('fax_backend', 'phaxio', 'Default fax provider'),
('hipaa_mode', 'false', 'Default HIPAA compliance mode'),
('email_gateway_enabled', 'false', 'Email gateway availability'),
('max_file_size_mb', '10', 'Maximum file upload size');

-- Mercy Hospital tenant configuration
INSERT INTO config_tenant (tenant_id, key, value) VALUES
('mercy_hospital', 'fax_backend', 'phaxio'),
('mercy_hospital', 'hipaa_mode', 'true'),
('mercy_hospital', 'organization_name', 'Mercy Hospital Network'),
('mercy_hospital', 'branding_color', '#2E7D99');

-- Medical department configuration
INSERT INTO config_department (tenant_id, department, key, value) VALUES
('mercy_hospital', 'medical', 'hipaa_mode', 'true'),
('mercy_hospital', 'medical', 'phi_access_enabled', 'true'),
('mercy_hospital', 'medical', 'email_gateway_enabled', 'false');

-- Marketing department configuration
INSERT INTO config_department (tenant_id, department, key, value) VALUES
('mercy_hospital', 'marketing', 'hipaa_mode', 'false'),
('mercy_hospital', 'marketing', 'phi_access_enabled', 'false'),
('mercy_hospital', 'marketing', 'email_gateway_enabled', 'true');

-- Emergency doctors group configuration
INSERT INTO config_group (group_id, key, value) VALUES
('emergency_doctors_group', 'fax_backend', 'sip'),  -- Need faster SIP for emergencies
('emergency_doctors_group', 'priority_processing', 'true'),
('emergency_doctors_group', 'notification_urgency', 'high');
```

## Configuration Provider Plugin

### Plugin Interface
```python
# api/app/plugins/config/base.py
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

@dataclass
class UserContext:
    user_id: str
    tenant_id: Optional[str]
    department: Optional[str]
    groups: List[str]
    traits: List[str]

@dataclass
class ConfigValue:
    key: str
    value: Any
    source_level: str  # 'global', 'tenant', 'department', 'group', 'user'
    source_id: str
    encrypted: bool
    last_updated: datetime

class ConfigProvider(Plugin):
    """Base interface for configuration providers"""

    @abstractmethod
    async def get(self, key: str, context: UserContext, default: Any = None) -> ConfigValue:
        """Get configuration value with hierarchy resolution"""
        pass

    @abstractmethod
    async def set(self, key: str, value: Any, level: str, level_id: str,
                  context: UserContext) -> bool:
        """Set configuration value at specific level"""
        pass

    @abstractmethod
    async def delete(self, key: str, level: str, level_id: str,
                     context: UserContext) -> bool:
        """Delete configuration value at specific level"""
        pass

    @abstractmethod
    async def list_keys(self, context: UserContext, prefix: str = None) -> List[str]:
        """List available configuration keys for user context"""
        pass

    @abstractmethod
    async def get_hierarchy(self, key: str, context: UserContext) -> List[ConfigValue]:
        """Get configuration hierarchy showing all levels"""
        pass

    @abstractmethod
    async def get_effective_config(self, context: UserContext) -> Dict[str, Any]:
        """Get all effective configuration for user context"""
        pass
```

### Default Implementation - PostgreSQL Provider
```python
# api/app/plugins/config/postgresql/provider.py
class PostgreSQLConfigProvider(ConfigProvider):
    """PostgreSQL-based hierarchical configuration"""

    def __init__(self):
        self.db = SessionLocal
        self.cache = ConfigCache()  # Redis-backed cache
        self.encryptor = ConfigEncryption()

    async def get(self, key: str, context: UserContext, default: Any = None) -> ConfigValue:
        """Resolve configuration with caching and hierarchy"""

        # Check cache first
        cache_key = self._build_cache_key(key, context)
        cached_value = await self.cache.get(cache_key)
        if cached_value:
            return cached_value

        # Resolve through hierarchy
        resolved_value = await self._resolve_hierarchy(key, context, default)

        # Cache the result
        await self.cache.set(cache_key, resolved_value, ttl=300)  # 5 minute TTL

        return resolved_value

    async def _resolve_hierarchy(self, key: str, context: UserContext, default: Any) -> ConfigValue:
        """Resolve configuration through hierarchy levels"""

        with self.db() as db:
            # 1. Check user-specific config
            user_config = db.query(ConfigUser).filter(
                ConfigUser.user_id == context.user_id,
                ConfigUser.key == key
            ).first()

            if user_config:
                return self._to_config_value(user_config, 'user', context.user_id)

            # 2. Check group configs (most specific group wins)
            for group_id in context.groups:
                group_config = db.query(ConfigGroup).filter(
                    ConfigGroup.group_id == group_id,
                    ConfigGroup.key == key
                ).first()

                if group_config:
                    return self._to_config_value(group_config, 'group', group_id)

            # 3. Check department config
            if context.department and context.tenant_id:
                dept_config = db.query(ConfigDepartment).filter(
                    ConfigDepartment.tenant_id == context.tenant_id,
                    ConfigDepartment.department == context.department,
                    ConfigDepartment.key == key
                ).first()

                if dept_config:
                    return self._to_config_value(dept_config, 'department',
                                               f"{context.tenant_id}/{context.department}")

            # 4. Check tenant config
            if context.tenant_id:
                tenant_config = db.query(ConfigTenant).filter(
                    ConfigTenant.tenant_id == context.tenant_id,
                    ConfigTenant.key == key
                ).first()

                if tenant_config:
                    return self._to_config_value(tenant_config, 'tenant', context.tenant_id)

            # 5. Check global config
            global_config = db.query(ConfigGlobal).filter(
                ConfigGlobal.key == key
            ).first()

            if global_config:
                return self._to_config_value(global_config, 'global', 'global')

            # 6. Return default
            return ConfigValue(
                key=key,
                value=default,
                source_level='default',
                source_id='default',
                encrypted=False,
                last_updated=datetime.utcnow()
            )

    async def set(self, key: str, value: Any, level: str, level_id: str,
                  context: UserContext) -> bool:
        """Set configuration value with audit trail"""

        try:
            with self.db() as db:
                # Get existing value for audit
                old_value = await self._get_raw_value(key, level, level_id, db)

                # Encrypt if needed
                encrypted = self._should_encrypt(key)
                stored_value = self.encryptor.encrypt(str(value)) if encrypted else str(value)

                # Update/insert based on level
                config_record = await self._upsert_config(
                    key, stored_value, level, level_id, context, encrypted, db
                )

                # Create audit record
                audit_record = ConfigAudit(
                    config_table=level,
                    config_id=level_id,
                    key=key,
                    old_value=old_value,
                    new_value=str(value),  # Store decrypted in audit (secure audit table)
                    change_type='update' if old_value else 'create',
                    changed_by=context.user_id,
                    changed_at=datetime.utcnow(),
                    reason=f"Configuration update via {level} level"
                )
                db.add(audit_record)

                db.commit()

                # Invalidate cache
                await self._invalidate_cache(key, level, level_id)

                # Audit event
                audit_event('configuration_changed',
                           user_id=context.user_id,
                           key=key,
                           level=level,
                           level_id=level_id)

                return True

        except Exception as e:
            audit_event('configuration_change_failed',
                       user_id=context.user_id,
                       key=key,
                       error=str(e))
            return False

    def _should_encrypt(self, key: str) -> bool:
        """Determine if configuration key should be encrypted"""
        encryption_patterns = [
            'api_key', 'api_secret', 'password', 'token',
            'oauth_', 'credentials', 'private_key', 'secret'
        ]

        return any(pattern in key.lower() for pattern in encryption_patterns)

    async def get_effective_config(self, context: UserContext) -> Dict[str, Any]:
        """Get complete effective configuration for user"""

        # Get all possible keys from all levels
        all_keys = await self._get_all_available_keys(context)

        # Resolve each key through hierarchy
        effective_config = {}
        for key in all_keys:
            config_value = await self.get(key, context)
            effective_config[key] = config_value.value

        return effective_config
```

## Migration Strategy

### Phase 1: Parallel Systems (Week 1-2)
```python
# Run both .env and database config simultaneously
class HybridConfigProvider(ConfigProvider):
    """Transition provider supporting both .env and database"""

    def __init__(self):
        self.db_provider = PostgreSQLConfigProvider()
        self.env_provider = EnvConfigProvider()  # Legacy .env reader

    async def get(self, key: str, context: UserContext, default: Any = None) -> ConfigValue:
        """Try database first, fallback to .env"""

        try:
            # Try database configuration first
            db_value = await self.db_provider.get(key, context, None)
            if db_value and db_value.value is not None:
                return db_value
        except Exception:
            pass

        # Fallback to .env
        env_value = self.env_provider.get(key, default)
        return ConfigValue(
            key=key,
            value=env_value,
            source_level='env_legacy',
            source_id='env_file',
            encrypted=False,
            last_updated=datetime.utcnow()
        )
```

### Phase 2: .env Import (Week 3-4)
```python
# Import existing .env configuration into database
class EnvImporter:
    """Import .env configuration into hierarchical system"""

    def __init__(self, config_provider: ConfigProvider):
        self.config = config_provider

    async def import_env_file(self, env_file_path: str, target_level: str = 'global') -> ImportResult:
        """Import .env file into configuration database"""

        try:
            # Parse .env file
            env_vars = self._parse_env_file(env_file_path)

            imported_count = 0
            skipped_count = 0

            for key, value in env_vars.items():
                # Map .env keys to new configuration keys
                config_key = self._map_env_key(key)

                # Determine appropriate level and value
                target_level, level_id, final_value = self._determine_target(
                    config_key, value
                )

                # Import into database
                success = await self.config.set(
                    config_key,
                    final_value,
                    target_level,
                    level_id,
                    admin_context
                )

                if success:
                    imported_count += 1
                else:
                    skipped_count += 1

            return ImportResult(
                success=True,
                imported=imported_count,
                skipped=skipped_count,
                env_file=env_file_path
            )

        except Exception as e:
            return ImportResult(success=False, error=str(e))

    def _map_env_key(self, env_key: str) -> str:
        """Map old .env keys to new configuration keys"""
        key_mappings = {
            'FAX_BACKEND': 'fax.backend.provider',
            'PHAXIO_API_KEY': 'providers.phaxio.api_key',
            'PHAXIO_API_SECRET': 'providers.phaxio.api_secret',
            'HIPAA_MODE': 'compliance.hipaa.enabled',
            'EMAIL_GATEWAY_ENABLED': 'features.email_gateway.enabled',
            'MAX_FILE_SIZE_MB': 'uploads.max_size_mb',
            'API_KEY': 'security.default_api_key'
        }

        return key_mappings.get(env_key, env_key.lower())

    def _determine_target(self, key: str, value: str) -> Tuple[str, str, Any]:
        """Determine appropriate configuration level for key"""

        # Global platform settings
        global_keys = ['uploads.max_size_mb', 'security.', 'platform.']
        if any(key.startswith(prefix) for prefix in global_keys):
            return 'global', 'global', self._parse_value(value)

        # Provider-specific settings go to tenant level by default
        if key.startswith('providers.'):
            return 'tenant', 'default_tenant', self._parse_value(value)

        # Feature flags go to global by default
        if key.startswith('features.'):
            return 'global', 'global', self._parse_value(value)

        # Compliance settings go to tenant level
        if key.startswith('compliance.'):
            return 'tenant', 'default_tenant', self._parse_value(value)

        # Default to global
        return 'global', 'global', self._parse_value(value)
```

### Phase 3: Multi-Tenant Setup (Week 5-6)
```python
# Create tenant-specific configurations
class TenantProvisioner:
    """Set up multi-tenant configuration hierarchies"""

    def __init__(self, config_provider: ConfigProvider):
        self.config = config_provider

    async def create_tenant(self, tenant_data: Dict) -> TenantCreationResult:
        """Create new tenant with configuration hierarchy"""

        tenant_id = tenant_data['id']
        tenant_name = tenant_data['name']
        tenant_type = tenant_data.get('type', 'healthcare')  # healthcare, business, etc.

        try:
            # Create base tenant configuration
            base_config = self._get_tenant_template(tenant_type)

            for key, value in base_config.items():
                await self.config.set(
                    key, value, 'tenant', tenant_id, admin_context
                )

            # Create default departments
            departments = tenant_data.get('departments', ['general'])
            for dept in departments:
                await self._create_department(tenant_id, dept)

            # Create default groups
            groups = tenant_data.get('groups', [])
            for group_data in groups:
                await self._create_group(tenant_id, group_data)

            return TenantCreationResult(
                success=True,
                tenant_id=tenant_id,
                config_keys_created=len(base_config)
            )

        except Exception as e:
            return TenantCreationResult(success=False, error=str(e))

    def _get_tenant_template(self, tenant_type: str) -> Dict[str, Any]:
        """Get configuration template for tenant type"""

        if tenant_type == 'healthcare':
            return {
                'compliance.hipaa.enabled': True,
                'compliance.hipaa.audit_level': 'maximum',
                'features.email_gateway.enabled': False,
                'features.phi_access.enabled': True,
                'ui.theme': 'medical',
                'ui.terminology': 'clinical',
                'notifications.compliance_alerts': True
            }

        elif tenant_type == 'business':
            return {
                'compliance.hipaa.enabled': False,
                'features.email_gateway.enabled': True,
                'features.phi_access.enabled': False,
                'ui.theme': 'business',
                'ui.terminology': 'standard',
                'notifications.marketing_features': True
            }

        else:  # default
            return {
                'compliance.hipaa.enabled': False,
                'features.email_gateway.enabled': True,
                'ui.theme': 'neutral'
            }
```

## Admin Console Integration

### Configuration Management UI
```typescript
// Hierarchical configuration management interface
export default function ConfigurationManager({ user }: { user: User }) {
  const [selectedLevel, setSelectedLevel] = useState<ConfigLevel>('tenant');
  const [selectedScope, setSelectedScope] = useState<string>('');
  const [configData, setConfigData] = useState<ConfigHierarchy>();

  const canManageConfig = user.traits.includes('admin_capable');

  if (!canManageConfig) {
    return <AccessDenied feature="Configuration Management" />;
  }

  return (
    <ResponsiveCard title="Configuration Management">
      <ConfigLevelSelector
        level={selectedLevel}
        scope={selectedScope}
        user={user}
        onChange={(level, scope) => {
          setSelectedLevel(level);
          setSelectedScope(scope);
        }}
      />

      <ConfigHierarchyView
        level={selectedLevel}
        scope={selectedScope}
        config={configData}
        onChange={setConfigData}
      />

      <ConfigPreviewPanel
        user={user}
        config={configData}
        showEffectiveConfig={true}
      />
    </ResponsiveCard>
  );
}

function ConfigLevelSelector({ level, scope, user, onChange }: SelectorProps) {
  return (
    <Box sx={{ mb: 3 }}>
      <Typography variant="h6">Configuration Level</Typography>

      <Stack direction="row" spacing={2} sx={{ mt: 1 }}>
        <Button
          variant={level === 'global' ? 'contained' : 'outlined'}
          onClick={() => onChange('global', '')}
          disabled={!user.traits.includes('super_admin')}
        >
          🌐 Global
        </Button>

        <Button
          variant={level === 'tenant' ? 'contained' : 'outlined'}
          onClick={() => onChange('tenant', user.tenant_id)}
          disabled={!user.traits.includes('tenant_admin')}
        >
          🏢 Tenant
        </Button>

        <Button
          variant={level === 'department' ? 'contained' : 'outlined'}
          onClick={() => onChange('department', user.department)}
          disabled={!user.traits.includes('dept_admin')}
        >
          🏬 Department
        </Button>

        <Button
          variant={level === 'group' ? 'contained' : 'outlined'}
          onClick={() => onChange('group', '')}
        >
          👥 Group
        </Button>
      </Stack>

      {level !== 'global' && (
        <ScopeSelector
          level={level}
          selectedScope={scope}
          user={user}
          onChange={(newScope) => onChange(level, newScope)}
        />
      )}
    </Box>
  );
}

function ConfigHierarchyView({ level, scope, config, onChange }: HierarchyProps) {
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set());

  return (
    <Box>
      <Typography variant="h6" sx={{ mb: 2 }}>
        Configuration: {level} {scope && `(${scope})`}
      </Typography>

      {Object.entries(configSections).map(([sectionKey, section]) => (
        <ConfigSection
          key={sectionKey}
          section={section}
          expanded={expandedSections.has(sectionKey)}
          config={config}
          level={level}
          scope={scope}
          onToggle={() => toggleSection(sectionKey)}
          onChange={onChange}
        />
      ))}
    </Box>
  );
}

function ConfigSection({ section, expanded, config, level, scope, onToggle, onChange }: SectionProps) {
  return (
    <Accordion expanded={expanded} onChange={onToggle}>
      <AccordionSummary>
        <Typography variant="subtitle1">{section.title}</Typography>
        <Typography variant="body2" color="text.secondary">
          {section.description}
        </Typography>
      </AccordionSummary>

      <AccordionDetails>
        <Stack spacing={2}>
          {section.keys.map(configKey => (
            <ConfigKeyEditor
              key={configKey.key}
              configKey={configKey}
              value={config?.[configKey.key]}
              level={level}
              scope={scope}
              onChange={(key, value) => onChange(key, value)}
            />
          ))}
        </Stack>
      </AccordionDetails>
    </Accordion>
  );
}

function ConfigKeyEditor({ configKey, value, level, scope, onChange }: KeyEditorProps) {
  const [localValue, setLocalValue] = useState(value?.value);
  const [showHierarchy, setShowHierarchy] = useState(false);

  const hierarchyData = value?.hierarchy || [];
  const isOverridden = hierarchyData.length > 1;

  return (
    <Box sx={{ border: '1px solid', borderColor: 'divider', p: 2, borderRadius: 1 }}>
      <Stack direction="row" justifyContent="space-between" alignItems="center">
        <Typography variant="subtitle2">
          {configKey.label}
          {isOverridden && (
            <Chip size="small" label="Overridden" color="warning" sx={{ ml: 1 }} />
          )}
        </Typography>

        <IconButton
          size="small"
          onClick={() => setShowHierarchy(!showHierarchy)}
        >
          <HierarchyIcon />
        </IconButton>
      </Stack>

      <Typography variant="body2" color="text.secondary" sx={{ mb: 1 }}>
        {configKey.description}
      </Typography>

      <ConfigValueInput
        type={configKey.type}
        value={localValue}
        onChange={setLocalValue}
        options={configKey.options}
      />

      {showHierarchy && (
        <ConfigHierarchyDisplay
          hierarchy={hierarchyData}
          currentLevel={level}
          currentScope={scope}
        />
      )}

      <Stack direction="row" spacing={1} sx={{ mt: 1 }}>
        <Button
          size="small"
          variant="contained"
          onClick={() => onChange(configKey.key, localValue)}
          disabled={localValue === value?.value}
        >
          Save
        </Button>

        <Button
          size="small"
          variant="outlined"
          onClick={() => setLocalValue(value?.value)}
        >
          Reset
        </Button>

        {isOverridden && (
          <Button
            size="small"
            variant="outlined"
            color="warning"
            onClick={() => removeOverride(configKey.key)}
          >
            Remove Override
          </Button>
        )}
      </Stack>
    </Box>
  );
}
```

### Effective Configuration Preview
```typescript
function ConfigPreviewPanel({ user, config, showEffectiveConfig }: PreviewProps) {
  const [effectiveConfig, setEffectiveConfig] = useState<EffectiveConfig>();
  const [previewUser, setPreviewUser] = useState<User>(user);

  // Show what configuration would be effective for different users
  return (
    <ResponsiveCard title="Configuration Preview">
      <Typography variant="subtitle1" sx={{ mb: 2 }}>
        Preview effective configuration for different user types
      </Typography>

      <UserContextSelector
        selectedUser={previewUser}
        onChange={setPreviewUser}
        availableUsers={getPreviewUsers()}
      />

      <Divider sx={{ my: 2 }} />

      <EffectiveConfigDisplay
        user={previewUser}
        config={effectiveConfig}
        highlightChanges={true}
      />

      <Alert severity="info" sx={{ mt: 2 }}>
        This preview shows how configuration inheritance would affect different user types.
        Changes are not applied until you save the configuration.
      </Alert>
    </ResponsiveCard>
  );
}
```

## Performance Considerations

### Caching Strategy
```python
# Multi-level caching for configuration
class ConfigCache:
    """Redis-backed configuration cache with intelligent invalidation"""

    def __init__(self):
        self.redis = Redis(connection_pool=redis_pool)
        self.local_cache = {}  # In-memory cache for frequently accessed keys

    async def get(self, cache_key: str) -> Optional[ConfigValue]:
        """Get from cache with local + Redis fallback"""

        # Check local cache first (fastest)
        if cache_key in self.local_cache:
            local_value, expires_at = self.local_cache[cache_key]
            if expires_at > time.time():
                return local_value

        # Check Redis cache
        redis_value = await self.redis.get(cache_key)
        if redis_value:
            config_value = pickle.loads(redis_value)

            # Update local cache
            self.local_cache[cache_key] = (config_value, time.time() + 60)  # 1 minute local cache

            return config_value

        return None

    async def set(self, cache_key: str, config_value: ConfigValue, ttl: int = 300):
        """Set in both local and Redis cache"""

        # Set in Redis with TTL
        await self.redis.setex(cache_key, ttl, pickle.dumps(config_value))

        # Set in local cache with shorter TTL
        self.local_cache[cache_key] = (config_value, time.time() + min(ttl, 60))

    async def invalidate_pattern(self, pattern: str):
        """Invalidate cache keys matching pattern"""

        # Clear local cache
        keys_to_remove = [k for k in self.local_cache.keys() if fnmatch.fnmatch(k, pattern)]
        for key in keys_to_remove:
            del self.local_cache[key]

        # Clear Redis cache
        redis_keys = await self.redis.keys(pattern)
        if redis_keys:
            await self.redis.delete(*redis_keys)
```

### Database Optimization
```sql
-- Indexes for fast configuration lookup
CREATE INDEX idx_config_tenant_key ON config_tenant(tenant_id, key);
CREATE INDEX idx_config_department_key ON config_department(tenant_id, department, key);
CREATE INDEX idx_config_group_key ON config_group(group_id, key);
CREATE INDEX idx_config_user_key ON config_user(user_id, key);

-- Partial indexes for encrypted values
CREATE INDEX idx_config_global_encrypted ON config_global(key) WHERE encrypted = true;
CREATE INDEX idx_config_tenant_encrypted ON config_tenant(tenant_id, key) WHERE encrypted = true;

-- Index for audit queries
CREATE INDEX idx_config_audit_user_time ON config_audit(changed_by, changed_at DESC);
CREATE INDEX idx_config_audit_key_time ON config_audit(key, changed_at DESC);
```

## Security Considerations

### Encryption at Rest
```python
# Encrypt sensitive configuration values
class ConfigEncryption:
    """Encrypt/decrypt sensitive configuration values"""

    def __init__(self):
        # Use platform's encryption key management
        self.encryption_key = self._get_encryption_key()
        self.fernet = Fernet(self.encryption_key)

    def encrypt(self, value: str) -> str:
        """Encrypt configuration value"""
        encrypted_bytes = self.fernet.encrypt(value.encode())
        return base64.b64encode(encrypted_bytes).decode()

    def decrypt(self, encrypted_value: str) -> str:
        """Decrypt configuration value"""
        encrypted_bytes = base64.b64decode(encrypted_value.encode())
        decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
        return decrypted_bytes.decode()

    def _get_encryption_key(self) -> bytes:
        """Get encryption key from secure storage"""
        # In production, this would come from HSM, Key Vault, etc.
        key_material = os.getenv('CONFIG_ENCRYPTION_KEY')
        if not key_material:
            raise ValueError("CONFIG_ENCRYPTION_KEY not set")

        return base64.urlsafe_b64decode(key_material)
```

### Access Control
```python
# Configuration access control using traits
def require_config_access(level: str, operation: str):
    """Decorator to control configuration access"""
    def decorator(func):
        def wrapper(request: Request, *args, **kwargs):
            user = request.state.user

            # Check base configuration permission
            if not user.has_trait('admin_capable'):
                raise HTTPException(403, "Configuration access requires admin privileges")

            # Level-specific permissions
            if level == 'global' and not user.has_trait('super_admin'):
                raise HTTPException(403, "Global configuration requires super admin")

            if level == 'tenant' and not user.has_trait('tenant_admin'):
                if user.tenant_id != kwargs.get('tenant_id'):
                    raise HTTPException(403, "Cannot modify other tenant's configuration")

            # Operation-specific permissions
            if operation == 'write' and not user.has_trait('config_write'):
                raise HTTPException(403, "Configuration write access denied")

            return func(request, *args, **kwargs)
        return wrapper
    return decorator

# Usage
@require_config_access('tenant', 'write')
def update_tenant_config(request: Request, tenant_id: str, config_data: Dict):
    pass
```

## Expected Outcomes

### Scalability Achievements
1. **Multi-Tenant Support**: Each hospital/organization gets isolated configuration
2. **Departmental Flexibility**: Marketing and medical departments have different settings
3. **User Customization**: Individual users can override group/department settings
4. **Real-time Updates**: Configuration changes without restart
5. **Delegation**: Department admins can manage their own settings

### User Experience Improvements
1. **Contextual Configuration**: Users only see relevant settings
2. **Visual Hierarchy**: Clear understanding of where settings come from
3. **Bulk Operations**: Templates and bulk configuration management
4. **Audit Trail**: Complete history of who changed what when
5. **Preview System**: See configuration impact before applying

### Operational Benefits
1. **No More Restarts**: Live configuration updates
2. **Tenant Isolation**: One platform, multiple organizations
3. **Compliance Flexibility**: HIPAA and non-HIPAA users coexist
4. **Performance**: Cached configuration with sub-millisecond lookup
5. **Security**: Encrypted sensitive values, access-controlled changes

## Migration Timeline

### Week 1-2: Foundation
- Create database schema and migrations
- Implement PostgreSQL configuration provider
- Build caching layer with Redis
- Create hybrid .env/database system

### Week 3-4: Migration Tools
- Build .env import utilities
- Create tenant provisioning system
- Implement configuration templates
- Test migration with existing installations

### Week 5-6: UI Development
- Build hierarchical configuration management interface
- Create user-friendly configuration editors
- Implement preview and comparison tools
- Add audit trail visualization

### Week 7-8: Integration
- Update all plugins to use hierarchical configuration
- Modify Admin Console to show user-specific settings
- Implement trait-based configuration access
- Performance optimization and caching tuning

## Conclusion

This hierarchical configuration system solves the fundamental scaling problems that prevent Faxbot from serving large, complex organizations. By implementing configuration as a plugin with proper inheritance, caching, and security, the platform can support hundreds of users across multiple hospitals while maintaining security and compliance.

**Key Innovation**: Configuration becomes a foundational service that enables true multi-tenancy, user-specific experiences, and enterprise-grade flexibility while maintaining the simplicity that makes Faxbot approachable for smaller deployments.