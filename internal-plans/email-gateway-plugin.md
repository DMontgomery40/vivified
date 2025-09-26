# Email Gateway Plugin Architecture - The Perfect Plugin Example

## Executive Summary

The Email Gateway plugin demonstrates the full power of Faxbot's plugin architecture. It implements email-to-fax and fax-to-email functionality while leveraging all core platform services: security, HIPAA compliance, trait-based permissions, canonical models, and hierarchical configuration.

**Key Innovation**: A complex, multi-component feature implemented as a pure plugin without any core modifications, showcasing the platform's extensibility.

## Plugin Overview

### Manifest Definition
```json
{
  "id": "email_gateway",
  "version": "1.0.0",
  "type": "communication_channel",
  "name": "Email Gateway",
  "description": "Bidirectional email-to-fax and fax-to-email communication",

  "core_version_required": ">=3.0.0",
  "plugin_api_version": "1.0",

  "contracts": [
    "communication_channel:1.0",
    "background_worker:1.0"
  ],

  "dependencies": {
    "identity_provider": ">=1.0",
    "config_provider": ">=1.0",
    "storage_provider": ">=1.0"
  },

  "canonical_models": {
    "input": ["CanonicalMessage", "CanonicalIdentity", "CanonicalContent"],
    "output": ["DeliveryStatus", "CanonicalMessage", "ProcessingEvent"]
  },

  "traits": {
    "provides": ["email_capable", "async_delivery", "attachment_processing"],
    "requires": ["internet_access"],
    "optional": ["hipaa_compliant"],
    "conflicts": ["offline_only"]
  },

  "permissions": {
    "send_via_email": {
      "default_unix": "664",
      "default_windows": "modify",
      "description": "Send faxes via email",
      "required_traits": ["email_capable", "fax_capable"]
    },
    "receive_via_email": {
      "default_unix": "644",
      "default_windows": "read_execute",
      "description": "Receive faxes via email",
      "required_traits": ["email_capable"]
    },
    "configure_email": {
      "default_unix": "600",
      "default_windows": "full_control",
      "description": "Configure email gateway settings",
      "required_traits": ["email_capable", "admin_capable"]
    }
  },

  "configuration_schema": {
    "oauth_provider": {
      "type": "string",
      "enum": ["gmail", "outlook"],
      "default": "gmail",
      "ui_component": "select",
      "traits": ["requires_oauth"]
    },
    "poll_interval": {
      "type": "integer",
      "default": 60,
      "minimum": 30,
      "maximum": 3600,
      "ui_component": "slider",
      "traits": ["performance_setting"]
    },
    "allowed_senders": {
      "type": "array",
      "items": {"type": "string", "format": "email"},
      "ui_component": "email_list",
      "traits": ["security_setting"]
    },
    "inbound_distribution": {
      "type": "array",
      "items": {"type": "string", "format": "email"},
      "ui_component": "email_list",
      "traits": ["notification_setting"]
    }
  },

  "background_workers": [
    {
      "name": "email_processor",
      "interval": 60,
      "description": "Process incoming emails for fax conversion"
    },
    {
      "name": "oauth_token_refresher",
      "interval": 1800,
      "description": "Refresh OAuth tokens before expiration"
    }
  ],

  "ui_components": {
    "settings": {
      "component": "/plugins/email_gateway/ui/SettingsPanel.tsx",
      "traits": ["admin_capable", "email_capable"]
    },
    "dashboard": {
      "component": "/plugins/email_gateway/ui/DashboardWidget.tsx",
      "traits": ["email_capable"]
    },
    "status": {
      "component": "/plugins/email_gateway/ui/StatusIndicator.tsx",
      "traits": ["email_capable"]
    }
  },

  "database_migrations": [
    "001_create_email_events.sql",
    "002_create_oauth_tokens.sql",
    "003_create_email_config.sql"
  ],

  "compliance": {
    "hipaa_ready": false,
    "hipaa_restrictions": {
      "enabled": false,
      "message": "Email Gateway disabled in HIPAA mode. Enhanced security available in Phase 2."
    },
    "audit_level": "standard",
    "data_retention": {
      "email_metadata": "30d",
      "oauth_tokens": "indefinite",
      "processing_logs": "90d"
    }
  }
}
```

## Core Integration Architecture

### Plugin Initialization
```python
# api/app/plugins/communication/email_gateway/plugin.py
from api.app.plugins.base import CommunicationChannelPlugin
from api.app.canonical import CanonicalMessage, CanonicalIdentity, CanonicalContent
from api.app.plugins.communication.email_gateway.oauth import OAuthManager
from api.app.plugins.communication.email_gateway.processor import EmailProcessor

class EmailGatewayPlugin(CommunicationChannelPlugin):
    """Email Gateway plugin implementation"""

    def __init__(self,
                 identity_provider: IdentityProvider,
                 config_provider: ConfigProvider,
                 storage_provider: StorageProvider):
        super().__init__()

        # Core dependencies injected by platform
        self.identity = identity_provider
        self.config = config_provider
        self.storage = storage_provider

        # Plugin components
        self.oauth_manager = OAuthManager(config_provider)
        self.email_processor = EmailProcessor(self, storage_provider)

        # Core integration
        self.security_core = SecurityCore()
        self.audit_logger = AuditLogger()
        self.trait_engine = TraitEngine()

    async def initialize(self) -> bool:
        """Initialize plugin with core platform services"""
        try:
            # Register with core platform
            self.core_platform.register_plugin(self)

            # Initialize OAuth configuration
            await self.oauth_manager.initialize()

            # Start background workers
            await self.start_background_workers()

            # Register canonical model transformers
            self.register_canonical_transformers()

            audit_event('plugin_initialized', plugin_id='email_gateway')
            return True

        except Exception as e:
            audit_event('plugin_initialization_failed',
                       plugin_id='email_gateway',
                       error=str(e))
            return False

    def register_canonical_transformers(self):
        """Register message format transformers"""
        # Email -> Canonical Message
        self.core_platform.canonical_router.register_transformer(
            'email', 'canonical', self.email_to_canonical
        )

        # Canonical Message -> Fax Job
        self.core_platform.canonical_router.register_transformer(
            'canonical', 'fax_job', self.canonical_to_fax_job
        )

        # Fax Status -> Email Reply
        self.core_platform.canonical_router.register_transformer(
            'fax_status', 'email_reply', self.status_to_email_reply
        )
```

### Trait-Based Functionality
```python
# Email processing with trait-based restrictions
class EmailProcessor:
    def __init__(self, plugin: EmailGatewayPlugin, storage: StorageProvider):
        self.plugin = plugin
        self.storage = storage
        self.trait_engine = TraitEngine()

    async def process_incoming_email(self, email_data: Dict) -> ProcessingResult:
        """Process incoming email with trait-based security"""
        # Extract sender identity
        sender_identity = CanonicalIdentity(
            type='email',
            value=email_data['from'],
            verified=False,
            traits=['external', 'unverified']
        )

        # Check sender authorization
        if not await self._authorize_sender(sender_identity):
            audit_event('email_sender_rejected',
                       sender=email_data['from'],
                       reason='not_authorized')
            return ProcessingResult(
                success=False,
                error="Sender not authorized for email-to-fax"
            )

        # Parse email into canonical message
        canonical_msg = await self.email_to_canonical(email_data)

        # Apply trait-based processing rules
        processing_traits = await self._determine_processing_traits(
            canonical_msg, sender_identity
        )

        # HIPAA users cannot process emails (Phase 1 restriction)
        if 'hipaa_compliant' in processing_traits:
            audit_event('email_processing_blocked',
                       reason='hipaa_mode_restriction',
                       sender=email_data['from'])
            await self._send_error_reply(
                sender_identity,
                "Email-to-fax disabled in HIPAA mode. Please use direct fax transmission."
            )
            return ProcessingResult(
                success=False,
                error="HIPAA mode restriction"
            )

        # Non-HIPAA users can process emails freely
        return await self._process_message(canonical_msg, processing_traits)

    async def _authorize_sender(self, sender: CanonicalIdentity) -> bool:
        """Check if sender is authorized based on configuration and traits"""
        # Get allowed senders from config
        allowed_senders = await self.plugin.config.get(
            'email_gateway.allowed_senders',
            namespace='plugins',
            default=[]
        )

        # If no restrictions, allow all (non-HIPAA mode)
        if not allowed_senders:
            return True

        # Check against patterns
        sender_email = sender.value
        for pattern in allowed_senders:
            if self._matches_pattern(sender_email, pattern):
                return True

        return False

    async def _determine_processing_traits(self,
                                         message: CanonicalMessage,
                                         sender: CanonicalIdentity) -> List[str]:
        """Determine traits for processing this message"""
        traits = ['email_originated']

        # Check for PHI indicators (future: use core PHI detection)
        if await self._contains_potential_phi(message):
            traits.extend(['potential_phi', 'requires_hipaa'])

        # Check sender traits
        if sender.traits:
            traits.extend(sender.traits)

        # Add contextual traits
        if self._is_business_hours():
            traits.append('business_hours')

        return traits

    async def email_to_canonical(self, email_data: Dict) -> CanonicalMessage:
        """Transform email to canonical message format"""
        # Parse destination number from subject/body
        destination = self._parse_destination(
            email_data['subject'],
            email_data['body']
        )

        if not destination:
            raise ValueError("No valid fax destination found in email")

        # Process attachments
        canonical_attachments = []
        for attachment in email_data.get('attachments', []):
            if not self._is_allowed_attachment(attachment):
                continue

            canonical_content = CanonicalContent(
                type='document',
                format=attachment['content_type'],
                data=attachment['data'],
                metadata={
                    'filename': attachment['filename'],
                    'size_bytes': len(attachment['data']),
                    'source': 'email_attachment'
                },
                traits=['user_uploaded', 'email_originated']
            )

            # Apply core security validation
            if not self.plugin.security_core.validate_content(canonical_content):
                raise ValueError(f"Attachment {attachment['filename']} failed security validation")

            canonical_attachments.append(canonical_content)

        # Create canonical message
        canonical_message = CanonicalMessage(
            id=generate_uuid(),
            sender=CanonicalIdentity(
                type='email',
                value=email_data['from'],
                verified=False,
                traits=['external']
            ),
            recipient=CanonicalIdentity(
                type='phone',
                value=destination,
                verified=False,
                traits=['fax_number']
            ),
            content=canonical_attachments[0] if canonical_attachments else None,
            metadata={
                'email_subject': email_data['subject'],
                'email_message_id': email_data['message_id'],
                'attachment_count': len(canonical_attachments),
                'processing_timestamp': datetime.utcnow().isoformat()
            },
            traits=['email_originated', 'requires_processing'],
            timestamp=datetime.utcnow()
        )

        # Core security validation
        if not self.plugin.security_core.validate_message(canonical_message):
            raise ValueError("Message failed core security validation")

        return canonical_message
```

### Configuration Integration
```python
# Hierarchical configuration with trait-based access
class EmailGatewayConfig:
    def __init__(self, config_provider: ConfigProvider):
        self.config = config_provider

    async def get_oauth_config(self, user_context: UserContext) -> Dict:
        """Get OAuth configuration with user-specific overrides"""
        # Start with global defaults
        base_config = await self.config.get(
            'email_gateway.oauth',
            namespace='global',
            default={
                'provider': 'gmail',
                'scopes': ['gmail.readonly', 'gmail.send']
            }
        )

        # Apply tenant-level overrides
        if user_context.tenant_id:
            tenant_config = await self.config.get(
                'email_gateway.oauth',
                namespace=f'tenant:{user_context.tenant_id}',
                default={}
            )
            base_config.update(tenant_config)

        # Apply group-level overrides
        for group in user_context.groups:
            group_config = await self.config.get(
                'email_gateway.oauth',
                namespace=f'group:{group}',
                default={}
            )
            base_config.update(group_config)

        # Apply user-level overrides
        user_config = await self.config.get(
            'email_gateway.oauth',
            namespace=f'user:{user_context.user_id}',
            default={}
        )
        base_config.update(user_config)

        return base_config

    async def get_processing_rules(self, user_traits: List[str]) -> Dict:
        """Get processing rules based on user traits"""
        # HIPAA users get restricted rules
        if 'hipaa_compliant' in user_traits:
            return {
                'enabled': False,
                'reason': 'hipaa_mode_restriction',
                'alternative': 'Use direct fax transmission for PHI'
            }

        # Non-HIPAA users get full functionality
        return {
            'enabled': True,
            'max_attachment_size_mb': 10,
            'allowed_file_types': ['pdf', 'txt'],
            'poll_interval_seconds': 60,
            'rate_limit_per_hour': 100
        }
```

### UI Components with Trait Adaptation

#### Settings Panel
```typescript
// api/app/plugins/communication/email_gateway/ui/SettingsPanel.tsx
import React from 'react';
import { useTraitBasedUI } from '@/hooks/useTraitBasedUI';
import { ResponsiveCard, ResponsiveFormSection } from '@/components/common';

interface EmailGatewaySettingsProps {
  user: User;
  config: ConfigProvider;
  onSave: (config: EmailConfig) => Promise<void>;
}

export default function EmailGatewaySettings({
  user,
  config,
  onSave
}: EmailGatewaySettingsProps) {
  const uiContext = useTraitBasedUI(user);
  const [emailConfig, setEmailConfig] = useState<EmailConfig>();

  // Trait-based feature availability
  const canConfigureEmail = user.traits.includes('admin_capable') &&
                           user.traits.includes('email_capable');
  const isHIPAAUser = user.traits.includes('hipaa_compliant');

  if (!canConfigureEmail) {
    return (
      <Alert severity="warning">
        You don't have permission to configure the email gateway.
        Required traits: admin_capable, email_capable
      </Alert>
    );
  }

  if (isHIPAAUser) {
    return (
      <ResponsiveCard title="Email Gateway - HIPAA Mode">
        <Alert severity="warning" sx={{ mb: 2 }}>
          <Typography variant="h6">Email Gateway Disabled</Typography>
          <Typography variant="body2">
            Email-to-fax functionality is disabled in HIPAA mode to ensure PHI security.
            This feature will be available in Phase 2 with enhanced encryption and audit controls.
          </Typography>
        </Alert>

        <Typography variant="body2" color="text.secondary">
          Alternative: Use direct fax transmission through the main fax interface.
        </Typography>

        <Button
          variant="outlined"
          onClick={() => window.open(`${uiContext.docsBase}/hipaa/email-restrictions`)}
          sx={{ mt: 2 }}
        >
          Learn About HIPAA Email Restrictions
        </Button>
      </ResponsiveCard>
    );
  }

  // Non-HIPAA users get full configuration interface
  return (
    <ResponsiveCard title="Email Gateway Configuration">
      <ResponsiveFormSection
        title="OAuth Provider"
        subtitle="Connect your email account for gateway access"
      >
        <OAuthProviderSelector
          value={emailConfig?.oauth_provider}
          onChange={(provider) => updateConfig('oauth_provider', provider)}
          options={[
            { value: 'gmail', label: 'Gmail / Google Workspace' },
            { value: 'outlook', label: 'Outlook / Microsoft 365' }
          ]}
        />

        <OAuthStatusIndicator
          provider={emailConfig?.oauth_provider}
          status={emailConfig?.oauth_status}
        />
      </ResponsiveFormSection>

      <ResponsiveFormSection
        title="Email Processing"
        subtitle="Configure how emails are processed for fax transmission"
      >
        <AllowedSendersList
          senders={emailConfig?.allowed_senders}
          onChange={(senders) => updateConfig('allowed_senders', senders)}
          helperText="Leave empty to allow all senders (not recommended for production)"
        />

        <PollIntervalSlider
          value={emailConfig?.poll_interval}
          onChange={(interval) => updateConfig('poll_interval', interval)}
          min={30}
          max={3600}
          step={30}
          helperText="How often to check for new emails (seconds)"
        />
      </ResponsiveFormSection>

      <ResponsiveFormSection
        title="Inbound Distribution"
        subtitle="Configure where received faxes are sent via email"
      >
        <DistributionList
          recipients={emailConfig?.inbound_distribution}
          onChange={(recipients) => updateConfig('inbound_distribution', recipients)}
          helperText="Email addresses to receive inbound faxes"
        />
      </ResponsiveFormSection>

      <Box sx={{ display: 'flex', justifyContent: 'space-between', mt: 3 }}>
        <Button
          variant="outlined"
          onClick={() => window.open(`${uiContext.docsBase}/plugins/email-gateway`)}
        >
          📚 Setup Guide
        </Button>

        <Button
          variant="contained"
          onClick={() => onSave(emailConfig)}
          disabled={!isConfigValid(emailConfig)}
        >
          Save Configuration
        </Button>
      </Box>
    </ResponsiveCard>
  );
}
```

#### Dashboard Widget
```typescript
// Trait-aware dashboard widget
export default function EmailGatewayDashboard({ user }: { user: User }) {
  const uiContext = useTraitBasedUI(user);
  const isHIPAAUser = user.traits.includes('hipaa_compliant');
  const canUseEmail = user.traits.includes('email_capable');

  if (!canUseEmail) {
    return null; // Don't show widget if user can't use email
  }

  if (isHIPAAUser) {
    return (
      <DashboardWidget title="Email Gateway" color="warning">
        <Typography variant="body2">
          Disabled in HIPAA mode for security
        </Typography>
        <Chip label="HIPAA Restricted" size="small" color="warning" />
      </DashboardWidget>
    );
  }

  return (
    <DashboardWidget title="Email Gateway" color="success">
      <EmailGatewayStats user={user} />
      <QuickActions user={user} />
    </DashboardWidget>
  );
}
```

## Background Processing Architecture

### Email Polling Worker
```python
# Background worker using core platform worker system
class EmailPollingWorker(BackgroundWorker):
    def __init__(self, email_plugin: EmailGatewayPlugin):
        super().__init__(
            name='email_processor',
            interval=60,  # From plugin config
            plugin_id='email_gateway'
        )
        self.plugin = email_plugin

    async def execute(self, context: WorkerContext) -> WorkerResult:
        """Execute email polling cycle with full core integration"""
        try:
            # Check if plugin is enabled
            enabled = await self.plugin.config.get(
                'email_gateway.enabled',
                namespace='global',
                default=False
            )

            if not enabled:
                return WorkerResult(success=True, message="Plugin disabled")

            # Get OAuth tokens for all configured accounts
            oauth_accounts = await self._get_active_oauth_accounts()

            results = []
            for account in oauth_accounts:
                # Check account traits and permissions
                if not await self._can_process_account(account):
                    continue

                # Process emails for this account
                account_result = await self._process_account_emails(account)
                results.append(account_result)

            # Update worker metrics
            await self._update_metrics(results)

            return WorkerResult(
                success=True,
                message=f"Processed {len(results)} accounts",
                data={'account_results': results}
            )

        except Exception as e:
            audit_event('email_worker_failed', error=str(e))
            return WorkerResult(success=False, error=str(e))

    async def _process_account_emails(self, account: OAuthAccount) -> Dict:
        """Process emails for single account"""
        try:
            # Get user context for this account
            user = await self.plugin.identity.get_user(account.user_id)
            if not user:
                return {'account': account.email, 'error': 'User not found'}

            # Check user traits - HIPAA users cannot process emails
            if user.has_trait('hipaa_compliant'):
                return {
                    'account': account.email,
                    'skipped': True,
                    'reason': 'hipaa_restriction'
                }

            # Connect to email provider
            email_client = await self._get_email_client(account)

            # Get new messages since last poll
            new_messages = await email_client.get_new_messages(
                since=account.last_poll_time
            )

            processed_messages = []
            for message in new_messages:
                try:
                    # Process individual email
                    result = await self.plugin.email_processor.process_incoming_email(
                        message,
                        user_context=user
                    )
                    processed_messages.append(result)

                    # Core audit logging
                    audit_event('email_processed',
                               user_id=user.id,
                               account=account.email,
                               message_id=message['message_id'],
                               result=result.status)

                except Exception as e:
                    # Individual message failure doesn't fail the whole batch
                    audit_event('email_processing_failed',
                               user_id=user.id,
                               account=account.email,
                               message_id=message.get('message_id'),
                               error=str(e))
                    continue

            # Update last poll time
            account.last_poll_time = datetime.utcnow()
            await self._save_account_state(account)

            return {
                'account': account.email,
                'messages_found': len(new_messages),
                'messages_processed': len(processed_messages),
                'success': True
            }

        except Exception as e:
            audit_event('account_processing_failed',
                       account=account.email,
                       error=str(e))
            return {
                'account': account.email,
                'error': str(e),
                'success': False
            }
```

## Integration with Core Fax System

### Message Routing
```python
# Route canonical messages through core platform
class EmailToFaxRouter:
    def __init__(self, core_platform: CorePlatform):
        self.core = core_platform

    async def route_email_to_fax(self,
                                canonical_msg: CanonicalMessage,
                                user_context: UserContext) -> RoutingResult:
        """Route email-originated message to fax system"""

        # Use core platform's canonical router
        try:
            # Transform canonical message to fax job format
            fax_job_data = await self.core.canonical_router.transform(
                source_format='canonical_message',
                target_format='fax_job_request',
                data=canonical_msg,
                context=user_context
            )

            # Submit to core fax system (existing /fax endpoint)
            fax_result = await self.core.fax_service.create_job(
                job_data=fax_job_data,
                user_context=user_context
            )

            # Transform result back to canonical format
            canonical_result = await self.core.canonical_router.transform(
                source_format='fax_job_result',
                target_format='canonical_delivery_status',
                data=fax_result,
                context=user_context
            )

            return RoutingResult(
                success=True,
                canonical_result=canonical_result,
                fax_job_id=fax_result.job_id
            )

        except Exception as e:
            audit_event('email_to_fax_routing_failed',
                       user_id=user_context.user_id,
                       canonical_message_id=canonical_msg.id,
                       error=str(e))

            return RoutingResult(
                success=False,
                error=str(e)
            )
```

## HIPAA Compliance Integration

### Phase 1: Disabled for HIPAA Users
```python
class HIPAAComplianceEnforcer:
    """Enforce HIPAA restrictions for email gateway"""

    def check_email_gateway_access(self, user: User, operation: str) -> ComplianceResult:
        """Check if user can perform email gateway operations"""

        if user.has_trait('hipaa_compliant'):
            # HIPAA users cannot use email gateway in Phase 1
            return ComplianceResult(
                allowed=False,
                reason='hipaa_mode_restriction',
                message='Email gateway disabled in HIPAA mode for PHI security',
                alternative='Use direct fax transmission',
                documentation_url='/docs/hipaa/email-restrictions'
            )

        if user.has_trait('phi_authorized') and operation == 'send_phi':
            # Users authorized for PHI cannot send PHI via email
            return ComplianceResult(
                allowed=False,
                reason='phi_security_restriction',
                message='PHI cannot be transmitted via email',
                alternative='Use secure fax transmission for PHI'
            )

        # Non-HIPAA users can use email gateway freely
        return ComplianceResult(allowed=True)

    def validate_email_content(self, content: CanonicalContent) -> ValidationResult:
        """Validate email content for potential PHI"""

        # Use core platform's PHI detection
        phi_detected = self.core.phi_detector.scan_content(content)

        if phi_detected.risk_score > 0.5:
            return ValidationResult(
                valid=False,
                risk_score=phi_detected.risk_score,
                detected_types=phi_detected.types,
                recommendation='Use secure fax for potential PHI content'
            )

        return ValidationResult(valid=True)
```

## Database Schema (Plugin-Managed)

```sql
-- Plugin-managed database tables
CREATE TABLE email_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id TEXT UNIQUE NOT NULL,
    from_address TEXT NOT NULL,
    to_address TEXT NOT NULL,
    subject TEXT,
    processing_status TEXT DEFAULT 'received',
    fax_job_id UUID REFERENCES fax_jobs(id),
    user_id UUID REFERENCES users(id),
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    processed_at TIMESTAMP
);

CREATE TABLE email_oauth_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    provider TEXT NOT NULL,
    email_address TEXT NOT NULL,
    encrypted_access_token TEXT NOT NULL,
    encrypted_refresh_token TEXT,
    expires_at TIMESTAMP,
    scopes TEXT[],
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, provider, email_address)
);

CREATE TABLE email_processing_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id),
    date DATE NOT NULL,
    emails_processed INTEGER DEFAULT 0,
    fax_jobs_created INTEGER DEFAULT 0,
    processing_errors INTEGER DEFAULT 0,
    UNIQUE(user_id, date)
);
```

## Plugin Lifecycle Management

### Installation
```python
class EmailGatewayInstaller:
    """Handle plugin installation and setup"""

    async def install(self) -> InstallResult:
        """Install email gateway plugin"""
        try:
            # Run database migrations
            await self._run_migrations()

            # Create default configuration
            await self._create_default_config()

            # Register with core platform
            await self._register_with_core()

            # Initialize background workers
            await self._setup_background_workers()

            return InstallResult(success=True)

        except Exception as e:
            return InstallResult(success=False, error=str(e))

    async def _create_default_config(self):
        """Create default configuration hierarchy"""
        default_config = {
            'global': {
                'email_gateway': {
                    'enabled': False,  # Disabled by default
                    'oauth_provider': 'gmail',
                    'poll_interval': 60,
                    'max_attachment_size_mb': 10,
                    'allowed_file_types': ['pdf', 'txt']
                }
            }
        }

        await self.config.set_hierarchical(default_config)
```

### Uninstallation
```python
class EmailGatewayUninstaller:
    """Handle clean plugin removal"""

    async def uninstall(self, preserve_data: bool = True) -> UninstallResult:
        """Safely remove email gateway plugin"""
        try:
            # Stop background workers
            await self._stop_workers()

            # Revoke OAuth tokens (security)
            await self._revoke_oauth_tokens()

            # Remove configuration (optional)
            if not preserve_data:
                await self._remove_configuration()

            # Unregister from core
            await self._unregister_from_core()

            # Optionally remove database tables
            if not preserve_data:
                await self._drop_tables()

            return UninstallResult(success=True)

        except Exception as e:
            return UninstallResult(success=False, error=str(e))
```

## Testing Strategy

### Plugin-Specific Tests
```python
# Plugin tests using core testing framework
class TestEmailGatewayPlugin(PluginTestCase):
    """Comprehensive plugin testing"""

    def setUp(self):
        super().setUp()
        self.plugin = self.create_plugin('email_gateway')
        self.mock_user = self.create_test_user(traits=['email_capable', 'non_hipaa'])

    def test_hipaa_user_restriction(self):
        """HIPAA users cannot access email gateway"""
        hipaa_user = self.create_test_user(traits=['hipaa_compliant'])

        result = self.plugin.check_access(hipaa_user, 'configure_email')

        self.assertFalse(result.allowed)
        self.assertEqual(result.reason, 'hipaa_mode_restriction')

    def test_email_to_canonical_conversion(self):
        """Email messages convert to canonical format"""
        email_data = self.create_test_email(
            from_addr='test@example.com',
            subject='Fax to +15551234567',
            attachments=[self.create_test_pdf()]
        )

        canonical_msg = self.plugin.email_to_canonical(email_data)

        self.assertEqual(canonical_msg.recipient.type, 'phone')
        self.assertEqual(canonical_msg.recipient.value, '+15551234567')
        self.assertIn('email_originated', canonical_msg.traits)

    def test_trait_based_processing(self):
        """Processing adapts to user traits"""
        # Non-HIPAA user can process emails
        result = self.plugin.process_email(self.mock_user, self.create_test_email())
        self.assertTrue(result.success)

        # HIPAA user cannot process emails
        hipaa_user = self.create_test_user(traits=['hipaa_compliant'])
        result = self.plugin.process_email(hipaa_user, self.create_test_email())
        self.assertFalse(result.success)
        self.assertEqual(result.error, 'HIPAA mode restriction')
```

## Expected Outcomes

### For Non-HIPAA Users
1. **Full Email Integration**: Send faxes by emailing PDFs, receive faxes as email attachments
2. **OAuth Setup**: Easy connection to Gmail/Outlook accounts
3. **Flexible Configuration**: Customize sender restrictions, polling intervals
4. **Dashboard Integration**: Email gateway status and statistics
5. **Error Handling**: Clear feedback when emails cannot be processed

### For HIPAA Users
1. **Clear Restrictions**: Obvious messaging that email gateway is disabled
2. **Alternative Guidance**: Direction to use direct fax transmission
3. **Phase 2 Roadmap**: Information about enhanced security features coming
4. **No Confusion**: UI clearly adapted to their compliance requirements

### For Platform
1. **Plugin Demonstration**: Shows full plugin architecture capabilities
2. **Core Integration**: Demonstrates canonical models, traits, security integration
3. **Extensibility**: Proves complex features can be implemented as plugins
4. **Migration Path**: Shows evolution from core feature to plugin

## Conclusion

The Email Gateway plugin demonstrates the full power of Faxbot's plugin architecture. It implements a complex, multi-component feature while leveraging all core platform services and adapting to user traits and compliance requirements.

**Key Achievements**:
- Complex functionality as pure plugin
- Full integration with trait-based permissions
- HIPAA compliance enforcement through core platform
- Hierarchical configuration with user-specific overrides
- Canonical message transformation and routing
- Trait-aware UI that adapts to user context

This plugin proves that Faxbot's architecture can support sophisticated features while maintaining security, compliance, and modularity.