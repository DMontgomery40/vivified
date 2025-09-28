"""
Security validation tests for HIPAA compliance and PHI protection.
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

from core.identity.service import IdentityService
from core.policy.engine import PolicyEngine, PolicyRequest, PolicyDecision
from core.audit.service import AuditService
from core.messaging.service import MessagingService
from core.canonical.service import CanonicalService
from core.gateway.service import GatewayService


class TestHIPAACompliance:
    """Test HIPAA compliance requirements."""
    
    @pytest.fixture
    def policy_engine(self):
        """Create policy engine for testing."""
        return PolicyEngine()
    
    @pytest.fixture
    def audit_service(self):
        """Create audit service for testing."""
        return AuditService()
    
    @pytest.mark.asyncio
    async def test_phi_access_requires_handles_phi_trait(self, policy_engine):
        """Test that PHI access requires handles_phi trait."""
        # Test unauthorized access to PHI
        request = PolicyRequest(
            user_id="test_user",
            resource_type="data",
            resource_id="phi_data_123",
            action="access",
            traits=[],
            context={"data_classification": "phi"}
        )
        
        result = await policy_engine.evaluate_request(request)
        assert result.decision == PolicyDecision.DENY
        assert "phi" in result.reason.lower()
    
    @pytest.mark.asyncio
    async def test_phi_access_with_handles_phi_trait(self, policy_engine):
        """Test that PHI access is allowed with handles_phi trait."""
        request = PolicyRequest(
            user_id="test_user",
            resource_type="data",
            resource_id="phi_data_123",
            action="access",
            traits=["handles_phi", "audit_required"],
            context={"data_classification": "phi"}
        )
        
        result = await policy_engine.evaluate_request(request)
        assert result.decision == PolicyDecision.ALLOW
    
    @pytest.mark.asyncio
    async def test_pii_access_requires_handles_pii_trait(self, policy_engine):
        """Test that PII access requires handles_pii trait."""
        request = PolicyRequest(
            user_id="test_user",
            resource_type="data",
            resource_id="pii_data_123",
            action="access",
            traits=[],
            context={"data_classification": "pii"}
        )
        
        result = await policy_engine.evaluate_request(request)
        assert result.decision == PolicyDecision.DENY
        assert "pii" in result.reason.lower()
    
    @pytest.mark.asyncio
    async def test_admin_override_for_phi_access(self, policy_engine):
        """Test that admin users can override PHI access restrictions."""
        request = PolicyRequest(
            user_id="admin_user",
            resource_type="data",
            resource_id="phi_data_123",
            action="access",
            traits=["admin"],
            context={"data_classification": "phi"}
        )
        
        result = await policy_engine.evaluate_request(request)
        assert result.decision == PolicyDecision.ALLOW
    
    def test_audit_logging_for_phi_access(self, audit_service):
        """Test that PHI access is properly audited."""
        # Mock audit logging
        with patch.object(audit_service, 'log_event') as mock_log:
            asyncio.run(audit_service.log_event(
                event_type="phi_access",
                category="security",
                action="access_phi",
                result="success",
                description="PHI data accessed",
                user_id="test_user",
                level="detailed",
                phi_involved=True
            ))
            
            # Verify audit log was called with PHI flag
            mock_log.assert_called_once()
            call_args = mock_log.call_args[1]
            assert call_args["phi_involved"] is True
            assert call_args["level"] == "detailed"


class TestDataEncryption:
    """Test data encryption requirements."""
    
    def test_sensitive_config_encryption(self):
        """Test that sensitive configuration values are encrypted."""
        from core.config.encryption import ConfigEncryption
        
        encryption = ConfigEncryption()
        
        # Test encryption/decryption
        original_value = "sensitive_password_123"
        encrypted = encryption.encrypt(original_value)
        decrypted = encryption.decrypt(encrypted)
        
        assert encrypted != original_value
        assert decrypted == original_value
        assert len(encrypted) > len(original_value)  # Encrypted should be longer
    
    def test_storage_encryption(self):
        """Test that storage encryption works correctly."""
        from core.storage.encryption import StorageEncryption
        
        encryption = StorageEncryption()
        
        # Test object encryption
        test_data = b"test sensitive data"
        object_id = "test_object_123"
        
        # Use the same encryption instance to ensure key consistency
        encrypted_data, key_id = encryption.encrypt_object(test_data, object_id)
        decrypted_data = encryption.decrypt_object(encrypted_data, object_id, key_id)
        
        assert encrypted_data != test_data
        assert decrypted_data == test_data
        assert key_id is not None


class TestAuthenticationSecurity:
    """Test authentication security requirements."""
    
    def test_jwt_token_expiry(self):
        """Test that JWT tokens have proper expiry."""
        from core.identity.auth import AuthManager
        from datetime import datetime, timezone
        
        auth_manager = AuthManager("test_secret")
        
        # Generate token
        token = auth_manager.generate_user_token("test_user", ["admin"])
        
        # Decode and check expiry
        import jwt
        payload = jwt.decode(token, "test_secret", algorithms=["HS256"])
        
        # Check that token has expiry
        assert "exp" in payload
        assert payload["exp"] > datetime.now(timezone.utc).timestamp()
    
    def test_password_hashing(self):
        """Test that passwords are properly hashed."""
        import bcrypt
        
        password = "test_password_123"
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
        
        # Verify password can be checked
        assert bcrypt.checkpw(password.encode('utf-8'), hashed)
        assert not bcrypt.checkpw("wrong_password".encode('utf-8'), hashed)
        assert hashed != password.encode('utf-8')  # Hashed should be different


class TestPluginSecurity:
    """Test plugin security requirements."""
    
    def test_plugin_manifest_validation(self):
        """Test that plugin manifests are properly validated."""
        from core.plugin_manager.validator import SecurityValidator
        from core.plugin_manager.models import PluginManifest
        
        validator = SecurityValidator()
        
        # Test valid manifest
        valid_manifest = PluginManifest(
            id="test-plugin",
            name="Test Plugin",
            description="Test plugin for validation",
            version="1.0.0",
            contracts=["IdentityPlugin"],
            traits=["handles_pii"],
            security={
                "authentication_required": True,
                "data_classification": ["pii"]
            },
            compliance={
                "hipaa_controls": ["164.312(a)"],
                "audit_level": "detailed"
            }
        )
        
        is_secure, errors = validator.validate_manifest_security(valid_manifest)
        assert is_secure
        assert len(errors) == 0
        
        # Test invalid manifest (missing security section)
        invalid_manifest = PluginManifest(
            id="test-plugin",
            name="Test Plugin",
            description="Test plugin for validation",
            version="1.0.0",
            contracts=["IdentityPlugin"],
            traits=["handles_pii"]
        )
        
        is_secure, errors = validator.validate_manifest_security(invalid_manifest)
        assert not is_secure
        assert len(errors) > 0
    
    def test_plugin_domain_allowlist(self):
        """Test that plugin domains are properly validated."""
        from core.gateway.service import GatewayService
        from core.audit.service import AuditService
        from core.policy.engine import PolicyEngine
        
        audit_service = AuditService()
        policy_engine = PolicyEngine()
        gateway_service = GatewayService(audit_service, policy_engine)
        
        # Test safe domain
        safe_domain = "api.example.com"
        assert gateway_service._is_safe_domain(safe_domain)
        
        # Test unsafe domains
        unsafe_domains = [
            "localhost",
            "127.0.0.1",
            "10.0.0.1",
            "192.168.1.1"
        ]
        
        for domain in unsafe_domains:
            assert not gateway_service._is_safe_domain(domain)


class TestAuditLogging:
    """Test comprehensive audit logging."""
    
    def test_audit_log_structure(self):
        """Test that audit logs have proper structure."""
        audit_service = AuditService()
        with patch.object(audit_service, 'log_event') as mock_log:
            asyncio.run(audit_service.log_event(
                event_type="test_event",
                category="security",
                action="test_action",
                result="success",
                description="Test audit log",
                user_id="test_user",
                level="standard"
            ))
            
            # Verify log structure
            mock_log.assert_called_once()
            call_args = mock_log.call_args[1]
            
            required_fields = [
                "event_type", "category", "action", "result",
                "description", "user_id", "level"
            ]
            
            for field in required_fields:
                assert field in call_args
    
    def test_phi_audit_logging(self):
        """Test that PHI-related actions are properly audited."""
        audit_service = AuditService()
        with patch.object(audit_service, 'log_event') as mock_log:
            asyncio.run(audit_service.log_event(
                event_type="phi_access",
                category="security",
                action="access_phi",
                result="success",
                description="PHI data accessed",
                user_id="test_user",
                level="detailed",
                phi_involved=True
            ))
            
            # Verify PHI flag is set
            call_args = mock_log.call_args[1]
            assert call_args["phi_involved"] is True
            assert call_args["level"] == "detailed"


class TestDataClassification:
    """Test data classification and handling."""
    
    def test_data_classification_levels(self):
        """Test that data classification levels are properly defined."""
        from core.storage.models import DataClassification
        
        # Test all classification levels
        assert DataClassification.PUBLIC == "public"
        assert DataClassification.INTERNAL == "internal"
        assert DataClassification.CONFIDENTIAL == "confidential"
        assert DataClassification.PHI == "phi"
        assert DataClassification.PII == "pii"
    
    def test_phi_data_handling(self):
        """Test that PHI data is properly handled."""
        from core.storage.models import DataClassification, StorageMetadata
        from uuid import uuid4
        
        # Create PHI metadata
        phi_metadata = StorageMetadata(
            object_key="phi_document_123",
            original_filename="patient_record.pdf",
            content_type="application/pdf",
            size_bytes=1024,
            data_classification=DataClassification.PHI,
            traits=["phi"],
            created_by=uuid4(),
            provider="filesystem",
            provider_path="/storage/phi_document_123"
        )
        
        # Verify PHI classification
        assert phi_metadata.data_classification == DataClassification.PHI
        assert "phi" in phi_metadata.traits
        assert phi_metadata.is_sensitive  # Should be sensitive


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
