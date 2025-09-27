"""
Storage service with encryption, audit logging, and HIPAA compliance.
"""

import logging
from datetime import datetime
from typing import Dict, List, Optional, BinaryIO
from uuid import UUID, uuid4

from ..audit.service import AuditService, AuditLevel
from ..identity.auth import audit_phi_access
from ..policy.engine import PolicyEngine, PolicyDecision, PolicyRequest
from .encryption import StorageEncryption
from .models import (
    DataClassification,
    StorageConfig,
    StorageMetadata,
    StorageObject,
    StorageProvider,
    StorageQuery,
    RetentionPolicy
)
from .providers import FilesystemProvider, S3Provider, StorageProviderBase

logger = logging.getLogger(__name__)


class StorageService:
    """
    Main storage service with PHI/PII protection and HIPAA compliance.

    Features:
    - Automatic encryption for sensitive data
    - Data classification and trait-based access control
    - Comprehensive audit logging
    - HIPAA-compliant retention policies
    - Multi-provider support (filesystem, S3, etc.)
    """

    def __init__(
        self,
        config: StorageConfig,
        policy_engine: PolicyEngine,
        audit_service: AuditService,
        encryption_key: Optional[str] = None
    ):
        """Initialize storage service."""
        self.config = config
        self.policy_engine = policy_engine
        self.audit_service = audit_service
        self.encryption = StorageEncryption(encryption_key)

        # Initialize storage providers
        self.providers: Dict[StorageProvider, StorageProviderBase] = {}
        self._init_providers()

    def _init_providers(self) -> None:
        """Initialize configured storage providers."""
        # Always init filesystem provider
        self.providers[StorageProvider.FILESYSTEM] = FilesystemProvider(
            self.config.filesystem_base_path
        )

        # Init S3 provider if configured
        if self.config.s3_bucket:
            self.providers[StorageProvider.S3] = S3Provider(
                bucket=self.config.s3_bucket,
                region=self.config.s3_region or "us-east-1",
                endpoint_url=self.config.s3_endpoint_url
            )

    def _get_provider(self, provider: StorageProvider) -> StorageProviderBase:
        """Get storage provider instance."""
        if provider not in self.providers:
            raise ValueError(f"Storage provider {provider} not configured")
        return self.providers[provider]

    async def _check_access_policy(self, user_id: UUID, metadata: StorageMetadata, action: str) -> bool:
        """Check if user has access to perform action on object."""
        # Create policy request
        request = PolicyRequest(
            user_id=user_id,
            resource_type="storage_object",
            resource_id=str(metadata.id),
            action=action,
            traits=metadata.traits,
            context={
                "data_classification": metadata.data_classification.value,
                "object_key": metadata.object_key,
                "content_type": metadata.content_type,
                "size_bytes": metadata.size_bytes
            }
        )

        # Evaluate policy
        decision = await self.policy_engine.evaluate_request(request)
        return decision.decision == PolicyDecision.ALLOW

    def _auto_classify_content(self, content: bytes, filename: str, content_type: str) -> DataClassification:
        """
        Automatically classify content based on patterns and metadata.

        This is a basic implementation. In production, use ML models
        or pattern matching for more sophisticated classification.
        """
        # Check filename patterns
        filename_lower = filename.lower()
        if any(pattern in filename_lower for pattern in ['medical', 'patient', 'health', 'phi']):
            return DataClassification.PHI

        if any(pattern in filename_lower for pattern in ['ssn', 'social', 'personal', 'pii']):
            return DataClassification.PII

        # Check content type
        if content_type.startswith('application/dicom'):
            return DataClassification.PHI

        # Check content patterns (basic)
        if len(content) > 0:
            content_str = content[:1024].decode('utf-8', errors='ignore').lower()

            # PHI patterns
            phi_patterns = ['patient', 'medical record', 'diagnosis', 'treatment', 'healthcare']
            if any(pattern in content_str for pattern in phi_patterns):
                return DataClassification.PHI

            # PII patterns
            pii_patterns = ['ssn', 'social security', 'driver license', 'passport']
            if any(pattern in content_str for pattern in pii_patterns):
                return DataClassification.PII

        # Default to confidential for safety
        return DataClassification.CONFIDENTIAL

    async def store_object(
        self,
        content: bytes,
        filename: str,
        user_id: UUID,
        content_type: str = "application/octet-stream",
        data_classification: Optional[DataClassification] = None,
        traits: Optional[List[str]] = None,
        retention_policy: Optional[RetentionPolicy] = None,
        custom_metadata: Optional[Dict] = None,
        provider: Optional[StorageProvider] = None
    ) -> StorageMetadata:
        """
        Store object with encryption and audit logging.

        Args:
            content: Raw content bytes
            filename: Original filename
            user_id: User storing the object
            content_type: MIME content type
            data_classification: Manual classification override
            traits: Additional traits for access control
            retention_policy: Custom retention policy
            custom_metadata: Additional metadata
            provider: Storage provider to use

        Returns:
            Storage metadata for the stored object

        Raises:
            ValueError: If validation fails
            PermissionError: If user lacks permission
        """
        # Validate content size
        if len(content) > self.config.max_file_size_mb * 1024 * 1024:
            raise ValueError(f"File size exceeds limit of {self.config.max_file_size_mb}MB")

        # Validate content type
        if content_type not in self.config.allowed_content_types:
            raise ValueError(f"Content type {content_type} not allowed")

        # Auto-classify if not provided
        if data_classification is None and self.config.auto_classify_content:
            data_classification = self._auto_classify_content(content, filename, content_type)
        elif data_classification is None:
            data_classification = DataClassification.CONFIDENTIAL

        # Create metadata
        object_id = str(uuid4())
        metadata = StorageMetadata(
            object_key=object_id,
            original_filename=filename,
            content_type=content_type,
            size_bytes=len(content),
            data_classification=data_classification,
            traits=traits or [],
            retention_policy=retention_policy or RetentionPolicy.HIPAA_STANDARD,
            created_by=user_id,
            provider=provider or self.config.default_provider,
            provider_path="",  # Will be set by provider
            custom_metadata=custom_metadata or {}
        )

        # Check access policy
        if not await self._check_access_policy(user_id, metadata, "store"):
            await self.audit_service.log_event(
                event_type="storage_access_denied",
                user_id=user_id,
                level=AuditLevel.DETAILED,
                details={
                    "action": "store",
                    "object_key": object_id,
                    "data_classification": data_classification.value,
                    "reason": "policy_denied"
                }
            )
            raise PermissionError("Access denied by policy engine")

        # Encrypt content if required
        if self.config.encryption_enabled or metadata.is_sensitive:
            content, key_id = self.encryption.encrypt_object(content, object_id)
            metadata.is_encrypted = True
            metadata.encryption_key_id = key_id

        # Calculate checksum
        metadata.checksum = self.encryption.calculate_checksum(content)

        # Create storage object
        storage_object = StorageObject(metadata=metadata, content=content)

        # Store using provider
        provider_instance = self._get_provider(metadata.provider)
        stored_metadata = await provider_instance.store_object(storage_object)

        # Audit log
        audit_level = AuditLevel.COMPREHENSIVE if stored_metadata.is_sensitive else AuditLevel.STANDARD
        await self.audit_service.log_event(
            event_type="object_stored",
            user_id=user_id,
            level=audit_level,
            phi_involved=stored_metadata.is_phi,
            details={
                "object_key": stored_metadata.object_key,
                "data_classification": stored_metadata.data_classification.value,
                "size_bytes": stored_metadata.size_bytes,
                "provider": stored_metadata.provider.value,
                "encrypted": stored_metadata.is_encrypted,
                "traits": stored_metadata.traits
            }
        )

        logger.info(f"Stored object {stored_metadata.object_key} for user {user_id}")
        return stored_metadata

    @audit_phi_access
    async def retrieve_object(self, object_key: str, user_id: UUID) -> Optional[StorageObject]:
        """
        Retrieve object with access control and audit logging.

        Args:
            object_key: Object identifier
            user_id: User requesting the object

        Returns:
            Storage object with content, or None if not found

        Raises:
            PermissionError: If user lacks access
        """
        # Get metadata first to check permissions
        metadata = await self.get_object_metadata(object_key, user_id)
        if not metadata:
            return None

        # Check access policy
        if not await self._check_access_policy(user_id, metadata, "retrieve"):
            await self.audit_service.log_event(
                event_type="storage_access_denied",
                user_id=user_id,
                level=AuditLevel.DETAILED,
                phi_involved=metadata.is_phi,
                details={
                    "action": "retrieve",
                    "object_key": object_key,
                    "data_classification": metadata.data_classification.value,
                    "reason": "policy_denied"
                }
            )
            raise PermissionError("Access denied by policy engine")

        # Retrieve from provider
        provider_instance = self._get_provider(metadata.provider)
        storage_object = await provider_instance.retrieve_object(object_key)

        if not storage_object:
            return None

        # Decrypt if encrypted
        if metadata.is_encrypted and metadata.encryption_key_id:
            try:
                decrypted_content = self.encryption.decrypt_object(
                    storage_object.content,
                    object_key,
                    metadata.encryption_key_id
                )
                storage_object.content = decrypted_content
            except Exception as e:
                logger.error(f"Failed to decrypt object {object_key}: {e}")
                raise ValueError("Failed to decrypt object content")

        # Verify checksum
        if metadata.checksum:
            if not self.encryption.verify_checksum(storage_object.content, metadata.checksum):
                logger.error(f"Checksum verification failed for object {object_key}")
                raise ValueError("Object integrity check failed")

        # Update access tracking
        storage_object.update_access_tracking(user_id)

        # Update metadata in storage
        provider_instance = self._get_provider(metadata.provider)
        await provider_instance.store_object(
            StorageObject(metadata=storage_object.metadata, content=b"")  # Just update metadata
        )

        # Audit log
        audit_level = AuditLevel.COMPREHENSIVE if metadata.is_sensitive else AuditLevel.STANDARD
        await self.audit_service.log_event(
            event_type="object_retrieved",
            user_id=user_id,
            level=audit_level,
            phi_involved=metadata.is_phi,
            details={
                "object_key": object_key,
                "data_classification": metadata.data_classification.value,
                "size_bytes": metadata.size_bytes,
                "access_count": storage_object.metadata.access_count
            }
        )

        logger.info(f"Retrieved object {object_key} for user {user_id}")
        return storage_object

    async def delete_object(self, object_key: str, user_id: UUID) -> bool:
        """
        Delete object with access control and audit logging.

        Args:
            object_key: Object identifier
            user_id: User requesting deletion

        Returns:
            True if deleted, False if not found

        Raises:
            PermissionError: If user lacks permission
        """
        # Get metadata first to check permissions
        metadata = await self.get_object_metadata(object_key, user_id)
        if not metadata:
            return False

        # Check access policy
        if not await self._check_access_policy(user_id, metadata, "delete"):
            await self.audit_service.log_event(
                event_type="storage_access_denied",
                user_id=user_id,
                level=AuditLevel.DETAILED,
                phi_involved=metadata.is_phi,
                details={
                    "action": "delete",
                    "object_key": object_key,
                    "data_classification": metadata.data_classification.value,
                    "reason": "policy_denied"
                }
            )
            raise PermissionError("Access denied by policy engine")

        # Delete from provider
        provider_instance = self._get_provider(metadata.provider)
        success = await provider_instance.delete_object(object_key)

        if success:
            # Audit log
            audit_level = AuditLevel.COMPREHENSIVE if metadata.is_sensitive else AuditLevel.STANDARD
            await self.audit_service.log_event(
                event_type="object_deleted",
                user_id=user_id,
                level=audit_level,
                phi_involved=metadata.is_phi,
                details={
                    "object_key": object_key,
                    "data_classification": metadata.data_classification.value,
                    "size_bytes": metadata.size_bytes,
                    "provider": metadata.provider.value
                }
            )

            logger.info(f"Deleted object {object_key} by user {user_id}")

        return success

    async def list_objects(self, query: StorageQuery, user_id: UUID) -> List[StorageMetadata]:
        """
        List objects with access control filtering.

        Args:
            query: Query parameters
            user_id: User requesting the list

        Returns:
            List of accessible object metadata
        """
        results = []

        # Get objects from all providers
        for provider_type, provider in self.providers.items():
            provider_results = await provider.list_objects(query)

            # Filter by access policy
            for metadata in provider_results:
                if await self._check_access_policy(user_id, metadata, "list"):
                    results.append(metadata)

        # Audit log (minimal for list operations)
        await self.audit_service.log_event(
            event_type="objects_listed",
            user_id=user_id,
            level=AuditLevel.MINIMAL,
            details={
                "query_filters": query.dict(exclude_none=True),
                "result_count": len(results)
            }
        )

        return results

    async def get_object_metadata(self, object_key: str, user_id: UUID) -> Optional[StorageMetadata]:
        """
        Get object metadata with access control.

        Args:
            object_key: Object identifier
            user_id: User requesting metadata

        Returns:
            Object metadata or None if not found/accessible
        """
        # Try all providers to find object
        for provider_type, provider in self.providers.items():
            metadata = await provider.get_object_metadata(object_key)
            if metadata:
                # Check access policy
                if await self._check_access_policy(user_id, metadata, "metadata"):
                    return metadata
                else:
                    # Object exists but access denied
                    return None

        return None

    async def cleanup_expired_objects(self) -> int:
        """
        Clean up expired objects based on retention policies.

        Returns:
            Number of objects cleaned up
        """
        if not self.config.cleanup_expired_objects:
            return 0

        cleaned_count = 0
        current_time = datetime.utcnow()

        # Check all providers
        for provider_type, provider in self.providers.items():
            # Query for all objects (this is inefficient - in production use database index)
            query = StorageQuery(limit=10000)  # Large limit for cleanup
            all_objects = await provider.list_objects(query)

            for metadata in all_objects:
                if metadata.expires_at and current_time > metadata.expires_at:
                    # Object is expired, delete it
                    success = await provider.delete_object(metadata.object_key)
                    if success:
                        cleaned_count += 1

                        # Audit log
                        await self.audit_service.log_event(
                            event_type="object_expired_cleanup",
                            user_id=None,  # System operation
                            level=AuditLevel.STANDARD,
                            phi_involved=metadata.is_phi,
                            details={
                                "object_key": metadata.object_key,
                                "data_classification": metadata.data_classification.value,
                                "expired_at": metadata.expires_at.isoformat(),
                                "retention_policy": metadata.retention_policy.value
                            }
                        )

        if cleaned_count > 0:
            logger.info(f"Cleaned up {cleaned_count} expired objects")

        return cleaned_count