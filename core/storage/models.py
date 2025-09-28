"""
Storage data models for PHI/PII protection and HIPAA compliance.
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator


class DataClassification(str, Enum):
    """Data classification levels for HIPAA compliance."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PHI = "phi"  # Protected Health Information
    PII = "pii"  # Personally Identifiable Information


class RetentionPolicy(str, Enum):
    """Standard retention periods for different data types."""

    SHORT_TERM = "90_days"  # 90 days
    MEDIUM_TERM = "1_year"  # 1 year
    LONG_TERM = "3_years"  # 3 years
    HIPAA_STANDARD = "7_years"  # 7 years (HIPAA requirement)
    INDEFINITE = "indefinite"  # Never auto-delete


class StorageProvider(str, Enum):
    """Supported storage providers."""

    FILESYSTEM = "filesystem"
    S3 = "s3"
    AZURE_BLOB = "azure_blob"
    GCS = "gcs"


class StorageMetadata(BaseModel):
    """Metadata for stored objects with HIPAA compliance tracking."""

    id: UUID = Field(default_factory=uuid4)
    object_key: str = Field(..., description="Unique object identifier")
    original_filename: Optional[str] = None
    content_type: str = "application/octet-stream"
    size_bytes: int = Field(..., ge=0)

    # Classification and security
    data_classification: DataClassification = DataClassification.INTERNAL
    traits: List[str] = Field(default_factory=list)
    is_encrypted: bool = True
    encryption_key_id: Optional[str] = None

    # Retention and compliance
    retention_policy: RetentionPolicy = RetentionPolicy.HIPAA_STANDARD
    created_at: datetime = Field(default_factory=datetime.utcnow)
    accessed_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None

    # Audit tracking
    created_by: UUID
    last_accessed_by: Optional[UUID] = None
    access_count: int = 0

    # Storage provider info
    provider: StorageProvider = StorageProvider.FILESYSTEM
    provider_path: str
    checksum: Optional[str] = None

    # Custom metadata
    custom_metadata: Dict[str, Any] = Field(default_factory=dict)

    @validator("expires_at", always=True)
    def set_expiration_date(cls, v, values):
        """Set expiration date based on retention policy."""
        if v is not None:
            return v

        created_at = values.get("created_at", datetime.utcnow())
        retention = values.get("retention_policy", RetentionPolicy.HIPAA_STANDARD)

        if retention == RetentionPolicy.SHORT_TERM:
            return created_at + timedelta(days=90)
        elif retention == RetentionPolicy.MEDIUM_TERM:
            return created_at + timedelta(days=365)
        elif retention == RetentionPolicy.LONG_TERM:
            return created_at + timedelta(days=365 * 3)
        elif retention == RetentionPolicy.HIPAA_STANDARD:
            return created_at + timedelta(days=365 * 7)
        else:  # INDEFINITE
            return None

    @validator("traits")
    def validate_traits_for_classification(cls, v, values):
        """Ensure traits match data classification."""
        classification = values.get("data_classification")

        if classification == DataClassification.PHI:
            if "phi_handler" not in v:
                v.append("phi_handler")
            if "hipaa_covered_entity" not in v:
                v.append("hipaa_covered_entity")
        elif classification == DataClassification.PII:
            if "pii_processor" not in v:
                v.append("pii_processor")

        return v

    @property
    def is_sensitive(self) -> bool:
        """Check if the data is sensitive based on classification."""
        return self.data_classification in [
            DataClassification.PHI, 
            DataClassification.PII, 
            DataClassification.CONFIDENTIAL
        ]

    class Config:
        use_enum_values = True


class StorageObject(BaseModel):
    """Complete storage object with metadata and content."""

    metadata: StorageMetadata
    content: Optional[bytes] = None
    content_stream: Optional[Any] = None  # For streaming large files

    @property
    def is_phi(self) -> bool:
        """Check if object contains PHI data."""
        return self.metadata.data_classification == DataClassification.PHI

    @property
    def is_pii(self) -> bool:
        """Check if object contains PII data."""
        return self.metadata.data_classification == DataClassification.PII

    @property
    def is_sensitive(self) -> bool:
        """Check if object contains sensitive data (PHI or PII)."""
        return self.is_phi or self.is_pii

    @property
    def is_expired(self) -> bool:
        """Check if object has expired based on retention policy."""
        if self.metadata.expires_at is None:
            return False
        return datetime.utcnow() > self.metadata.expires_at

    def update_access_tracking(self, user_id: UUID) -> None:
        """Update access tracking metadata."""
        self.metadata.last_accessed_by = user_id
        self.metadata.accessed_at = datetime.utcnow()
        self.metadata.access_count += 1

    class Config:
        arbitrary_types_allowed = True


class StorageConfig(BaseModel):
    """Configuration for storage service."""

    default_provider: StorageProvider = StorageProvider.FILESYSTEM
    encryption_enabled: bool = True
    auto_classify_content: bool = True
    audit_all_access: bool = True

    # Provider-specific settings
    filesystem_base_path: str = "/var/lib/vivified/storage"
    s3_bucket: Optional[str] = None
    s3_region: Optional[str] = None
    s3_endpoint_url: Optional[str] = None

    # Security settings
    max_file_size_mb: int = 100
    allowed_content_types: List[str] = Field(
        default_factory=lambda: [
            "application/json",
            "application/pdf",
            "text/plain",
            "text/csv",
            "image/jpeg",
            "image/png",
            "application/octet-stream",
        ]
    )

    # Retention cleanup
    cleanup_expired_objects: bool = True
    cleanup_interval_hours: int = 24

    class Config:
        use_enum_values = True


class StorageQuery(BaseModel):
    """Query parameters for searching stored objects."""

    object_keys: Optional[List[str]] = None
    data_classification: Optional[DataClassification] = None
    traits: Optional[List[str]] = None
    created_by: Optional[UUID] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    content_type: Optional[str] = None
    expired_only: bool = False

    # Pagination
    limit: int = Field(default=50, le=1000)
    offset: int = Field(default=0, ge=0)

    class Config:
        use_enum_values = True
