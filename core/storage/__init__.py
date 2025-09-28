"""
Storage service for encrypted PHI/PII data with HIPAA compliance.

This module provides:
- Encrypted storage abstraction layer
- Automatic data classification and tagging
- HIPAA-compliant retention policies
- Comprehensive audit integration
"""

from .service import StorageService
from .models import StorageObject, StorageMetadata, DataClassification
from .encryption import StorageEncryption
from .providers import FilesystemProvider, S3Provider

__all__ = [
    "StorageService",
    "StorageObject",
    "StorageMetadata",
    "DataClassification",
    "StorageEncryption",
    "FilesystemProvider",
    "S3Provider",
]
