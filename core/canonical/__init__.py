"""
Canonical service for data normalization and transformation.

This module provides:
- Data normalization to canonical formats
- PHI/PII data transformation
- Cross-plugin data compatibility
- Audit logging for all transformations
"""

from .service import CanonicalService
from .models import CanonicalUser, CanonicalMessage, CanonicalEvent
from .transformer import DataTransformer

__all__ = [
    "CanonicalService",
    "CanonicalUser",
    "CanonicalMessage", 
    "CanonicalEvent",
    "DataTransformer",
]
