"""
Canonical data models for cross-plugin compatibility.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import uuid4

from pydantic import BaseModel, Field


class CanonicalUser(BaseModel):
    """Canonical user representation across all plugins."""

    id: str
    username: str
    email: str
    roles: List[str] = Field(default_factory=list)
    traits: List[str] = Field(default_factory=list)
    created_at: datetime
    attributes: Dict[str, str] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class CanonicalMessage(BaseModel):
    """Canonical message format for communication plugins."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    from_user: str
    to_user: str
    content_type: str = "text/plain"
    content: bytes
    data_traits: List[str] = Field(default_factory=list)
    sent_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class CanonicalEvent(BaseModel):
    """Canonical event format for event bus."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    trace_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_plugin: str
    data_traits: List[str] = Field(default_factory=list)
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, str] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class DataTransformation(BaseModel):
    """Record of data transformation."""

    source_format: str
    target_format: str
    transformation_type: str
    source_plugin: str
    target_plugin: str
    transformed_at: datetime = Field(default_factory=datetime.utcnow)
    success: bool
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True
