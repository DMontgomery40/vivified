"""
Messaging data models for inter-plugin communication.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import uuid4

from pydantic import BaseModel, Field


class MessageType(str, Enum):
    """Types of messages in the system."""

    EVENT = "event"
    REQUEST = "request"
    RESPONSE = "response"
    NOTIFICATION = "notification"


class MessagePriority(str, Enum):
    """Message priority levels."""

    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class DataClassification(str, Enum):
    """Data classification for message content."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PHI = "phi"
    PII = "pii"


class Message(BaseModel):
    """Canonical message format for inter-plugin communication."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    message_type: MessageType
    priority: MessagePriority = MessagePriority.NORMAL
    source_plugin: str
    target_plugin: Optional[str] = None
    target_traits: List[str] = Field(default_factory=list)
    content_type: str = "application/json"
    payload: Dict[str, Any] = Field(default_factory=dict)
    data_classification: DataClassification = DataClassification.INTERNAL
    traits: List[str] = Field(default_factory=list)
    correlation_id: Optional[str] = None
    reply_to: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class Event(BaseModel):
    """Event message for canonical communication."""

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    event_type: str
    trace_id: str = Field(default_factory=lambda: str(uuid4()))
    source_plugin: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data_traits: List[str] = Field(default_factory=list)
    payload: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, str] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class MessageFilter(BaseModel):
    """Filter criteria for message queries."""

    message_types: Optional[List[MessageType]] = None
    source_plugins: Optional[List[str]] = None
    target_plugins: Optional[List[str]] = None
    data_classifications: Optional[List[DataClassification]] = None
    traits: Optional[List[str]] = None
    priority: Optional[MessagePriority] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    correlation_id: Optional[str] = None

    class Config:
        use_enum_values = True


class MessageDeliveryStatus(str, Enum):
    """Message delivery status."""

    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    EXPIRED = "expired"
    REJECTED = "rejected"


class MessageDelivery(BaseModel):
    """Message delivery tracking."""

    message_id: str
    target_plugin: str
    status: MessageDeliveryStatus
    attempts: int = 0
    max_attempts: int = 3
    last_attempt: Optional[datetime] = None
    error_message: Optional[str] = None
    delivered_at: Optional[datetime] = None

    class Config:
        use_enum_values = True
