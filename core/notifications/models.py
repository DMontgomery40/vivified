"""
Notification domain models.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field


class NotificationPriority(str, Enum):
    low = "low"
    normal = "normal"
    high = "high"
    critical = "critical"


class NotificationRequest(BaseModel):
    notification_id: str
    title: Optional[str] = None
    body: str
    priority: NotificationPriority = NotificationPriority.normal
    channel: Optional[str] = None
    targets: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class NotificationStatus(str, Enum):
    queued = "queued"
    sent = "sent"
    partial = "partial"
    failed = "failed"


class NotificationSent(BaseModel):
    event_type: str = "NotificationSent"
    notification_id: str
    plugin: str
    timestamp: str
    status: NotificationStatus
    details: Dict[str, Any] = Field(default_factory=dict)


class InboxItem(BaseModel):
    id: str
    type: str
    ts: datetime
    payload: Dict[str, Any]
