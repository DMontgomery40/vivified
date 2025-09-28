"""
Gateway data models for external API access.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, HttpUrl


class ProxyMethod(str, Enum):
    """HTTP methods supported by proxy."""
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    HEAD = "HEAD"
    OPTIONS = "OPTIONS"


class ProxyStatus(str, Enum):
    """Proxy request status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"


class ProxyRequest(BaseModel):
    """Proxy request model."""
    
    id: str = Field(default_factory=lambda: str(uuid4()))
    plugin_id: str
    method: ProxyMethod
    url: HttpUrl
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[bytes] = None
    timeout: int = 30
    retries: int = 3
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class ProxyResponse(BaseModel):
    """Proxy response model."""
    
    request_id: str
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[bytes] = None
    response_time_ms: int
    success: bool
    error_message: Optional[str] = None
    completed_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


class DomainAllowlist(BaseModel):
    """Domain allowlist entry."""
    
    id: str = Field(default_factory=lambda: str(uuid4()))
    plugin_id: str
    domain: str
    allowed_methods: List[ProxyMethod] = Field(default_factory=list)
    allowed_paths: List[str] = Field(default_factory=list)
    max_requests_per_minute: int = 60
    created_at: datetime = Field(default_factory=datetime.utcnow)
    is_active: bool = True

    class Config:
        use_enum_values = True


class RateLimit(BaseModel):
    """Rate limiting configuration."""
    
    plugin_id: str
    domain: str
    requests_per_minute: int
    burst_limit: int
    window_start: datetime = Field(default_factory=datetime.utcnow)
    current_requests: int = 0

    class Config:
        use_enum_values = True


class ProxyStats(BaseModel):
    """Proxy statistics."""
    
    total_requests: int = 0
    successful_requests: int = 0
    failed_requests: int = 0
    blocked_requests: int = 0
    average_response_time_ms: float = 0.0
    requests_by_domain: Dict[str, int] = Field(default_factory=dict)
    requests_by_plugin: Dict[str, int] = Field(default_factory=dict)
    last_updated: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True
