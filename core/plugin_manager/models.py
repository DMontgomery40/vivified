"""
Plugin manager data models.
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any

from pydantic import BaseModel, Field


class PluginStatus(str, Enum):
    """Plugin status values."""

    REGISTERED = "registered"
    ACTIVE = "active"
    INACTIVE = "inactive"
    DISABLED = "disabled"
    UNHEALTHY = "unhealthy"
    ERROR = "error"


class HealthStatus(str, Enum):
    """Plugin health status values."""

    HEALTHY = "healthy"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"
    DEGRADED = "degraded"


class PluginManifest(BaseModel):
    """Plugin manifest model."""

    id: str
    name: str
    version: str
    description: str
    contracts: List[str] = Field(default_factory=list)
    traits: List[str] = Field(default_factory=list)
    dependencies: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    endpoints: Dict[str, str] = Field(default_factory=dict)
    security: Dict[str, Any] = Field(default_factory=dict)
    compliance: Dict[str, Any] = Field(default_factory=dict)
    health_check: Optional[str] = None

    class Config:
        use_enum_values = True


class PluginInfo(BaseModel):
    """Plugin information model."""

    id: str
    manifest: PluginManifest
    status: PluginStatus
    health: "PluginHealth"
    registered_at: datetime
    last_heartbeat: Optional[datetime] = None
    last_error: Optional[str] = None
    consecutive_failures: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    token: Optional[str] = None

    class Config:
        use_enum_values = True


class PluginHealth(BaseModel):
    """Plugin health information."""

    status: HealthStatus
    last_check: datetime
    consecutive_failures: int = 0
    response_time_ms: Optional[int] = None
    error_message: Optional[str] = None
    uptime_seconds: Optional[int] = None
    memory_usage_mb: Optional[float] = None
    cpu_usage_percent: Optional[float] = None
    metrics: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class PluginRegistration(BaseModel):
    """Plugin registration request."""

    manifest: PluginManifest
    registration_token: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    class Config:
        use_enum_values = True


class PluginUpdate(BaseModel):
    """Plugin update request."""

    status: Optional[PluginStatus] = None
    health: Optional[HealthStatus] = None
    metadata: Optional[Dict[str, Any]] = None

    class Config:
        use_enum_values = True
