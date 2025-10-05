from __future__ import annotations

from abc import ABC, abstractmethod
from typing import List, Optional
from pydantic import BaseModel, Field


class ConnectURL(BaseModel):
    """OAuth connection URL returned by provider plugins."""

    url: str


class IntegrationStatus(BaseModel):
    """Connection status for a given user and provider."""

    connected: bool
    account: Optional[str] = None


class Result(BaseModel):
    """Generic result structure for plugin operations."""

    success: bool


class IntegrationManifest(BaseModel):
    """Manifest for integration plugins backed by an external host (sidecar)."""

    key: str
    name: str
    category: str = "other"
    hipaa_eligible: bool = False
    allowed_hosts: List[str] = Field(default_factory=list)
    scopes: List[str] = Field(default_factory=list)
    icon: str = "hub"


class IntegrationPluginBase(ABC):
    """Abstract base for integration plugins.

    Implementations delegate OAuth flows and stateful operations to the
    external integrations sidecar via the ExternalPluginClient.
    """

    @abstractmethod
    async def connect(
        self, user_id: str, state: str
    ) -> ConnectURL:  # pragma: no cover - interface
        """Return an authorization URL for the given user/state."""

    @abstractmethod
    async def callback(
        self, user_id: str, code: str, state: str
    ) -> Result:  # pragma: no cover - interface
        """Handle OAuth code exchange and persist credentials."""

    @abstractmethod
    async def status(
        self, user_id: str
    ) -> IntegrationStatus:  # pragma: no cover - interface
        """Return connection status for the user."""

    @abstractmethod
    async def revoke(self, user_id: str) -> Result:  # pragma: no cover - interface
        """Revoke credentials for the user."""
