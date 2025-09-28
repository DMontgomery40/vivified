from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
from dataclasses import dataclass


@dataclass
class PluginManifest:
    """Plugin manifest structure."""

    id: str
    name: str
    version: str
    description: str
    contracts: List[str]
    traits: List[str]
    dependencies: List[str]
    allowed_domains: List[str]
    endpoints: Dict[str, str]
    security: Dict[str, Any]
    compliance: Dict[str, Any]


class PluginBase(ABC):
    """Base class all plugins must implement."""

    @abstractmethod
    async def initialize(self, core_context: Dict[str, Any]) -> bool:
        """Initialize plugin with core context."""

    @abstractmethod
    async def shutdown(self) -> None:
        """Clean shutdown of plugin."""

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Return plugin health status."""

    @abstractmethod
    def get_manifest(self) -> PluginManifest:
        """Return plugin manifest."""


class CommunicationPlugin(PluginBase):
    """Interface for communication plugins."""

    @abstractmethod
    async def send_message(self, message: Dict[str, Any]) -> str:
        """Send a message through the communication channel."""

    @abstractmethod
    async def receive_messages(self) -> List[Dict[str, Any]]:
        """Retrieve pending messages."""


class StoragePlugin(PluginBase):
    """Interface for storage plugins."""

    @abstractmethod
    async def store(self, data: bytes, metadata: Dict[str, Any]) -> str:
        """Store data with metadata, return ID."""

    @abstractmethod
    async def retrieve(self, id: str) -> Optional[bytes]:
        """Retrieve data by ID."""

    @abstractmethod
    async def delete(self, id: str) -> bool:
        """Delete data by ID."""
