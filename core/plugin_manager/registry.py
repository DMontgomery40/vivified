from typing import Dict
from datetime import datetime
import uuid
import jwt
from fastapi import HTTPException
import logging

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Manages plugin registration and lifecycle."""

    def __init__(self, jwt_secret: str):
        self.plugins: Dict[str, Dict] = {}
        self.jwt_secret = jwt_secret

    async def register_plugin(self, manifest: Dict) -> Dict:
        """Register a new plugin with the core."""
        plugin_id = manifest.get("id")

        # Validate manifest
        if not self._validate_manifest(manifest):
            raise HTTPException(status_code=400, detail="Invalid manifest")

        # Check for duplicate registration
        if plugin_id in self.plugins:
            raise HTTPException(status_code=409, detail="Plugin already registered")

        # Generate authentication token for plugin
        token = self._generate_plugin_token(plugin_id)

        # Store plugin information
        self.plugins[plugin_id] = {
            "manifest": manifest,
            "status": "registered",
            "registered_at": datetime.utcnow().isoformat(),
            "last_heartbeat": datetime.utcnow().isoformat(),
            "token": token,
            "health": "unknown",
        }

        logger.info(
            f"Plugin registered: {plugin_id}", extra={"trace_id": str(uuid.uuid4())}
        )

        return {"status": "registered", "token": token, "plugin_id": plugin_id}

    def _validate_manifest(self, manifest: Dict) -> bool:
        """Validate plugin manifest against schema."""
        required_fields = [
            "id",
            "name",
            "version",
            "contracts",
            "traits",
            "security",
            "compliance",
        ]
        return all(field in manifest for field in required_fields)

    def _generate_plugin_token(self, plugin_id: str) -> str:
        """Generate JWT token for plugin authentication."""
        payload = {
            "plugin_id": plugin_id,
            "type": "plugin",
            "issued_at": datetime.utcnow().isoformat(),
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    async def heartbeat(self, plugin_id: str, status: Dict) -> bool:
        """Update plugin heartbeat and status."""
        if plugin_id not in self.plugins:
            return False

        self.plugins[plugin_id]["last_heartbeat"] = datetime.utcnow().isoformat()
        self.plugins[plugin_id]["health"] = status.get("health", "healthy")
        return True

