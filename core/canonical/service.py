"""
Canonical service for data normalization and cross-plugin compatibility.
"""

import logging
from typing import Dict, Any, Optional, List

from .models import CanonicalUser, CanonicalMessage, CanonicalEvent
from .transformer import DataTransformer
from ..audit.service import AuditService, AuditLevel
from ..policy.engine import PolicyEngine, PolicyRequest, PolicyDecision, PolicyContext

logger = logging.getLogger(__name__)


class CanonicalService:
    """Service for canonical data transformation and normalization."""

    def __init__(self, audit_service: AuditService, policy_engine: PolicyEngine):
        self.audit_service = audit_service
        self.policy_engine = policy_engine
        self.transformer = DataTransformer(audit_service)
        self.canonical_store: Dict[str, Any] = {}

    async def normalize_user(
        self, user_data: Dict[str, Any], source_plugin: str, target_plugin: str
    ) -> CanonicalUser:
        """Normalize user data to canonical format."""
        try:
            # Check if transformation is allowed
            if not await self._can_transform_data(source_plugin, target_plugin, "user"):
                raise PermissionError(
                    f"Plugin {source_plugin} not authorized to transform user data for {target_plugin}"
                )

            canonical_user = await self.transformer.transform_user_to_canonical(
                user_data, source_plugin, target_plugin
            )

            # Store canonical data
            self.canonical_store[f"user:{canonical_user.id}"] = canonical_user

            await self.audit_service.log_event(
                event_type="user_normalized",
                category="canonical",
                action="normalize_user",
                result="success",
                description=f"User {canonical_user.id} normalized from {source_plugin} to {target_plugin}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={"user_id": canonical_user.id, "target_plugin": target_plugin},
            )

            return canonical_user

        except Exception as e:
            logger.error(f"Failed to normalize user: {e}")
            await self.audit_service.log_event(
                event_type="user_normalization_failed",
                category="canonical",
                action="normalize_user",
                result="failed",
                description=f"Failed to normalize user: {str(e)}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={"error": str(e)},
            )
            raise

    async def normalize_message(
        self, message_data: Dict[str, Any], source_plugin: str, target_plugin: str
    ) -> CanonicalMessage:
        """Normalize message data to canonical format."""
        try:
            # Check if transformation is allowed
            if not await self._can_transform_data(
                source_plugin, target_plugin, "message"
            ):
                raise PermissionError(
                    f"Plugin {source_plugin} not authorized to transform message data for {target_plugin}"
                )

            canonical_message = await self.transformer.transform_message_to_canonical(
                message_data, source_plugin, target_plugin
            )

            # Store canonical data
            self.canonical_store[f"message:{canonical_message.id}"] = canonical_message

            await self.audit_service.log_event(
                event_type="message_normalized",
                category="canonical",
                action="normalize_message",
                result="success",
                description=f"Message {canonical_message.id} normalized from {source_plugin} to {target_plugin}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={
                    "message_id": canonical_message.id,
                    "target_plugin": target_plugin,
                },
            )

            return canonical_message

        except Exception as e:
            logger.error(f"Failed to normalize message: {e}")
            await self.audit_service.log_event(
                event_type="message_normalization_failed",
                category="canonical",
                action="normalize_message",
                result="failed",
                description=f"Failed to normalize message: {str(e)}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={"error": str(e)},
            )
            raise

    async def normalize_event(
        self, event_data: Dict[str, Any], source_plugin: str, target_plugin: str
    ) -> CanonicalEvent:
        """Normalize event data to canonical format."""
        try:
            # Check if transformation is allowed
            if not await self._can_transform_data(
                source_plugin, target_plugin, "event"
            ):
                raise PermissionError(
                    f"Plugin {source_plugin} not authorized to transform event data for {target_plugin}"
                )

            canonical_event = await self.transformer.transform_event_to_canonical(
                event_data, source_plugin, target_plugin
            )

            # Store canonical data
            self.canonical_store[f"event:{canonical_event.event_id}"] = canonical_event

            await self.audit_service.log_event(
                event_type="event_normalized",
                category="canonical",
                action="normalize_event",
                result="success",
                description=f"Event {canonical_event.event_id} normalized from {source_plugin} to {target_plugin}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={
                    "event_id": canonical_event.event_id,
                    "target_plugin": target_plugin,
                },
            )

            return canonical_event

        except Exception as e:
            logger.error(f"Failed to normalize event: {e}")
            await self.audit_service.log_event(
                event_type="event_normalization_failed",
                category="canonical",
                action="normalize_event",
                result="failed",
                description=f"Failed to normalize event: {str(e)}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={"error": str(e)},
            )
            raise

    async def denormalize_data(
        self,
        canonical_data: Any,
        target_format: str,
        source_plugin: str,
        target_plugin: str,
    ) -> Dict[str, Any]:
        """Convert canonical data to plugin-specific format."""
        try:
            # Check if transformation is allowed
            if not await self._can_transform_data(
                source_plugin, target_plugin, "denormalize"
            ):
                raise PermissionError(
                    f"Plugin {source_plugin} not authorized to denormalize data for {target_plugin}"
                )

            plugin_data = await self.transformer.transform_from_canonical(
                canonical_data, target_format, source_plugin, target_plugin
            )

            await self.audit_service.log_event(
                event_type="data_denormalized",
                category="canonical",
                action="denormalize_data",
                result="success",
                description=f"Data denormalized from canonical to {target_format} for {target_plugin}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={
                    "target_format": target_format,
                    "target_plugin": target_plugin,
                },
            )

            return plugin_data

        except Exception as e:
            logger.error(f"Failed to denormalize data: {e}")
            await self.audit_service.log_event(
                event_type="data_denormalization_failed",
                category="canonical",
                action="denormalize_data",
                result="failed",
                description=f"Failed to denormalize data: {str(e)}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={"error": str(e)},
            )
            raise

    async def get_canonical_data(self, data_type: str, data_id: str) -> Optional[Any]:
        """Get canonical data by type and ID."""
        key = f"{data_type}:{data_id}"
        return self.canonical_store.get(key)

    async def list_canonical_data(
        self, data_type: str | None = None, limit: int = 100, offset: int = 0
    ) -> List[Any]:
        """List canonical data with optional filtering."""
        items = list(self.canonical_store.values())

        if data_type:
            items = [
                item
                for item in items
                if f"{data_type}:" in str(type(item).__name__).lower()
            ]

        return items[offset : offset + limit]

    async def _can_transform_data(
        self, source_plugin: str, target_plugin: str, data_type: str
    ) -> bool:
        """Check if plugin can transform data."""
        # Create policy request
        request = PolicyRequest(
            user_id=None,
            resource_type="canonical",
            resource_id=f"{source_plugin}->{target_plugin}",
            action="transform_data",
            traits=[],
            context={"data_type": data_type},
            policy_context=PolicyContext.PLUGIN_INTERACTION,
            source_plugin=source_plugin,
            target_plugin=target_plugin,
        )

        result = await self.policy_engine.evaluate_request(request)
        return result.decision == PolicyDecision.ALLOW

    async def get_transformation_stats(self) -> Dict[str, Any]:
        """Get canonical service statistics."""
        total_canonical = len(self.canonical_store)
        transformation_history = self.transformer.get_transformation_history()

        # Count by data type
        data_types: Dict[str, int] = {}
        for key in self.canonical_store.keys():
            data_type = key.split(":")[0]
            data_types[data_type] = data_types.get(data_type, 0) + 1

        # Count successful vs failed transformations
        successful_transformations = sum(1 for t in transformation_history if t.success)
        failed_transformations = sum(1 for t in transformation_history if not t.success)

        return {
            "total_canonical_data": total_canonical,
            "data_types": data_types,
            "total_transformations": len(transformation_history),
            "successful_transformations": successful_transformations,
            "failed_transformations": failed_transformations,
        }
