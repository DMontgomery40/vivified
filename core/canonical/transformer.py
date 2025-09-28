"""
Data transformation utilities for canonical formats.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from .models import CanonicalUser, CanonicalMessage, CanonicalEvent, DataTransformation
from ..audit.service import AuditService, AuditLevel

logger = logging.getLogger(__name__)


class DataTransformer:
    """Transforms data between plugin-specific and canonical formats."""
    
    def __init__(self, audit_service: AuditService):
        self.audit_service = audit_service
        self.transformations: List[DataTransformation] = []

    async def transform_user_to_canonical(
        self,
        user_data: Dict[str, Any],
        source_plugin: str,
        target_plugin: str
    ) -> CanonicalUser:
        """Transform user data to canonical format."""
        try:
            canonical_user = CanonicalUser(
                id=user_data.get("id", ""),
                username=user_data.get("username", ""),
                email=user_data.get("email", ""),
                roles=user_data.get("roles", []),
                traits=user_data.get("traits", []),
                created_at=user_data.get("created_at", datetime.utcnow()),
                attributes=user_data.get("attributes", {})
            )
            
            # Log transformation
            await self._log_transformation(
                "user",
                "canonical",
                source_plugin,
                target_plugin,
                True
            )
            
            return canonical_user
            
        except Exception as e:
            logger.error(f"Failed to transform user to canonical: {e}")
            await self._log_transformation(
                "user",
                "canonical", 
                source_plugin,
                target_plugin,
                False,
                str(e)
            )
            raise

    async def transform_message_to_canonical(
        self,
        message_data: Dict[str, Any],
        source_plugin: str,
        target_plugin: str
    ) -> CanonicalMessage:
        """Transform message data to canonical format."""
        try:
            # Handle content conversion
            content = message_data.get("content", "")
            if isinstance(content, str):
                content = content.encode("utf-8")
            
            canonical_message = CanonicalMessage(
                id=message_data.get("id", ""),
                from_user=message_data.get("from_user", ""),
                to_user=message_data.get("to_user", ""),
                content_type=message_data.get("content_type", "text/plain"),
                content=content,
                data_traits=message_data.get("data_traits", []),
                sent_at=message_data.get("sent_at", datetime.utcnow()),
                metadata=message_data.get("metadata", {})
            )
            
            # Log transformation
            await self._log_transformation(
                "message",
                "canonical",
                source_plugin,
                target_plugin,
                True
            )
            
            return canonical_message
            
        except Exception as e:
            logger.error(f"Failed to transform message to canonical: {e}")
            await self._log_transformation(
                "message",
                "canonical",
                source_plugin,
                target_plugin,
                False,
                str(e)
            )
            raise

    async def transform_event_to_canonical(
        self,
        event_data: Dict[str, Any],
        source_plugin: str,
        target_plugin: str
    ) -> CanonicalEvent:
        """Transform event data to canonical format."""
        try:
            canonical_event = CanonicalEvent(
                event_id=event_data.get("event_id", ""),
                trace_id=event_data.get("trace_id", ""),
                event_type=event_data.get("event_type", ""),
                timestamp=event_data.get("timestamp", datetime.utcnow()),
                source_plugin=event_data.get("source_plugin", source_plugin),
                data_traits=event_data.get("data_traits", []),
                payload=event_data.get("payload", {}),
                metadata=event_data.get("metadata", {})
            )
            
            # Log transformation
            await self._log_transformation(
                "event",
                "canonical",
                source_plugin,
                target_plugin,
                True
            )
            
            return canonical_event
            
        except Exception as e:
            logger.error(f"Failed to transform event to canonical: {e}")
            await self._log_transformation(
                "event",
                "canonical",
                source_plugin,
                target_plugin,
                False,
                str(e)
            )
            raise

    async def transform_from_canonical(
        self,
        canonical_data: Any,
        target_format: str,
        source_plugin: str,
        target_plugin: str
    ) -> Dict[str, Any]:
        """Transform canonical data to plugin-specific format."""
        try:
            if isinstance(canonical_data, CanonicalUser):
                result = {
                    "id": canonical_data.id,
                    "username": canonical_data.username,
                    "email": canonical_data.email,
                    "roles": canonical_data.roles,
                    "traits": canonical_data.traits,
                    "created_at": canonical_data.created_at.isoformat(),
                    "attributes": canonical_data.attributes
                }
            elif isinstance(canonical_data, CanonicalMessage):
                result = {
                    "id": canonical_data.id,
                    "from_user": canonical_data.from_user,
                    "to_user": canonical_data.to_user,
                    "content_type": canonical_data.content_type,
                    "content": canonical_data.content.decode("utf-8") if isinstance(canonical_data.content, bytes) else canonical_data.content,
                    "data_traits": canonical_data.data_traits,
                    "sent_at": canonical_data.sent_at.isoformat(),
                    "metadata": canonical_data.metadata
                }
            elif isinstance(canonical_data, CanonicalEvent):
                result = {
                    "event_id": canonical_data.event_id,
                    "trace_id": canonical_data.trace_id,
                    "event_type": canonical_data.event_type,
                    "timestamp": canonical_data.timestamp.isoformat(),
                    "source_plugin": canonical_data.source_plugin,
                    "data_traits": canonical_data.data_traits,
                    "payload": canonical_data.payload,
                    "metadata": canonical_data.metadata
                }
            else:
                raise ValueError(f"Unknown canonical data type: {type(canonical_data)}")
            
            # Log transformation
            await self._log_transformation(
                "canonical",
                target_format,
                source_plugin,
                target_plugin,
                True
            )
            
            return result
            
        except Exception as e:
            logger.error(f"Failed to transform from canonical: {e}")
            await self._log_transformation(
                "canonical",
                target_format,
                source_plugin,
                target_plugin,
                False,
                str(e)
            )
            raise

    async def _log_transformation(
        self,
        source_format: str,
        target_format: str,
        source_plugin: str,
        target_plugin: str,
        success: bool,
        error_message: Optional[str] = None
    ):
        """Log data transformation."""
        transformation = DataTransformation(
            source_format=source_format,
            target_format=target_format,
            transformation_type="data_transform",
            source_plugin=source_plugin,
            target_plugin=target_plugin,
            success=success,
            error_message=error_message
        )
        
        self.transformations.append(transformation)
        
        # Audit log
        await self.audit_service.log_event(
            event_type="data_transformation",
            category="canonical",
            action="transform_data",
            result="success" if success else "failed",
            description=f"Data transformation from {source_format} to {target_format}",
            plugin_id=source_plugin,
            level=AuditLevel.STANDARD,
            details={
                "source_format": source_format,
                "target_format": target_format,
                "target_plugin": target_plugin,
                "success": success,
                "error": error_message
            }
        )

    def get_transformation_history(self) -> List[DataTransformation]:
        """Get transformation history."""
        return self.transformations.copy()
