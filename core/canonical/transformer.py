"""
Data transformation utilities for canonical formats.
"""

import logging
from typing import Dict, Any, Optional, List
from datetime import datetime

from .models import CanonicalUser, CanonicalMessage, CanonicalEvent, DataTransformation
from ..audit.service import AuditService, AuditLevel
from ..config.service import ConfigService, get_config_service

logger = logging.getLogger(__name__)


class DataTransformer:
    """Transforms data between plugin-specific and canonical formats."""

    def __init__(
        self,
        audit_service: AuditService,
        config_service: Optional[ConfigService] = None,
    ):
        self.audit_service = audit_service
        self.config_service = config_service or get_config_service()
        self.transformations: List[DataTransformation] = []
        self._map_cache: Dict[str, Dict[str, Any]] = {}

    async def _get_mapping(
        self, source_plugin: str, target_plugin: str
    ) -> Dict[str, Any]:
        key = f"{source_plugin}->{target_plugin}"
        if key in self._map_cache:
            return self._map_cache[key]
        try:
            if self.config_service is None:
                return {}
            cfg_key = f"canonical.transforms.{source_plugin}->{target_plugin}"
            data = await self.config_service.get(cfg_key) or {}
            if not isinstance(data, dict):
                data = {}
            self._map_cache[key] = data
            return data
        except Exception:
            return {}

    @staticmethod
    def _get_path(data: Dict[str, Any], path: str) -> Any:
        cur: Any = data
        for p in (path.split(".") if path else []):
            if isinstance(cur, dict) and p in cur:
                cur = cur[p]
            else:
                return None
        return cur

    @staticmethod
    def _set_path(obj: Dict[str, Any], path: str, value: Any) -> None:
        parts = path.split(".") if path else []
        cur = obj
        for p in parts[:-1]:
            if p not in cur or not isinstance(cur[p], dict):
                cur[p] = {}
            cur = cur[p]
        if parts:
            cur[parts[-1]] = value

    async def transform_user_to_canonical(
        self, user_data: Dict[str, Any], source_plugin: str, target_plugin: str
    ) -> CanonicalUser:
        """Transform user data to canonical format."""
        try:
            # Apply mapping if supplied
            mapping = await self._get_mapping(source_plugin, target_plugin)
            mapped: Dict[str, Any] = {}
            for k, v in (mapping.get("user_to_canonical") or {}).items():
                val = self._get_path(user_data, str(v))
                if val is not None:
                    self._set_path(mapped, str(k), val)

            canonical_user = CanonicalUser(
                id=user_data.get("id", ""),
                username=user_data.get("username", ""),
                email=user_data.get("email", ""),
                roles=user_data.get("roles", []),
                traits=user_data.get("traits", []),
                created_at=user_data.get("created_at", datetime.utcnow()),
                attributes=(
                    {**user_data.get("attributes", {}), **mapped.get("attributes", {})}
                    if mapped
                    else user_data.get("attributes", {})
                ),
            )

            # Log transformation
            await self._log_transformation(
                "user", "canonical", source_plugin, target_plugin, True
            )

            return canonical_user

        except Exception as e:
            logger.error(f"Failed to transform user to canonical: {e}")
            await self._log_transformation(
                "user", "canonical", source_plugin, target_plugin, False, str(e)
            )
            raise

    async def transform_message_to_canonical(
        self, message_data: Dict[str, Any], source_plugin: str, target_plugin: str
    ) -> CanonicalMessage:
        """Transform message data to canonical format."""
        try:
            # Handle content conversion
            content = message_data.get("content", "")
            if isinstance(content, str):
                content = content.encode("utf-8")

            mapping = await self._get_mapping(source_plugin, target_plugin)
            mapped_content = None
            if mapping.get("message_to_canonical"):
                # If mapping defines content, prefer that
                src_path = mapping["message_to_canonical"].get("content")
                if src_path:
                    mapped_content = self._get_path(message_data, str(src_path))
                    if isinstance(mapped_content, str):
                        mapped_content = mapped_content.encode("utf-8")

            canonical_message = CanonicalMessage(
                id=message_data.get("id", ""),
                from_user=message_data.get("from_user", ""),
                to_user=message_data.get("to_user", ""),
                content_type=message_data.get("content_type", "text/plain"),
                content=mapped_content if mapped_content is not None else content,
                data_traits=message_data.get("data_traits", []),
                sent_at=message_data.get("sent_at", datetime.utcnow()),
                metadata=message_data.get("metadata", {}),
            )

            # Log transformation
            await self._log_transformation(
                "message", "canonical", source_plugin, target_plugin, True
            )

            return canonical_message

        except Exception as e:
            logger.error(f"Failed to transform message to canonical: {e}")
            await self._log_transformation(
                "message", "canonical", source_plugin, target_plugin, False, str(e)
            )
            raise

    async def transform_event_to_canonical(
        self, event_data: Dict[str, Any], source_plugin: str, target_plugin: str
    ) -> CanonicalEvent:
        """Transform event data to canonical format."""
        try:
            mapping = await self._get_mapping(source_plugin, target_plugin)
            override_payload = (
                mapping.get("event_to_canonical", {}).get("payload")
                if isinstance(mapping.get("event_to_canonical"), dict)
                else None
            )
            new_payload = event_data.get("payload", {})
            if isinstance(override_payload, dict):
                new_payload = {**new_payload, **override_payload}

            canonical_event = CanonicalEvent(
                event_id=event_data.get("event_id", ""),
                trace_id=event_data.get("trace_id", ""),
                event_type=event_data.get("event_type", ""),
                timestamp=event_data.get("timestamp", datetime.utcnow()),
                source_plugin=event_data.get("source_plugin", source_plugin),
                data_traits=event_data.get("data_traits", []),
                payload=new_payload,
                metadata=event_data.get("metadata", {}),
            )

            # Log transformation
            await self._log_transformation(
                "event", "canonical", source_plugin, target_plugin, True
            )

            return canonical_event

        except Exception as e:
            logger.error(f"Failed to transform event to canonical: {e}")
            await self._log_transformation(
                "event", "canonical", source_plugin, target_plugin, False, str(e)
            )
            raise

    async def transform_from_canonical(
        self,
        canonical_data: Any,
        target_format: str,
        source_plugin: str,
        target_plugin: str,
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
                    "attributes": canonical_data.attributes,
                }
                mapping = await self._get_mapping(source_plugin, target_plugin)
                for k, v in (mapping.get("user_from_canonical") or {}).items():
                    val = self._get_path(result, str(v))
                    if val is not None:
                        self._set_path(result, str(k), val)
            elif isinstance(canonical_data, CanonicalMessage):
                result = {
                    "id": canonical_data.id,
                    "from_user": canonical_data.from_user,
                    "to_user": canonical_data.to_user,
                    "content_type": canonical_data.content_type,
                    "content": (
                        canonical_data.content.decode("utf-8")
                        if isinstance(canonical_data.content, bytes)
                        else canonical_data.content
                    ),
                    "data_traits": canonical_data.data_traits,
                    "sent_at": canonical_data.sent_at.isoformat(),
                    "metadata": canonical_data.metadata,
                }
                mapping = await self._get_mapping(source_plugin, target_plugin)
                for k, v in (mapping.get("message_from_canonical") or {}).items():
                    val = self._get_path(result, str(v))
                    if val is not None:
                        self._set_path(result, str(k), val)
            elif isinstance(canonical_data, CanonicalEvent):
                result = {
                    "event_id": canonical_data.event_id,
                    "trace_id": canonical_data.trace_id,
                    "event_type": canonical_data.event_type,
                    "timestamp": canonical_data.timestamp.isoformat(),
                    "source_plugin": canonical_data.source_plugin,
                    "data_traits": canonical_data.data_traits,
                    "payload": canonical_data.payload,
                    "metadata": canonical_data.metadata,
                }
                mapping = await self._get_mapping(source_plugin, target_plugin)
                for k, v in (mapping.get("event_from_canonical") or {}).items():
                    val = self._get_path(result, str(v))
                    if val is not None:
                        self._set_path(result, str(k), val)
            else:
                raise ValueError(f"Unknown canonical data type: {type(canonical_data)}")

            # Log transformation
            await self._log_transformation(
                "canonical", target_format, source_plugin, target_plugin, True
            )

            return result

        except Exception as e:
            logger.error(f"Failed to transform from canonical: {e}")
            await self._log_transformation(
                "canonical", target_format, source_plugin, target_plugin, False, str(e)
            )
            raise

    async def _log_transformation(
        self,
        source_format: str,
        target_format: str,
        source_plugin: str,
        target_plugin: str,
        success: bool,
        error_message: Optional[str] = None,
    ):
        """Log data transformation."""
        transformation = DataTransformation(
            source_format=source_format,
            target_format=target_format,
            transformation_type="data_transform",
            source_plugin=source_plugin,
            target_plugin=target_plugin,
            success=success,
            error_message=error_message,
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
                "error": error_message,
            },
        )

    def get_transformation_history(self) -> List[DataTransformation]:
        """Get transformation history."""
        return self.transformations.copy()
