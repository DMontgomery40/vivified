"""
Messaging service for inter-plugin communication with HIPAA compliance.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime

from .models import Message, Event, MessageFilter
from .event_bus import EventBus
from ..audit.service import AuditService, AuditLevel
from ..policy.engine import PolicyEngine

logger = logging.getLogger(__name__)


class MessagingService:
    """Main messaging service for inter-plugin communication."""

    def __init__(self, audit_service: AuditService, policy_engine: PolicyEngine, registry: Optional[Any] = None):
        self.audit_service = audit_service
        self.policy_engine = policy_engine
        # EventBus will auto-select broker via env (EVENT_BUS_BACKEND=nats|redis|memory)
        from .dispatch import PluginDispatcher

        dispatcher = PluginDispatcher(registry) if registry is not None else None
        self.event_bus = EventBus(audit_service, policy_engine, dispatcher=dispatcher)
        self.message_store: Dict[str, Message] = {}
        self.event_store: Dict[str, Event] = {}
        self._running = False

    async def start(self):
        """Start the messaging service."""
        if self._running:
            return

        await self.event_bus.start()
        self._running = True
        logger.info("Messaging service started")

    async def stop(self):
        """Stop the messaging service."""
        if not self._running:
            return

        await self.event_bus.stop()
        self._running = False
        logger.info("Messaging service stopped")

    async def publish_event(
        self,
        event_type: str,
        payload: Dict[str, Any],
        source_plugin: str,
        data_traits: Optional[List[str]] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> str:
        """Publish an event to the event bus."""
        event = Event(
            event_type=event_type,
            source_plugin=source_plugin,
            data_traits=data_traits or [],
            payload=payload,
            metadata=metadata or {},
        )

        success = await self.event_bus.publish_event(event, source_plugin)
        if success:
            self.event_store[event.event_id] = event
            return event.event_id
        else:
            raise PermissionError(
                f"Plugin {source_plugin} not authorized to publish event {event_type}"
            )

    async def send_message(
        self,
        target_plugin: str,
        message_type: str,
        payload: Dict[str, Any],
        source_plugin: str,
        data_classification: str = "internal",
        traits: Optional[List[str]] = None,
        correlation_id: Optional[str] = None,
        reply_to: Optional[str] = None,
        expires_at: Optional[datetime] = None,
    ) -> str:
        """Send a message to a specific plugin."""
        message = Message(
            message_type=message_type,
            source_plugin=source_plugin,
            target_plugin=target_plugin,
            payload=payload,
            data_classification=data_classification,
            traits=traits or [],
            correlation_id=correlation_id,
            reply_to=reply_to,
            expires_at=expires_at,
        )

        success = await self.event_bus.send_message(message, source_plugin)
        if success:
            self.message_store[message.id] = message
            return message.id
        else:
            raise PermissionError(
                f"Plugin {source_plugin} not authorized to send message to {target_plugin}"
            )

    async def subscribe_to_events(
        self, plugin_id: str, event_types: List[str], callback: Callable[..., Any]
    ) -> None:
        """Subscribe a plugin to specific event types."""
        await self.event_bus.subscribe(plugin_id, event_types, callback)

        await self.audit_service.log_event(
            event_type="event_subscription",
            category="messaging",
            action="subscribe",
            result="success",
            description=f"Plugin {plugin_id} subscribed to events: {event_types}",
            plugin_id=plugin_id,
            level=AuditLevel.STANDARD,
            details={"event_types": event_types},
        )

    async def get_messages(
        self, filter_criteria: MessageFilter, limit: int = 100, offset: int = 0
    ) -> List[Message]:
        """Get messages matching filter criteria."""
        messages = list(self.message_store.values())

        # Apply filters
        if filter_criteria.message_types:
            messages = [
                m for m in messages if m.message_type in filter_criteria.message_types
            ]

        if filter_criteria.source_plugins:
            messages = [
                m for m in messages if m.source_plugin in filter_criteria.source_plugins
            ]

        if filter_criteria.target_plugins:
            messages = [
                m for m in messages if m.target_plugin in filter_criteria.target_plugins
            ]

        if filter_criteria.data_classifications:
            messages = [
                m
                for m in messages
                if m.data_classification in filter_criteria.data_classifications
            ]

        if filter_criteria.traits:
            messages = [
                m
                for m in messages
                if any(trait in m.traits for trait in filter_criteria.traits)
            ]

        if filter_criteria.priority:
            messages = [m for m in messages if m.priority == filter_criteria.priority]

        if filter_criteria.created_after:
            messages = [
                m for m in messages if m.created_at >= filter_criteria.created_after
            ]

        if filter_criteria.created_before:
            messages = [
                m for m in messages if m.created_at <= filter_criteria.created_before
            ]

        if filter_criteria.correlation_id:
            messages = [
                m
                for m in messages
                if m.correlation_id == filter_criteria.correlation_id
            ]

        # Sort by creation time (newest first)
        messages.sort(key=lambda m: m.created_at, reverse=True)

        return messages[offset : offset + limit]

    async def get_events(
        self,
        event_types: Optional[List[str]] = None,
        source_plugins: Optional[List[str]] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Event]:
        """Get events matching criteria."""
        events = list(self.event_store.values())

        if event_types:
            events = [e for e in events if e.event_type in event_types]

        if source_plugins:
            events = [e for e in events if e.source_plugin in source_plugins]

        # Sort by timestamp (newest first)
        events.sort(key=lambda e: e.timestamp, reverse=True)

        return events[offset : offset + limit]

    async def get_message(self, message_id: str) -> Optional[Message]:
        """Get a specific message by ID."""
        return self.message_store.get(message_id)

    async def get_event(self, event_id: str) -> Optional[Event]:
        """Get a specific event by ID."""
        return self.event_store.get(event_id)

    async def cleanup_expired_messages(self):
        """Clean up expired messages."""
        now = datetime.utcnow()
        expired_messages = [
            msg_id
            for msg_id, message in self.message_store.items()
            if message.expires_at and message.expires_at < now
        ]

        for msg_id in expired_messages:
            del self.message_store[msg_id]

        if expired_messages:
            logger.info(f"Cleaned up {len(expired_messages)} expired messages")

    async def get_message_stats(self) -> Dict[str, Any]:
        """Get messaging statistics."""
        total_messages = len(self.message_store)
        total_events = len(self.event_store)

        # Count by message type
        message_types: Dict[str, int] = {}
        for message in self.message_store.values():
            msg_type = message.message_type
            message_types[msg_type] = message_types.get(msg_type, 0) + 1

        # Count by data classification
        classifications: Dict[str, int] = {}
        for message in self.message_store.values():
            classification = message.data_classification
            classifications[classification] = classifications.get(classification, 0) + 1

        return {
            "total_messages": total_messages,
            "total_events": total_events,
            "message_types": message_types,
            "data_classifications": classifications,
            "subscribers": len(self.event_bus.subscribers),
        }
