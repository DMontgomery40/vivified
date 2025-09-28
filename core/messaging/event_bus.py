"""
Event bus implementation for canonical communication.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Callable

from .models import Event, Message, MessageDeliveryStatus
from ..audit.service import AuditService, AuditLevel
from ..policy.engine import PolicyEngine, PolicyRequest, PolicyDecision

logger = logging.getLogger(__name__)


class EventBus:
    """Event bus for canonical inter-plugin communication."""

    def __init__(self, audit_service: AuditService, policy_engine: PolicyEngine):
        self.audit_service = audit_service
        self.policy_engine = policy_engine
        self.subscribers: Dict[str, List[Callable]] = {}
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.delivery_tracking: Dict[str, MessageDeliveryStatus] = {}
        self._running = False
        self._processing_task: Optional[asyncio.Task] = None

    async def start(self):
        """Start the event bus processing."""
        if self._running:
            return

        self._running = True
        self._processing_task = asyncio.create_task(self._process_messages())
        logger.info("Event bus started")

    async def stop(self):
        """Stop the event bus processing."""
        self._running = False
        if self._processing_task:
            self._processing_task.cancel()
            try:
                await self._processing_task
            except asyncio.CancelledError:
                pass
        logger.info("Event bus stopped")

    async def publish_event(self, event: Event, source_plugin: str) -> bool:
        """Publish an event to the bus."""
        try:
            # Check if source plugin can publish this event type
            if not await self._can_publish_event(source_plugin, event):
                await self.audit_service.log_event(
                    event_type="event_publish_denied",
                    category="security",
                    action="publish_event",
                    result="denied",
                    description=f"Plugin {source_plugin} denied event publish",
                    plugin_id=source_plugin,
                    level=AuditLevel.STANDARD,
                    details={"event_type": event.event_type},
                )
                return False

            # Add to processing queue
            await self.message_queue.put(("event", event, source_plugin))

            await self.audit_service.log_event(
                event_type="event_published",
                category="messaging",
                action="publish_event",
                result="success",
                description=f"Event {event.event_type} published by {source_plugin}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={"event_id": event.event_id, "event_type": event.event_type},
            )

            return True

        except Exception as e:
            logger.error(f"Failed to publish event: {e}")
            await self.audit_service.log_event(
                event_type="event_publish_failed",
                category="messaging",
                action="publish_event",
                result="failed",
                description="Failed to publish event",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={"error": str(e)},
            )
            return False

    async def send_message(self, message: Message, source_plugin: str) -> bool:
        """Send a message to a specific plugin."""
        try:
            # Check if source plugin can send this message
            if not await self._can_send_message(source_plugin, message):
                await self.audit_service.log_event(
                    event_type="message_send_denied",
                    category="security",
                    action="send_message",
                    result="denied",
                    description=f"Plugin {source_plugin} denied message send",
                    plugin_id=source_plugin,
                    level=AuditLevel.STANDARD,
                    details={"target_plugin": message.target_plugin},
                )
                return False

            # Add to processing queue
            await self.message_queue.put(("message", message, source_plugin))

            await self.audit_service.log_event(
                event_type="message_sent",
                category="messaging",
                action="send_message",
                result="success",
                description=(
                    f"Message sent from {source_plugin} to {message.target_plugin}"
                ),
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={
                    "message_id": message.id,
                    "target_plugin": message.target_plugin,
                },
            )

            return True

        except Exception as e:
            logger.error(f"Failed to send message: {e}")
            await self.audit_service.log_event(
                event_type="message_send_failed",
                category="messaging",
                action="send_message",
                result="failed",
                description=f"Failed to send message: {str(e)}",
                plugin_id=source_plugin,
                level=AuditLevel.STANDARD,
                details={"error": str(e)},
            )
            return False

    async def subscribe(
        self, plugin_id: str, event_types: List[str], callback: Callable
    ):
        """Subscribe a plugin to specific event types."""
        for event_type in event_types:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            self.subscribers[event_type].append(callback)

        logger.info(f"Plugin {plugin_id} subscribed to events: {event_types}")

    async def unsubscribe(self, plugin_id: str, event_types: List[str]):
        """Unsubscribe a plugin from specific event types."""
        for event_type in event_types:
            if event_type in self.subscribers:
                # Remove callbacks for this plugin (simplified - in real
                # implementation would track plugin-specific callbacks)
                self.subscribers[event_type] = []

        logger.info(f"Plugin {plugin_id} unsubscribed from events: {event_types}")

    async def _process_messages(self):
        """Process messages from the queue."""
        while self._running:
            try:
                message_type, content, source_plugin = await asyncio.wait_for(
                    self.message_queue.get(), timeout=1.0
                )

                if message_type == "event":
                    await self._process_event(content, source_plugin)
                elif message_type == "message":
                    await self._process_message(content, source_plugin)

            except asyncio.TimeoutError:
                continue
            except Exception as e:
                logger.error(f"Error processing message: {e}")

    async def _process_event(self, event: Event, source_plugin: str):
        """Process an event by notifying subscribers."""
        event_type = event.event_type

        if event_type in self.subscribers:
            for callback in self.subscribers[event_type]:
                try:
                    await callback(event, source_plugin)
                except Exception as e:
                    logger.error(f"Error in event callback: {e}")

    async def _process_message(self, message: Message, source_plugin: str):
        """Process a message by delivering to target plugin."""
        if not message.target_plugin:
            logger.warning(f"Message {message.id} has no target plugin")
            return

        # In a real implementation, this would route to the actual plugin
        # For now, we'll just log the delivery
        logger.info(f"Message {message.id} delivered to {message.target_plugin}")

    async def _can_publish_event(self, source_plugin: str, event: Event) -> bool:
        """Check if plugin can publish this event using the policy engine."""
        request = PolicyRequest(
            user_id=source_plugin,
            resource_type="event_bus",
            resource_id=event.event_type,
            action="publish_event",
            traits=[],
            context={"data_traits": event.data_traits},
        )
        result = await self.policy_engine.evaluate_request(request)
        return result.decision == PolicyDecision.ALLOW

    async def _can_send_message(self, source_plugin: str, message: Message) -> bool:
        """Check if plugin can send this message using the policy engine."""
        request = PolicyRequest(
            user_id=source_plugin,
            resource_type="plugin",
            resource_id=message.target_plugin or "unknown",
            action="send_message",
            traits=[],
            context={
                "message_type": message.message_type,
                "data_classification": message.data_classification,
            },
        )
        result = await self.policy_engine.evaluate_request(request)
        return result.decision == PolicyDecision.ALLOW
