"""
Event bus implementation for canonical communication.
"""

import asyncio
import logging
from typing import Dict, List, Optional, Callable, Protocol, Any
import os
import json
import asyncio
import logging
from contextlib import asynccontextmanager

from .models import Event, Message, MessageDeliveryStatus
from ..audit.service import AuditService, AuditLevel
from ..policy.engine import PolicyEngine, PolicyRequest, PolicyDecision

logger = logging.getLogger(__name__)


class BrokerClient(Protocol):
    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    async def publish(self, subject: str, data: bytes) -> None: ...
    async def subscribe(self, subject: str, handler: Callable[[bytes], Any]) -> Any: ...


class InMemoryBroker:
    """Simple in-memory broker used by default and for tests."""

    def __init__(self) -> None:
        self._subs: Dict[str, List[Callable[[bytes], Any]]] = {}
        self._running = False

    async def start(self) -> None:
        self._running = True

    async def stop(self) -> None:
        self._running = False
        self._subs.clear()

    async def publish(self, subject: str, data: bytes) -> None:
        for handler in list(self._subs.get(subject, [])):
            try:
                await handler(data)
            except Exception as e:  # noqa: BLE001
                logger.exception("InMemoryBroker handler error: %s", e)

    async def subscribe(self, subject: str, handler: Callable[[bytes], Any]) -> Any:
        self._subs.setdefault(subject, []).append(handler)
        return handler


class NatsBroker:
    """NATS broker adapter (uses nats-py)."""

    def __init__(self, servers: str) -> None:
        self._servers = servers
        self._nc = None
        self._subs: List[Any] = []

    async def start(self) -> None:
        import nats  # type: ignore

        if self._nc is None:
            self._nc = await nats.connect(servers=self._servers)

    async def stop(self) -> None:
        if self._nc is not None:
            try:
                for sub in self._subs:
                    await sub.unsubscribe()
            finally:
                await self._nc.drain()
                await self._nc.close()
            self._nc = None

    async def publish(self, subject: str, data: bytes) -> None:
        assert self._nc is not None
        await self._nc.publish(subject, data)

    async def subscribe(self, subject: str, handler: Callable[[bytes], Any]) -> Any:
        assert self._nc is not None

        async def _wrapped(msg):
            try:
                await handler(msg.data)
            except Exception as e:  # noqa: BLE001
                logger.exception("NATS handler error: %s", e)

        sub = await self._nc.subscribe(subject, cb=_wrapped)
        self._subs.append(sub)
        return sub


class RedisBroker:
    """Redis Pub/Sub adapter (uses redis asyncio client)."""

    def __init__(self, url: str) -> None:
        self._url = url
        self._redis = None
        self._pub = None
        self._ps = None
        self._tasks: List[asyncio.Task] = []

    async def start(self) -> None:
        import redis.asyncio as redis  # type: ignore

        self._redis = redis.from_url(self._url)
        self._pub = self._redis
        self._ps = self._redis.pubsub()

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        self._tasks.clear()
        if self._ps is not None:
            await self._ps.close()
            self._ps = None
        if self._redis is not None:
            await self._redis.close()
            self._redis = None

    async def publish(self, subject: str, data: bytes) -> None:
        assert self._pub is not None
        await self._pub.publish(subject, data)

    async def subscribe(self, subject: str, handler: Callable[[bytes], Any]) -> Any:
        assert self._ps is not None
        await self._ps.subscribe(subject)

        async def _reader():
            assert self._ps is not None
            while True:
                try:
                    msg = await self._ps.get_message(ignore_subscribe_messages=True, timeout=1.0)
                    if msg and msg.get("type") == "message":
                        data = msg.get("data")
                        if isinstance(data, (bytes, bytearray)):
                            await handler(data)
                except asyncio.CancelledError:
                    break
                except Exception as e:  # noqa: BLE001
                    logger.exception("Redis handler error: %s", e)

        task = asyncio.create_task(_reader())
        self._tasks.append(task)
        return task


def _select_broker_from_env() -> BrokerClient:
    backend = os.getenv("EVENT_BUS_BACKEND", "memory").lower()
    if backend == "nats":
        servers = os.getenv("NATS_SERVERS", "nats://127.0.0.1:4222")
        return NatsBroker(servers)
    if backend == "redis":
        url = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
        return RedisBroker(url)
    return InMemoryBroker()


class EventBus:
    """Event bus for canonical inter-plugin communication."""

    def __init__(self, audit_service: AuditService, policy_engine: PolicyEngine, broker: Optional[BrokerClient] = None):
        self.audit_service = audit_service
        self.policy_engine = policy_engine
        self.subscribers: Dict[str, List[Callable]] = {}
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.delivery_tracking: Dict[str, MessageDeliveryStatus] = {}
        self._running = False
        self._processing_task: Optional[asyncio.Task] = None
        self._broker: BrokerClient = broker or _select_broker_from_env()

    async def start(self):
        """Start the event bus processing."""
        if self._running:
            return

        self._running = True
        await self._broker.start()
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
        await self._broker.stop()
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

            # Publish to broker subject for fan-out and also enqueue locally
            subject = f"events.{event.event_type}"
            payload = json.dumps({
                "event": event.dict(),
                "source_plugin": source_plugin,
            }).encode("utf-8")
            await self._broker.publish(subject, payload)
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

            # Publish to broker subject for direct messaging and enqueue locally
            subject = f"messages.{message.target_plugin}"
            payload = json.dumps({
                "message": message.dict(),
                "source_plugin": source_plugin,
            }).encode("utf-8")
            await self._broker.publish(subject, payload)
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
        async def _handler_factory(user_callback: Callable):
            async def _wrapped(data: bytes):
                try:
                    obj = json.loads(data.decode("utf-8"))
                    raw_event = obj.get("event") or {}
                    evt = Event(**raw_event)
                    source_plugin = obj.get("source_plugin", "unknown")
                    await user_callback(evt, source_plugin)
                except Exception as e:  # noqa: BLE001
                    logger.exception("Subscriber callback error: %s", e)

            return _wrapped

        for event_type in event_types:
            if event_type not in self.subscribers:
                self.subscribers[event_type] = []
            self.subscribers[event_type].append(callback)
            # Also subscribe at broker level
            subject = f"events.{event_type}"
            handler = await _handler_factory(callback)
            await self._broker.subscribe(subject, handler)

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
