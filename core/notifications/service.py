"""
Notifications orchestration service.

Responsibilities:
- Accept NotificationRequest and publish canonical events
- Subscribe to NotificationSent events and maintain an inbox (in-memory for POC)
- Expose simple settings (in-memory; pluggable for Redis/Postgres later)
- Emit Prometheus metrics and audit events
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, List
from uuid import uuid4

from core.audit.service import AuditService, AuditLevel
from core.policy.engine import PolicyEngine
from core.messaging.service import MessagingService
from core.messaging.models import Event
from .models import NotificationRequest, NotificationSent, InboxItem, NotificationStatus
from core.monitoring.metrics import registry as prom_registry  # noqa: F401
from core.monitoring.metrics import (
    notifications_sends_total,
    notifications_sent_total,
    notifications_failed_total,
    notifications_send_latency,
)

logger = logging.getLogger(__name__)


class NotificationsService:
    def __init__(
        self,
        audit_service: AuditService,
        messaging_service: MessagingService,
        policy_engine: PolicyEngine,
    ) -> None:
        self.audit_service = audit_service
        self.messaging_service = messaging_service
        self.policy_engine = policy_engine
        self._inbox: List[InboxItem] = []
        self._running = False
        self._settings: Dict[str, Any] = {
            "enabled": True,
            "dry_run": True,
            "default_targets": [],
        }
        # In-memory rules for event-triggered notifications
        # Rule shape (wrapped for linting):
        # { id, name, enabled, event_type, channel, template: {title, body},
        #   audience: { mode: 'traits', traits: [..], scope?: 'tenant'|'org' } }
        self._rules: List[Dict[str, Any]] = []

    async def start(self) -> None:
        if self._running:
            return
        # Subscribe to NotificationSent events to build inbox
        await self.messaging_service.subscribe_to_events(
            "core-notifications",
            ["NotificationSent"],
            self._on_event,
        )
        # Broad subscription for application events to evaluate rules
        await self.messaging_service.subscribe_to_events(
            "core-notifications-rules",
            [
                "FaxReceived",
                "InboundReceived",
                "NotificationRequest",
                "UserEvent",
                "AppEvent",
            ],
            self._on_event,
        )
        self._running = True
        logger.info("Notifications service started")

    async def stop(self) -> None:
        self._running = False
        logger.info("Notifications service stopped")

    def get_settings(self) -> Dict[str, Any]:
        return dict(self._settings)

    def set_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        self._settings.update(settings or {})
        return self.get_settings()

    async def send(
        self, payload: Dict[str, Any], source: str = "system"
    ) -> Dict[str, Any]:
        start = datetime.utcnow()
        notifications_sends_total.labels(source=source).inc()
        # Authorization: notification_manager or admin should be implied by caller before invoking
        req = NotificationRequest(
            notification_id=payload.get("notification_id") or str(uuid4()),
            title=payload.get("title"),
            body=str(payload.get("body") or ""),
            priority=payload.get("priority") or "normal",
            channel=payload.get("channel"),
            targets=payload.get("targets") or self._settings.get("default_targets", []),
            metadata=payload.get("metadata") or {},
        )

        await self.audit_service.log_event(
            event_type="notification_requested",
            category="notifications",
            action="send",
            result="received",
            description="Notification requested",
            plugin_id=source,
            level=AuditLevel.STANDARD,
            details=req.model_dump(),
        )

        # Publish NotificationRequest event for plugins with handles_notifications
        await self.messaging_service.publish_event(
            event_type="NotificationRequest",
            payload=req.model_dump(),
            source_plugin=source,
            data_traits=["internal"],
        )

        # Dry-run completion for immediate inbox visibility
        status = NotificationStatus.queued
        details: Dict[str, Any] = {}
        if bool(self._settings.get("dry_run", True)):
            status = NotificationStatus.sent
            details = {"targets": req.targets, "dry_run": True}
            await self._ingest_sent(
                NotificationSent(
                    notification_id=req.notification_id,
                    plugin="core-notifications",
                    timestamp=datetime.utcnow().isoformat(),
                    status=status,
                    details=details,
                )
            )

        elapsed = (datetime.utcnow() - start).total_seconds()
        notifications_send_latency.observe(elapsed)
        if status == NotificationStatus.sent:
            notifications_sent_total.inc()
        elif status == NotificationStatus.failed:
            notifications_failed_total.inc()

        return {
            "status": status.value,
            "notification_id": req.notification_id,
            "queued": status == NotificationStatus.queued,
        }

    async def _on_event(self, event: Event, source_plugin: str) -> None:
        try:
            if event.event_type == "NotificationSent":
                sent = NotificationSent(**event.payload)
                await self._ingest_sent(sent)
            else:
                # Evaluate rules for other events
                for rule in list(self._rules):
                    if not rule.get("enabled", True):
                        continue
                    if str(rule.get("event_type") or "").strip() != event.event_type:
                        continue
                    # Build outbound notification payload
                    tpl = rule.get("template") or {}
                    title = str(tpl.get("title") or f"{event.event_type}")
                    body = str(tpl.get("body") or "")
                    channel = rule.get("channel") or None
                    audience = rule.get("audience") or {}
                    targets = None  # Let plugins fan-out based on audience
                    metadata: Dict[str, Any] = {
                        "source_event": event.event_type,
                        "audience": audience,
                        "source_plugin": source_plugin,
                    }
                    await self.send(
                        {
                            "title": title,
                            "body": body or f"Event {event.event_type}",
                            "channel": channel,
                            "targets": targets,
                            "metadata": metadata,
                        },
                        source="notifications-rule",
                    )
        except Exception as e:  # noqa: BLE001
            logger.error("notifications_event_error: %s", e)

    async def _ingest_sent(self, sent: NotificationSent) -> None:
        item = InboxItem(
            id=sent.notification_id,
            type="NotificationSent",
            ts=datetime.utcnow(),
            payload=sent.model_dump(),
        )
        self._inbox.insert(0, item)
        await self.audit_service.log_event(
            event_type="notification_ingested",
            category="notifications",
            action="ingest",
            result="success",
            description="Notification sent ingested",
            plugin_id=sent.plugin,
            level=AuditLevel.STANDARD,
            details={"notification_id": sent.notification_id, "status": sent.status},
        )

    def list_inbox(self, limit: int = 100, offset: int = 0) -> List[Dict[str, Any]]:
        items = self._inbox[offset : offset + limit]
        return [i.model_dump() for i in items]

    # Rules management (in-memory)
    def list_rules(self) -> List[Dict[str, Any]]:
        return list(self._rules)

    def upsert_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        rid = str(rule.get("id") or str(uuid4()))
        rule["id"] = rid
        # normalize booleans/fields
        rule["enabled"] = bool(rule.get("enabled", True))
        # replace by id
        self._rules = [r for r in self._rules if r.get("id") != rid] + [rule]
        return rule

    def delete_rule(self, rid: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.get("id") != rid]
        return len(self._rules) != before
