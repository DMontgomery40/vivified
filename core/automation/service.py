"""
Automation service for rules and flows (event-driven actions).

Supports simple rules:
- Trigger: event_type match
- Action: set_user_roles (replace roles for a user_id from event payload)
- Optional: emit_notification (delegates to NotificationsService)

Audience/conditions can be extended later; this provides GUI-friendly flows without CLI scripts.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from core.audit.service import AuditService, AuditLevel
from core.policy.engine import PolicyEngine
from core.messaging.service import MessagingService
from core.messaging.models import Event
from core.identity.service import IdentityService
from core.identity.auth import get_auth_manager
from core.database import async_session_factory


logger = logging.getLogger(__name__)


class AutomationService:
    def __init__(
        self,
        audit_service: AuditService,
        messaging_service: MessagingService,
        policy_engine: PolicyEngine,
    ) -> None:
        self.audit_service = audit_service
        self.messaging_service = messaging_service
        self.policy_engine = policy_engine
        self._running = False
        self._rules: List[Dict[str, Any]] = []

    async def start(self) -> None:
        if self._running:
            return
        await self.messaging_service.subscribe_to_events(
            "core-automations",
            ["UserEvent", "EmployeeTerminated", "CRMEvent", "AppEvent"],
            self._on_event,
        )
        self._running = True
        logger.info("Automation service started")

    async def stop(self) -> None:
        self._running = False
        logger.info("Automation service stopped")

    # Rules CRUD
    def list_rules(self) -> List[Dict[str, Any]]:
        return list(self._rules)

    def upsert_rule(self, rule: Dict[str, Any]) -> Dict[str, Any]:
        rid = str(rule.get("id") or __import__("uuid").uuid4())
        rule["id"] = rid
        rule["enabled"] = bool(rule.get("enabled", True))
        # Normalize action
        action = rule.get("action") or {}
        if not isinstance(action, dict):
            action = {}
        rule["action"] = action
        # Replace existing by id
        self._rules = [r for r in self._rules if r.get("id") != rid] + [rule]
        return rule

    def delete_rule(self, rid: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r.get("id") != rid]
        return len(self._rules) != before

    async def _on_event(self, event: Event, source_plugin: str) -> None:
        for rule in list(self._rules):
            try:
                if not rule.get("enabled", True):
                    continue
                if str(rule.get("event_type") or "").strip() != event.event_type:
                    continue
                action = rule.get("action") or {}
                atype = str(action.get("type") or "").strip()
                if atype == "set_user_roles":
                    await self._apply_set_user_roles(rule, action, event)
                elif atype == "emit_notification":
                    await self._apply_emit_notification(rule, action, event)
            except Exception as e:  # noqa: BLE001
                logger.exception("automation rule error: %s", e)

    async def _apply_set_user_roles(
        self, rule: Dict[str, Any], action: Dict[str, Any], event: Event
    ) -> None:
        # Extract user_id from event payload common shapes
        payload = event.payload or {}
        user_id = (
            payload.get("user_id")
            or (payload.get("user") or {}).get("id")
            or payload.get("id")
        )
        if not user_id:
            return
        roles = action.get("roles") or []
        if not isinstance(roles, list) or not roles:
            return
        async with async_session_factory() as session:
            ids = IdentityService(session, get_auth_manager())
            ok = await ids.set_user_roles(str(user_id), [str(r) for r in roles])
            await self.audit_service.log_event(
                event_type="automation_set_user_roles",
                category="automations",
                action="set_user_roles",
                result="success" if ok else "failed",
                description=f"Set roles for user {user_id}",
                user_id=str(user_id),
                level=AuditLevel.STANDARD,
                details={"roles": roles, "event": event.event_type},
            )

    async def _apply_emit_notification(
        self, rule: Dict[str, Any], action: Dict[str, Any], event: Event
    ) -> None:
        # Optional helper that delegates to NotificationsService via event
        try:
            from core.notifications.service import NotificationsService  # noqa: F401
        except Exception:
            return
        # Compose payload to notifications
        title = str(action.get("title") or f"{event.event_type}")
        body = str(action.get("body") or "")
        channel = action.get("channel") or None
        audience = action.get("audience") or {}
        metadata = {"source_event": event.event_type, "audience": audience}
        await self.messaging_service.publish_event(
            event_type="NotificationRequest",
            payload={
                "title": title,
                "body": body or f"Event {event.event_type}",
                "channel": channel,
                "targets": None,
                "metadata": metadata,
                "notification_id": str(__import__("uuid").uuid4()),
            },
            source_plugin="automations",
            data_traits=["internal"],
        )
