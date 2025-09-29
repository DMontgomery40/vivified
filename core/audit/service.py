"""
Minimal audit logging service for Phase 2.

Provides structured logging utilities and a simple decorator for
auditing sensitive operations. In later phases this should persist to
an append-only store with retention policies per HIPAA.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional, Callable
import functools
import json
import logging

from .models import AuditCategory


class AuditLevel(str, Enum):
    MINIMAL = "minimal"
    STANDARD = "standard"
    DETAILED = "detailed"
    COMPREHENSIVE = "comprehensive"


logger = logging.getLogger(__name__)


@dataclass
class AuditEvent:
    event_type: str
    category: AuditCategory
    action: str
    result: str
    description: str
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    plugin_id: Optional[str] = None
    user_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    timestamp: datetime = datetime.now(tz=timezone.utc)


_EVENT_BUFFER: list[dict] = []
_EVENT_BUFFER_LIMIT = 1000


class AuditService:
    SENSITIVE_KEYS = {
        "ssn",
        "social_security",
        "social_security_number",
        "dob",
        "date_of_birth",
        "phone",
        "phone_number",
        "email",
        "email_address",
        "address",
        "street",
        "city",
        "state",
        "zip",
        "mrn",
        "patient_id",
        "member_id",
        "subscriber_id",
        "diagnosis",
        "medical_record",
        "phi",
        "pii",
    }

    @staticmethod
    def _mask_value(value: Any) -> Any:
        try:
            if not isinstance(value, (str, bytes)):
                return "[REDACTED]"
            s = value.decode() if isinstance(value, bytes) else str(value)
            if len(s) > 64:
                s = s[:64] + "…"
            return "[REDACTED]"
        except Exception:  # noqa: BLE001
            return "[REDACTED]"

    @classmethod
    def _sanitize(cls, data: Any) -> Any:
        """Recursively sanitize potentially sensitive structures."""
        try:
            # Mask obvious string patterns
            if isinstance(data, str):
                return (
                    "[REDACTED]"
                    if any(c in data for c in ("@", "+", "(", ")", "-"))
                    else data
                )
            if isinstance(data, bytes):
                return "[REDACTED]"
            if isinstance(data, dict):
                out: Dict[str, Any] = {}
                for k, v in data.items():
                    key_l = str(k).lower()
                    if key_l in cls.SENSITIVE_KEYS or any(
                        t in key_l
                        for t in ("email", "ssn", "phone", "patient", "diagnosis")
                    ):
                        out[k] = cls._mask_value(v)
                    else:
                        out[k] = cls._sanitize(v)
                return out
            if isinstance(data, list):
                return [cls._sanitize(x) for x in data[:50]]  # cap length
            if isinstance(data, (int, float, bool)) or data is None:
                return data
            # Fallback to string repr redacted
            return "[REDACTED]"
        except Exception:  # noqa: BLE001
            return "[REDACTED]"

    async def log_event(
        self,
        event_type: str,
        category: Any,
        action: str,
        result: str,
        description: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        plugin_id: Optional[str] = None,
        user_id: Optional[str] = None,
        level: AuditLevel = AuditLevel.STANDARD,
        phi_involved: bool = False,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        # IMPORTANT: Do not log PHI/PII content; only meta-information
        # Normalize category to string without assuming Enum
        try:
            category_str = (
                category.value if isinstance(category, AuditCategory) else str(category)
            )
        except Exception:  # noqa: BLE001
            category_str = "unknown"

        safe_details = self._sanitize(details or {})

        payload = {
            "type": event_type,
            "category": category_str,
            "action": action,
            "result": result,
            "level": level.value,
            "phi_involved": bool(phi_involved),
            "resource_type": resource_type,
            "resource_id": resource_id,
            "plugin_id": plugin_id,
            "user_id": user_id,
            "description": description,
            "details": safe_details,
            "ts": datetime.now(tz=timezone.utc).isoformat(),
        }
        logger.info("audit_event=%s", json.dumps(payload, separators=(",", ":")))
        # In-memory buffer for admin/audit listing (Phase 2 only)
        try:
            _EVENT_BUFFER.append(payload)
            if len(_EVENT_BUFFER) > _EVENT_BUFFER_LIMIT:
                del _EVENT_BUFFER[: len(_EVENT_BUFFER) - _EVENT_BUFFER_LIMIT]
        except Exception:  # noqa: BLE001
            pass

    async def list_events(self, limit: int = 100, offset: int = 0) -> dict:
        items = list(_EVENT_BUFFER)
        items.reverse()
        slice_ = items[offset : offset + limit]
        return {
            "items": slice_,
            "total": len(_EVENT_BUFFER),
            "limit": limit,
            "offset": offset,
        }


def audit_log(event_type: str = "action") -> Callable:
    """Decorator that emits an audit event before/after a call.

    This is a minimal implementation and does not include correlation IDs.
    """

    def _decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def _wrapper(*args, **kwargs):
            svc = await get_audit_service()
            try:
                await svc.log_event(
                    event_type=event_type,
                    category=AuditCategory.USER_ACTION,
                    action=func.__name__,
                    result="started",
                    description=f"{func.__name__} started",
                )
                result = await func(*args, **kwargs)
                await svc.log_event(
                    event_type=event_type,
                    category=AuditCategory.USER_ACTION,
                    action=func.__name__,
                    result="success",
                    description=f"{func.__name__} success",
                )
                return result
            except Exception as e:  # noqa: BLE001
                await svc.log_event(
                    event_type=event_type,
                    category=AuditCategory.USER_ACTION,
                    action=func.__name__,
                    result="failure",
                    description=f"{func.__name__} failed",
                    details={"error": str(e)},
                )
                raise

        return _wrapper

    return _decorator


_AUDIT_SERVICE: Optional[AuditService] = None


async def get_audit_service() -> AuditService:
    global _AUDIT_SERVICE
    if _AUDIT_SERVICE is None:
        _AUDIT_SERVICE = AuditService()
    return _AUDIT_SERVICE
