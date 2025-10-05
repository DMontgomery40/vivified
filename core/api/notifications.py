from __future__ import annotations

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from .dependencies import require_auth
from ..notifications.service import NotificationsService


notifications_router = APIRouter(prefix="/admin/notifications", tags=["notifications"])

_svc: Optional[NotificationsService] = None


def configure_notifications_api(*, svc: NotificationsService) -> None:
    global _svc
    _svc = svc


def _resolve_svc() -> NotificationsService:
    global _svc
    if _svc is not None:
        return _svc
    # Lazy resolve to avoid race during startup in tests
    try:
        from core.main import notifications_service as _ns  # type: ignore

        if _ns is not None:
            _svc = _ns  # type: ignore[assignment]
    except Exception:
        pass
    if _svc is None:
        raise HTTPException(status_code=503, detail="Notifications service unavailable")
    return _svc


@notifications_router.get("")
async def list_inbox(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    _: Dict = Depends(require_auth(["admin", "notification_manager", "audit_viewer"])),
):
    svc = _resolve_svc()
    return {"items": svc.list_inbox(limit=limit, offset=offset)}


@notifications_router.post("/send")
async def send_notification(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "notification_manager"])),
):
    svc = _resolve_svc()
    res = await svc.send(payload, source="admin")
    return res


@notifications_router.get("/settings")
async def get_settings(
    _: Dict = Depends(require_auth(["admin", "notification_manager"]))
):
    svc = _resolve_svc()
    return svc.get_settings()


@notifications_router.put("/settings")
async def set_settings(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "notification_manager"])),
):
    svc = _resolve_svc()
    return svc.set_settings(payload)


@notifications_router.get("/help")
async def help_links(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    return {
        "links": {
            "apprise": "https://github.com/caronc/apprise",
            "pushover": "https://pushover.net/api",
            "docs": "/docs/notifications",
        }
    }


# Rules API (in-memory in service; pluggable in future)
@notifications_router.get("/rules")
async def list_rules(
    _: Dict = Depends(require_auth(["admin", "notification_manager"]))
):
    svc = _resolve_svc()
    return {"items": svc.list_rules()}


@notifications_router.put("/rules")
async def upsert_rule(
    rule: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "notification_manager"])),
):
    svc = _resolve_svc()
    return svc.upsert_rule(rule)


@notifications_router.delete("/rules/{rid}")
async def delete_rule(
    rid: str, _: Dict = Depends(require_auth(["admin", "notification_manager"]))
):
    svc = _resolve_svc()
    ok = svc.delete_rule(rid)
    if not ok:
        raise HTTPException(status_code=404, detail="rule_not_found")
    return {"ok": True}
