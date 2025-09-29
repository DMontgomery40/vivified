from __future__ import annotations

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException

from .dependencies import require_auth
from ..automation.service import AutomationService


automation_router = APIRouter(prefix="/admin/automation", tags=["automation"])

_svc: Optional[AutomationService] = None


def configure_automation_api(*, svc: AutomationService) -> None:
    global _svc
    _svc = svc


def _resolve_svc() -> AutomationService:
    global _svc
    if _svc is not None:
        return _svc
    try:
        from core.main import automation_service as _as  # type: ignore

        if _as is not None:
            _svc = _as  # type: ignore[assignment]
    except Exception:
        pass
    if _svc is None:
        raise HTTPException(status_code=503, detail="Automation service unavailable")
    return _svc


@automation_router.get("/rules")
async def list_rules(_: Dict = Depends(require_auth(["admin", "user_manager"]))):
    return {"items": _resolve_svc().list_rules()}


@automation_router.put("/rules")
async def upsert_rule(
    rule: Dict[str, Any], _: Dict = Depends(require_auth(["admin", "user_manager"]))
):
    return _resolve_svc().upsert_rule(rule)


@automation_router.delete("/rules/{rid}")
async def delete_rule(
    rid: str, _: Dict = Depends(require_auth(["admin", "user_manager"]))
):
    ok = _resolve_svc().delete_rule(rid)
    if not ok:
        raise HTTPException(status_code=404, detail="rule_not_found")
    return {"ok": True}

