from __future__ import annotations

import os
import time
import secrets
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from core.api.dependencies import require_auth
from core.audit.service import get_audit_service, AuditLevel
from core.audit.models import AuditCategory
from core.plugins.manager import IntegrationPluginRegistry


router = APIRouter(prefix="/plugins/integration", tags=["plugins", "integration"])

_REGISTRY = IntegrationPluginRegistry()


def _env_true(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in {"1", "true", "yes"}


INTEGRATIONS_HIPAA_MODE = _env_true("INTEGRATIONS_HIPAA_MODE", "false")
INTEGRATIONS_HIPAA_ALLOWED = {
    p.strip().lower()
    for p in os.getenv("INTEGRATIONS_HIPAA_ALLOWED", "").split(",")
    if p.strip()
}


class ProviderInfo(BaseModel):
    key: str
    name: str
    icon: str = "hub"
    category: str = "other"
    hipaa_eligible: bool = False
    allowed: bool = True


class ConnectResponse(BaseModel):
    url: str


class StatusResponse(BaseModel):
    connected: bool
    details: Optional[Dict[str, Any]] = None


class RevokeResponse(BaseModel):
    ok: bool


async def _audit(
    event_type: str,
    action: str,
    result: str,
    user_id: str,
    provider: str,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    try:
        svc = await get_audit_service()
        await svc.log_event(
            event_type=event_type,
            category=AuditCategory.USER_ACTION,
            action=action,
            result=result,
            description=f"{action} {result}",
            resource_type="integration",
            resource_id=provider,
            user_id=user_id,
            level=AuditLevel.STANDARD,
            phi_involved=False,
            details=details or {},
        )
    except Exception:
        # Best-effort audit
        pass


def _hipaa_blocked(key: str, eligible: bool) -> bool:
    if not INTEGRATIONS_HIPAA_MODE:
        return False
    if not eligible:
        return True
    return key.lower() not in INTEGRATIONS_HIPAA_ALLOWED


# State store (short-lived, in-memory); mirrors /integrations implementation
_STATE_TTL_SECONDS = 10 * 60
_state_store: Dict[str, Tuple[str, float]] = {}


def _state_key(user_id: str, provider: str) -> str:
    return f"{user_id}:{provider}"


def _new_state(user_id: str) -> str:
    return f"{user_id}_{secrets.token_urlsafe(12)}"


async def _state_put(user_id: str, provider: str, state: str) -> None:
    _state_store[_state_key(user_id, provider)] = (
        state,
        time.time() + _STATE_TTL_SECONDS,
    )


async def _verify_state(user_id: str, provider: str, state: Optional[str]) -> bool:
    try:
        key = _state_key(user_id, provider)
        entry = _state_store.get(key)
        if not entry:
            return False
        expected, exp = entry
        _state_store.pop(key, None)
        if time.time() > exp:
            return False
        return bool(state) and str(state) == expected
    except Exception:
        return False


@router.get("/providers")
async def list_providers(
    _: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"]))
):
    items: List[ProviderInfo] = []
    for entry in _REGISTRY.list():
        allowed = not _hipaa_blocked(entry.key, entry.manifest.hipaa_eligible)
        items.append(
            ProviderInfo(
                key=entry.key,
                name=entry.manifest.name,
                icon=entry.manifest.icon,
                category=entry.manifest.category,
                hipaa_eligible=entry.manifest.hipaa_eligible,
                allowed=allowed,
            )
        )
    return {"providers": [i.model_dump() for i in items]}


@router.post("/{provider}/connect", response_model=ConnectResponse)
async def connect_provider(
    provider: str,
    popup: bool = Query(False),
    user: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"])),
):
    provider = provider.lower()
    entry = _REGISTRY.get(provider)
    if not entry:
        raise HTTPException(status_code=400, detail="integration.bad_request")
    if _hipaa_blocked(entry.key, entry.manifest.hipaa_eligible):
        await _audit(
            "integration_blocked", "connect", "denied", str(user.get("id")), provider
        )
        raise HTTPException(status_code=403, detail="integration.not_allowed")

    user_id = str(user.get("id"))
    state = _new_state(user_id)
    await _state_put(user_id, provider, state)
    await _audit("integration_connect", "connect", "started", user_id, provider)
    url = (await entry.impl.connect(user_id=user_id, state=state)).url
    return ConnectResponse(url=url)


@router.post("/{provider}/callback")
async def callback_provider(
    provider: str,
    code: str,
    state: Optional[str] = None,
    user: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"])),
):
    provider = provider.lower()
    entry = _REGISTRY.get(provider)
    if not entry:
        raise HTTPException(status_code=400, detail="integration.bad_request")
    user_id = str(user.get("id"))
    if not await _verify_state(user_id, provider, state):
        await _audit(
            "integration_connect",
            "callback",
            "failure",
            user_id,
            provider,
            details={"code": "state_mismatch"},
        )
        raise HTTPException(status_code=400, detail="integration.oauth_failed")
    await entry.impl.callback(user_id=user_id, code=code, state=state or "")
    await _audit("integration_connect", "callback", "success", user_id, provider)
    return {"ok": True}


@router.get("/{provider}/status", response_model=StatusResponse)
async def status_provider(
    provider: str,
    user: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"])),
):
    provider = provider.lower()
    entry = _REGISTRY.get(provider)
    if not entry:
        raise HTTPException(status_code=400, detail="integration.bad_request")
    user_id = str(user.get("id"))
    if _hipaa_blocked(entry.key, entry.manifest.hipaa_eligible):
        await _audit(
            "integration_status_checked", "status", "denied", user_id, provider
        )
        raise HTTPException(status_code=403, detail="integration.not_allowed")
    st = await entry.impl.status(user_id=user_id)
    details = {"account_name": st.account} if st.account else None
    await _audit("integration_status_checked", "status", "success", user_id, provider)
    return StatusResponse(connected=st.connected, details=details)


@router.post("/{provider}/revoke", response_model=RevokeResponse)
async def revoke_provider(
    provider: str,
    user: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"])),
):
    provider = provider.lower()
    entry = _REGISTRY.get(provider)
    if not entry:
        raise HTTPException(status_code=400, detail="integration.bad_request")
    user_id = str(user.get("id"))
    if _hipaa_blocked(entry.key, entry.manifest.hipaa_eligible):
        await _audit("integration_revoke", "revoke", "denied", user_id, provider)
        raise HTTPException(status_code=403, detail="integration.not_allowed")
    await _audit("integration_revoke", "revoke", "requested", user_id, provider)
    await entry.impl.revoke(user_id=user_id)
    await _audit("integration_revoke", "revoke", "success", user_id, provider)
    return RevokeResponse(ok=True)
