from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import os
import asyncio
import logging
import time
import secrets

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, Field
import httpx

from core.api.dependencies import require_auth
from core.audit.service import get_audit_service, AuditLevel
from core.audit.models import AuditCategory


logger = logging.getLogger(__name__)


# -----------------------------
# Public models (contracts.md)
# -----------------------------


class ErrorInfo(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorInfo


class IntegrationItem(BaseModel):
    provider: str
    name: str
    connected: bool
    details: Optional[Dict[str, Any]] = None


class IntegrationsList(BaseModel):
    items: List[IntegrationItem] = Field(default_factory=list)


class ConnectResponse(BaseModel):
    url: str


class StatusResponse(BaseModel):
    connected: bool
    details: Optional[Dict[str, Any]] = None


class RevokeResponse(BaseModel):
    ok: bool


# -----------------------------
# Config & constants
# -----------------------------


def _env_true(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).lower() in {"1", "true", "yes"}


INTEGRATIONS_BASE_URL = os.getenv("INTEGRATIONS_BASE_URL", "http://frigg:3001").rstrip(
    "/"
)
INTEGRATIONS_INTERNAL_TOKEN = os.getenv("INTEGRATIONS_INTERNAL_TOKEN", "")
INTEGRATIONS_HIPAA_MODE = _env_true("INTEGRATIONS_HIPAA_MODE", "false")
INTEGRATIONS_HIPAA_ALLOWED = {
    p.strip().lower()
    for p in os.getenv("INTEGRATIONS_HIPAA_ALLOWED", "").split(",")
    if p.strip()
}


# Initial provider catalog (white-labeled names kept in core)
# Note: provider IDs are stable; display names can be white-labeled.
PROVIDER_CATALOG: Dict[str, Dict[str, Any]] = {
    # contracts.md lists hubspot initial connector
    # name here is display-only and must not leak to errors/logs
    "hubspot": {"name": "HubSpot CRM", "hipaa_default_allowed": False},
}


# -----------------------------
# Helpers
# -----------------------------


def _hipaa_blocked(provider: str) -> bool:
    if not INTEGRATIONS_HIPAA_MODE:
        return False
    return provider.lower() not in INTEGRATIONS_HIPAA_ALLOWED


def _error_response(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": {"code": code, "message": message}}
    )


def _map_internal_error(code: str) -> Tuple[int, str]:
    """Map internal error codes to public taxonomy.

    Returns (status_code, public_code)
    """
    c = (code or "").lower()
    if any(
        k in c for k in ("service.unavailable", "mongo.unavailable", "health.unready")
    ):
        return 503, "integration.unavailable"
    if any(
        k in c
        for k in (
            "oauth.exchange_failed",
            "oauth.invalid_code",
            "oauth.state_mismatch",
            "oauth.url_generation_failed",
        )
    ):
        # Could be 400 or 502; default to 400 client error for exchange issues
        return 400, "integration.oauth_failed"
    if any(k in c for k in ("credential.delete_failed",)):
        return 502, "integration.revoke_failed"
    if any(k in c for k in ("entity.not_found", "credential.not_found")):
        return 400, "integration.bad_request"
    # Fallback
    return 400, "integration.bad_request"


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
        logger.debug("audit emit failed", exc_info=True)


def _client_headers() -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if INTEGRATIONS_INTERNAL_TOKEN:
        # Send both headers to remain compatible with older and newer sidecar checks
        headers["X-Internal-Token"] = INTEGRATIONS_INTERNAL_TOKEN
        headers["X-Internal-Auth"] = INTEGRATIONS_INTERNAL_TOKEN
    return headers


async def _integrator_health(timeout: float = 2.0) -> bool:
    url = f"{INTEGRATIONS_BASE_URL}/health"
    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            r = await client.get(url)
            if (
                r.status_code == 200
                and isinstance(r.json(), dict)
                and r.json().get("ok") is True
            ):
                return True
            return False
    except (httpx.TimeoutException, httpx.ConnectError):
        return False
    except Exception:
        return False


# -----------------------------
# OAuth State Store (short-lived)
# NOTE: In Step 1 this is in-memory and per-process.
# For multi-worker deployments, switch to a shared backend (e.g., Redis)
# to ensure consistent validation across instances.
# -----------------------------

_STATE_TTL_SECONDS = 10 * 60
_state_store: Dict[str, Tuple[str, float]] = {}
_STATE_LOCK: asyncio.Lock = asyncio.Lock()


def _state_key(user_id: str, provider: str) -> str:
    return f"{user_id}:{provider}"


def _state_generate(user_id: str) -> str:
    return f"{user_id}_{secrets.token_urlsafe(12)}"


async def _state_put(user_id: str, provider: str, state: str) -> None:
    async with _STATE_LOCK:
        _state_store[_state_key(user_id, provider)] = (
            state,
            time.time() + _STATE_TTL_SECONDS,
        )


async def _state_validate_and_clear(
    user_id: str, provider: str, state: Optional[str]
) -> bool:
    try:
        key = _state_key(user_id, provider)
        async with _STATE_LOCK:
            entry = _state_store.get(key)
            if not entry:
                return False
            expected, exp = entry
            # Clear once checked to prevent replay
            _state_store.pop(key, None)
        if time.time() > exp:
            return False
        return bool(state) and str(state) == expected
    except Exception:
        return False


router = APIRouter(prefix="/integrations", tags=["integrations"])


@router.get("", response_model=IntegrationsList)
async def list_integrations(
    user: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"]))
):
    # Optionally fast-fail if integrator not healthy
    if not await _integrator_health():
        return _error_response(
            503, "integration.unavailable", "Integration service unavailable"
        )

    items: List[IntegrationItem] = []
    user_id = str(user.get("id"))
    tasks = []

    async def fetch_status(provider: str, name: str) -> IntegrationItem:
        # HIPAA-disabled providers still appear but marked disabled via connected=False; actions will be blocked
        url = f"{INTEGRATIONS_BASE_URL}/status/{provider}"
        params = {"userId": user_id}
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                r = await client.get(url, params=params, headers=_client_headers())
                if r.status_code == 200:
                    data = r.json()
                    connected = bool(data.get("connected"))
                    details = data.get("details") if isinstance(data, dict) else None
                    return IntegrationItem(
                        provider=provider,
                        name=name,
                        connected=connected,
                        details=details,
                    )
                # Map errors from integrator to default false
                return IntegrationItem(provider=provider, name=name, connected=False)
        except Exception:
            return IntegrationItem(provider=provider, name=name, connected=False)

    for pid, meta in PROVIDER_CATALOG.items():
        tasks.append(fetch_status(pid, str(meta.get("name") or pid)))

    results = await asyncio.gather(*tasks)
    items.extend(results)
    return IntegrationsList(items=items)


@router.post("/{provider}/connect", response_model=ConnectResponse)
async def connect_integration(
    provider: str,
    user: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"])),
):
    provider = provider.lower()
    user_id = str(user.get("id"))

    if _hipaa_blocked(provider):
        await _audit("integration_blocked", "connect", "denied", user_id, provider)
        return _error_response(
            403,
            "integration.not_allowed",
            "This integration is disabled in compliance mode",
        )

    if provider not in PROVIDER_CATALOG:
        return _error_response(400, "integration.bad_request", "Unsupported provider")

    await _audit(
        "integration_connect_initiated", "connect", "started", user_id, provider
    )

    url = f"{INTEGRATIONS_BASE_URL}/oauth_url/{provider}"
    # Generate and store short-lived state; request pass-through by integrator
    state = _state_generate(user_id)
    await _state_put(user_id, provider, state)
    params = {"userId": user_id, "state": state}
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, params=params, headers=_client_headers())
            if r.status_code == 200:
                data = r.json()
                connect_url = str(data.get("url") or "")
                if not connect_url:
                    return _error_response(
                        502, "integration.unavailable", "Failed to generate connect URL"
                    )
                await _audit(
                    "integration_connect_initiated",
                    "connect",
                    "success",
                    user_id,
                    provider,
                )
                return ConnectResponse(url=connect_url)
            # Map error envelope
            try:
                err = r.json().get("error", {})
            except Exception:
                err = {}
            status, pcode = _map_internal_error(str(err.get("code") or ""))
            await _audit(
                "integration_connect_initiated",
                "connect",
                "failure",
                user_id,
                provider,
                details={"status": status, "code": pcode},
            )
            return _error_response(
                status, pcode, str(err.get("message") or "Unable to connect")
            )
    except (httpx.TimeoutException, httpx.ConnectError):
        return _error_response(
            503, "integration.unavailable", "Integration service unavailable"
        )


@router.get("/{provider}/callback")
async def oauth_callback(
    provider: str,
    code: Optional[str] = Query(default=None),
    state: Optional[str] = Query(default=None),
    user: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"])),
):
    provider = provider.lower()
    user_id = str(user.get("id"))

    if _hipaa_blocked(provider):
        await _audit("integration_blocked", "callback", "denied", user_id, provider)
        return _error_response(
            403,
            "integration.not_allowed",
            "This integration is disabled in compliance mode",
        )

    if provider not in PROVIDER_CATALOG:
        return _error_response(400, "integration.bad_request", "Unsupported provider")

    # Verify required params
    if not code:
        return _error_response(
            400, "integration.bad_request", "Missing authorization code"
        )
    if not state:
        return _error_response(400, "integration.oauth_failed", "Missing OAuth state")
    # Prefer validating against short-lived store; fall back to prefix check for transitional compatibility
    valid = await _state_validate_and_clear(user_id, provider, state)
    if not valid:
        return _error_response(400, "integration.oauth_failed", "Invalid OAuth state")

    payload = {"userId": user_id, "code": code, "state": state}
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(
                f"{INTEGRATIONS_BASE_URL}/oauth_cb/{provider}",
                json=payload,
                headers=_client_headers(),
            )
            if r.status_code == 200:
                try:
                    data = r.json()
                except Exception:
                    data = {}
                # Emit completed audit with safe details
                safe_details = {}
                ent = (data or {}).get("entity") or {}
                if isinstance(ent, dict) and ent.get("account_name"):
                    safe_details["account_name"] = ent.get("account_name")
                await _audit(
                    "integration_connect_completed",
                    "callback",
                    "success",
                    user_id,
                    provider,
                    details=safe_details,
                )
                # Redirect back to Admin UI Providers panel (hash-based SPA)
                return RedirectResponse(url="/admin/ui")
            try:
                err = r.json().get("error", {})
            except Exception:
                err = {}
            status, pcode = _map_internal_error(str(err.get("code") or ""))
            await _audit(
                "integration_connect_failed",
                "callback",
                "failure",
                user_id,
                provider,
                details={"status": status, "code": pcode},
            )
            return _error_response(
                status, pcode, str(err.get("message") or "OAuth failed")
            )
    except (httpx.TimeoutException, httpx.ConnectError):
        return _error_response(
            503, "integration.unavailable", "Integration service unavailable"
        )


@router.get("/{provider}/status", response_model=StatusResponse)
async def get_status(
    provider: str,
    user: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"])),
):
    provider = provider.lower()
    user_id = str(user.get("id"))

    if _hipaa_blocked(provider):
        await _audit("integration_blocked", "status", "denied", user_id, provider)
        return _error_response(
            403,
            "integration.not_allowed",
            "This integration is disabled in compliance mode",
        )

    if provider not in PROVIDER_CATALOG:
        return _error_response(400, "integration.bad_request", "Unsupported provider")

    await _audit("integration_status_checked", "status", "started", user_id, provider)
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(
                f"{INTEGRATIONS_BASE_URL}/status/{provider}",
                params={"userId": user_id},
                headers=_client_headers(),
            )
            if r.status_code == 200:
                data = r.json()
                await _audit(
                    "integration_status_checked", "status", "success", user_id, provider
                )
                return StatusResponse(
                    connected=bool(data.get("connected")), details=data.get("details")
                )
            try:
                err = r.json().get("error", {})
            except Exception:
                err = {}
            status, pcode = _map_internal_error(str(err.get("code") or ""))
            await _audit(
                "integration_status_checked",
                "status",
                "failure",
                user_id,
                provider,
                details={"status": status, "code": pcode},
            )
            return _error_response(
                status, pcode, str(err.get("message") or "Status check failed")
            )
    except (httpx.TimeoutException, httpx.ConnectError):
        return _error_response(
            503, "integration.unavailable", "Integration service unavailable"
        )


@router.post("/{provider}/revoke", response_model=RevokeResponse)
async def revoke_integration(
    provider: str,
    user: Dict[str, Any] = Depends(require_auth(["admin", "integration_manager"])),
):
    provider = provider.lower()
    user_id = str(user.get("id"))

    if _hipaa_blocked(provider):
        await _audit("integration_blocked", "revoke", "denied", user_id, provider)
        return _error_response(
            403,
            "integration.not_allowed",
            "This integration is disabled in compliance mode",
        )

    if provider not in PROVIDER_CATALOG:
        return _error_response(400, "integration.bad_request", "Unsupported provider")

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(
                f"{INTEGRATIONS_BASE_URL}/revoke/{provider}",
                json={"userId": user_id},
                headers=_client_headers(),
            )
            if r.status_code == 200:
                await _audit(
                    "integration_revoke", "revoke", "success", user_id, provider
                )
                return RevokeResponse(ok=True)
            try:
                err = r.json().get("error", {})
            except Exception:
                err = {}
            status, pcode = _map_internal_error(str(err.get("code") or ""))
            await _audit(
                "integration_revoke",
                "revoke",
                "failure",
                user_id,
                provider,
                details={"status": status, "code": pcode},
            )
            return _error_response(
                status, pcode, str(err.get("message") or "Revoke failed")
            )
    except (httpx.TimeoutException, httpx.ConnectError):
        return _error_response(
            503, "integration.unavailable", "Integration service unavailable"
        )
