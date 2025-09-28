from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Header
from fastapi.responses import JSONResponse
import hashlib
import json
import os

from core.api.models import ConfigSetRequest, UserCreateRequest
import httpx
from core.api.dependencies import get_current_user, require_auth
from core.audit.service import audit_log
from core.database import get_session
from core.identity.service import IdentityService
from core.identity.auth import get_auth_manager
from core.audit.service import get_audit_service
from core.policy.traits import registry as trait_registry
from core.identity.models import User


admin_router = APIRouter(prefix="/admin", tags=["admin"])


# Service providers set by core.main
_CONFIG_SVC = None
_REGISTRY = None


def configure_admin_api(*, config_service, registry) -> None:
    global _CONFIG_SVC, _REGISTRY
    _CONFIG_SVC = config_service
    _REGISTRY = registry


@admin_router.get("/config")
async def get_effective_config(
    _: Dict = Depends(require_auth(["admin", "config_manager"]))
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    return await _CONFIG_SVC.get_all(reveal=True)


@admin_router.put("/config")
@audit_log("config_update")
async def set_config(
    payload: ConfigSetRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    await _CONFIG_SVC.set(
        payload.key,
        payload.value,
        is_sensitive=bool(payload.is_sensitive),
        updated_by=str(user.get("id")),
        reason=payload.reason,
    )
    return {"status": "ok", "key": payload.key}


@admin_router.get("/plugins")
async def list_plugins(_: Dict = Depends(require_auth(["admin", "plugin_manager"]))):
    if _REGISTRY is None:
        raise HTTPException(status_code=500, detail="Plugin registry not available")
    # Sanitize token visibility; admins can see token for now if needed
    result = []
    for pid, info in _REGISTRY.plugins.items():
        entry = {**info}
        entry.pop("token", None)
        result.append(entry)
    return {"plugins": result, "total": len(result)}


@admin_router.post("/plugins/{plugin_id}/enable")
@audit_log("plugin_enabled")
async def enable_plugin(
    plugin_id: str, _: Dict = Depends(require_auth(["admin", "plugin_manager"]))
):
    if _REGISTRY is None:
        raise HTTPException(status_code=500, detail="Plugin registry not available")
    plugin = _REGISTRY.plugins.get(plugin_id)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    plugin["status"] = "active"
    return {"status": "enabled", "plugin_id": plugin_id}


@admin_router.post("/plugins/{plugin_id}/disable")
@audit_log("plugin_disabled")
async def disable_plugin(
    plugin_id: str,
    reason: Optional[str] = None,
    _: Dict = Depends(require_auth(["admin", "plugin_manager"])),
):
    if _REGISTRY is None:
        raise HTTPException(status_code=500, detail="Plugin registry not available")
    plugin = _REGISTRY.plugins.get(plugin_id)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    plugin["status"] = "disabled"
    if reason:
        plugin["disabled_reason"] = reason
    return {"status": "disabled", "plugin_id": plugin_id}


@admin_router.get("/users")
async def list_users(
    _: Dict = Depends(require_auth(["admin"])), session=Depends(get_session)
):
    ids = IdentityService(session, get_auth_manager())
    return await ids.list_users(page=1, page_size=100)


@admin_router.post("/users")
@audit_log("user_created")
async def create_user(
    payload: UserCreateRequest,
    _: Dict = Depends(require_auth(["admin"])),
    session=Depends(get_session),
):
    # Basic role mapping: if admin trait present, assign admin; if config/plugin
    # manager present, assign operator; else viewer
    tset = set(payload.traits or [])
    roles: list[str] = []
    if "admin" in tset:
        roles.append("admin")
    elif "config_manager" in tset or "plugin_manager" in tset:
        roles.append("operator")
    else:
        roles.append("viewer")

    ids = IdentityService(session, get_auth_manager())
    ok, user_id = await ids.create_user(
        payload.username, payload.email, payload.password, roles
    )
    if not ok:
        raise HTTPException(status_code=400, detail=str(user_id))
    return {"id": user_id, "roles": roles}


@admin_router.get("/traits")
async def list_traits(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    # Allow viewer to see trait catalog; enforcement happens server-side elsewhere.
    items = []
    for name, t in trait_registry._traits.items():  # noqa: SLF001
        items.append({"name": name, "description": t.description})
    return {"traits": items}


@admin_router.get("/audit")
async def list_audit(
    _: Dict = Depends(require_auth(["admin", "audit_viewer"])),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
):
    svc = await get_audit_service()
    return await svc.list_events(limit=limit, offset=offset)


@admin_router.get("/user/traits")
async def get_user_traits(user: Dict = Depends(get_current_user)):
    """Get user traits with enhanced trait mapping."""
    from core.policy.engine_enhanced import enhanced_policy_engine

    user_traits = user.get("traits", [])

    # Use enhanced policy engine to get UI traits
    ui_traits = enhanced_policy_engine.get_user_ui_traits(user_traits)

    # DEV-only traits to enable broader UI exploration without hitting unimplemented endpoints
    DEV_MODE = os.getenv("DEV_MODE", "false").lower() in {"1", "true", "yes"}
    if DEV_MODE:
        # Add development-only traits (but not risky ones by default)
        dev_traits = [
            "ui.monitoring",
            "ui.plugins",
            "ui.config",
            "ui.audit",
            "ui.gateway",
            "ui.messaging",
            "ui.canonical",
            "ui.policy",
            "ui.register",
            "ui.users",
        ]
        ui_traits.extend(dev_traits)

    # De-duplicate and sort
    ui_traits = sorted(list(set(ui_traits)))

    return {
        "schema_version": 1,
        "user": {"id": user.get("id")},
        "traits": ui_traits,
        "backend_traits": user_traits,
    }


@admin_router.get("/ui-config")
async def get_ui_config(
    _: Dict = Depends(require_auth(["admin", "viewer"])),
    if_none_match: Optional[str] = Header(default=None, alias="If-None-Match"),
):
    enabled = True
    plugins_enabled = True
    v3_plugins_enabled = False
    plugin_install_enabled = False
    sessions_enabled = False
    csrf_enabled = False
    docs_base: Optional[str] = None
    try:
        if _CONFIG_SVC is not None:
            v = await _CONFIG_SVC.get("ui.admin_console.enabled")
            if isinstance(v, bool):
                enabled = v
            v2 = await _CONFIG_SVC.get("ui.plugins.enabled")
            if isinstance(v2, bool):
                plugins_enabled = v2
            v3 = await _CONFIG_SVC.get("ui.v3_plugins.enabled")
            if isinstance(v3, bool):
                v3_plugins_enabled = v3
            pin = await _CONFIG_SVC.get("ui.plugin_install.enabled")
            if isinstance(pin, bool):
                plugin_install_enabled = pin
            ses = await _CONFIG_SVC.get("ui.sessions.enabled")
            if isinstance(ses, bool):
                sessions_enabled = ses
            csrf = await _CONFIG_SVC.get("ui.csrf.enabled")
            if isinstance(csrf, bool):
                csrf_enabled = csrf
            db = await _CONFIG_SVC.get("branding.docs_base") or await _CONFIG_SVC.get(
                "ui.docs.base"
            )
            if isinstance(db, str) and db:
                docs_base = db
    except Exception:
        pass
    payload = {
        "schema_version": 1,
        "features": {
            "admin_console": {"enabled": enabled},
            "plugins": {"enabled": plugins_enabled},
            "v3_plugins": {"enabled": v3_plugins_enabled},
            "plugin_install": bool(plugin_install_enabled),
            "sessions_enabled": bool(sessions_enabled),
            "csrf_enabled": bool(csrf_enabled),
        },
        "endpoints": {},
    }
    if docs_base:
        payload["docs_base"] = docs_base
    # Compute a weak ETag for simple client caching
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    etag = f'W/"{hashlib.sha256(body).hexdigest()[:16]}"'
    if if_none_match and if_none_match.strip() == etag:
        return JSONResponse(status_code=304, content=None)
    return JSONResponse(content=payload, headers={"ETag": etag})


# Phase 1 stubs to avoid 404s in UI when traits/flags expose surfaces
@admin_router.get("/marketplace/plugins")
async def get_marketplace_plugins(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    return {"plugins": []}


@admin_router.get("/health-status")
async def get_health_status(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    # Minimal, non-PHI health summary compatible with UI expectations
    # Enriched for Phase 4 UI parity
    tls_enabled = os.getenv("USE_TLS", "false").lower() in {"1", "true", "yes"}
    db_url = os.getenv("DATABASE_URL", "")
    db_ssl_required = "sslmode=require" in (db_url or "")

    # Plugin counts
    total_plugins = len(_REGISTRY.plugins) if _REGISTRY else 0
    active_plugins = sum(
        1
        for p in (_REGISTRY.plugins.values() if _REGISTRY else [])
        if p.get("status") == "active"
    )

    # NATS varz reachability (best-effort, internal only)
    nats_ok = False
    try:
        async with httpx.AsyncClient(timeout=1.5) as client:
            r = await client.get("http://nats:8222/varz")
            nats_ok = r.status_code == 200
    except Exception:
        nats_ok = False

    return {
        "backend_healthy": True,
        "backend": "core",
        "tls_enabled": tls_enabled,
        "db_ssl_required": db_ssl_required,
        "nats_ok": nats_ok,
        "plugins": {"active": active_plugins, "total": total_plugins},
        "jobs": {"queued": 0, "in_progress": 0, "recent_failures": 0},
        "plugins_ok": active_plugins == total_plugins if total_plugins else True,
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }


@admin_router.post("/diagnostics/run")
@audit_log("diagnostics_run")
async def run_diagnostics(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    # Return a safe, empty diagnostics structure so the UI does not error
    return {"checks": {}, "summary": {"ok": True}}


@admin_router.patch("/users/{user_id}")
@audit_log("user_updated")
async def patch_user(
    user_id: str,
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin"])),
    session=Depends(get_session),
):
    user = await session.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if "is_active" in payload:
        user.is_active = bool(payload.get("is_active"))
    if "email" in payload:
        user.email = str(payload.get("email") or user.email)
    await session.commit()
    return {"ok": True}


@admin_router.get("/roles")
async def list_roles(
    _: Dict = Depends(require_auth(["admin"])), session=Depends(get_session)
):
    ids = IdentityService(session, get_auth_manager())
    return {"roles": await ids.list_roles()}


@admin_router.put("/users/{user_id}/roles")
@audit_log("user_roles_updated")
async def set_user_roles(
    user_id: str,
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin"])),
    session=Depends(get_session),
):
    roles = payload.get("roles")
    if not isinstance(roles, list):
        raise HTTPException(
            status_code=400, detail="roles must be a list of role names"
        )
    ids = IdentityService(session, get_auth_manager())
    ok = await ids.set_user_roles(user_id, [str(r) for r in roles])
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True, "user_id": user_id, "roles": roles}
