from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query

from core.api.models import ConfigSetRequest, UserCreateRequest
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
async def get_effective_config(_: Dict = Depends(require_auth(["admin", "config_manager"]))):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    return _CONFIG_SVC.get_all(reveal=True)


@admin_router.put("/config")
@audit_log("config_update")
async def set_config(
    payload: ConfigSetRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    _CONFIG_SVC.set(
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
async def enable_plugin(plugin_id: str, _: Dict = Depends(require_auth(["admin", "plugin_manager"]))):
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
    _: Dict = Depends(require_auth(["admin", "plugin_manager"]))
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
    _: Dict = Depends(require_auth(["admin"])),
    session=Depends(get_session)
):
    ids = IdentityService(session, get_auth_manager())
    return await ids.list_users(page=1, page_size=100)


@admin_router.post("/users")
@audit_log("user_created")
async def create_user(
    payload: UserCreateRequest,
    _: Dict = Depends(require_auth(["admin"])),
    session=Depends(get_session)
):
    # Basic role mapping: if admin trait present, assign admin; if config/plugin manager present, assign operator; else viewer
    tset = set(payload.traits or [])
    roles: list[str] = []
    if "admin" in tset:
        roles.append("admin")
    elif "config_manager" in tset or "plugin_manager" in tset:
        roles.append("operator")
    else:
        roles.append("viewer")

    ids = IdentityService(session, get_auth_manager())
    ok, user_id = await ids.create_user(payload.username, payload.email, payload.password, roles)
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
    # Map Vivified traits to Faxbot UI trait names for compatibility
    traits = set(user.get("traits", []))
    ui_traits: list[str] = []
    if "admin" in traits:
        ui_traits.append("role.admin")
    # Additional UI flags can be added later
    return {"schema_version": 1, "user": {"id": user.get("id")}, "traits": ui_traits}


@admin_router.get("/ui-config")
async def get_ui_config(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    enabled = True
    plugins_enabled = True
    try:
      if _CONFIG_SVC is not None:
          v = _CONFIG_SVC.get("ui.admin_console.enabled")
          if isinstance(v, bool):
              enabled = v
          v2 = _CONFIG_SVC.get("ui.plugins.enabled")
          if isinstance(v2, bool):
              plugins_enabled = v2
    except Exception:
      pass
    return {
        "schema_version": 1,
        "features": {
            "admin_console": {"enabled": enabled},
            "plugins": {"enabled": plugins_enabled},
        },
        "endpoints": {},
    }


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
async def list_roles(_: Dict = Depends(require_auth(["admin"])) , session=Depends(get_session)):
    ids = IdentityService(session, get_auth_manager())
    return {"roles": await ids.list_roles()}


@admin_router.put("/users/{user_id}/roles")
@audit_log("user_roles_updated")
async def set_user_roles(user_id: str, payload: Dict[str, Any], _: Dict = Depends(require_auth(["admin"])), session=Depends(get_session)):
    roles = payload.get("roles")
    if not isinstance(roles, list):
        raise HTTPException(status_code=400, detail="roles must be a list of role names")
    ids = IdentityService(session, get_auth_manager())
    ok = await ids.set_user_roles(user_id, [str(r) for r in roles])
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"ok": True, "user_id": user_id, "roles": roles}
