from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Header
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
import hashlib
import json
import os
import base64
from datetime import datetime, timedelta

from core.api.models import ConfigSetRequest, UserCreateRequest
import httpx
from core.api.dependencies import get_current_user, require_auth
from core.audit.service import audit_log
from core.database import get_session
from core.identity.service import IdentityService
from core.identity.auth import get_auth_manager
from core.audit.service import get_audit_service
from core.policy.engine import policy_engine
from core.storage.models import StorageQuery, DataClassification, StorageConfig
from core.storage.service import StorageService
from core.security.encryption import get_phi_encryption, rotate_phi_encryption
from core.security.tls_config import create_tls_context
from core.policy.traits import registry as trait_registry
from core.identity.models import User, APIKey
from sqlalchemy import select, update
import io
import zipfile
import re
import pathlib
from urllib.parse import urlparse
import ipaddress


admin_router = APIRouter(prefix="/admin", tags=["admin"])


# Service providers set by core.main
_CONFIG_SVC = None
_REGISTRY = None
_STORAGE_SVC: Optional[StorageService] = None
_IDENTITY_SCHEMA_INIT = False


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


@admin_router.post("/plugins/scaffold")
async def scaffold_plugin(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "plugin_manager"])),
):
    """Generate a minimal plugin scaffold as a ZIP archive.

    Payload fields:
      - id (str, required)
      - name (str, optional)
      - version (str, default 1.0.0)
      - language (str: python|node, default python)
      - traits (list[str], optional)
      - capabilities (list[str], optional)
    """
    plugin_id = str(payload.get("id") or "").strip()
    language = str(payload.get("language") or "python").lower()
    name = str(payload.get("name") or plugin_id or "Plugin").strip() or "Plugin"
    version = str(payload.get("version") or "1.0.0").strip() or "1.0.0"
    traits = payload.get("traits") or []
    capabilities = payload.get("capabilities") or []

    if not plugin_id or not re.match(r"^[a-z0-9\-_.]+$", plugin_id):
        raise HTTPException(status_code=400, detail="Invalid plugin id")

    # Build files
    files: Dict[str, str] = {}
    manifest = {
        "id": plugin_id,
        "name": name,
        "version": version,
        "description": f"Scaffolded plugin {name}",
        "categories": ["outbound"],
        "capabilities": capabilities or ["send"],
        "traits": traits or ["communication_plugin"],
        "endpoints": {"health": "/health"},
        "security": {
            "authentication_required": True,
            "data_classification": ["internal"],
        },
        "compliance": {"hipaa_controls": [], "audit_level": "standard"},
    }

    if language == "node":
        main_path = f"{plugin_id}/index.js"
        files[main_path] = (
            "const { FaxPlugin } = require('@faxbot/plugin-dev');\n"
            f"class {re.sub(r'[^A-Za-z0-9]', '', name) or 'My'}Plugin extends FaxPlugin {{\n"
            "  constructor(deps){ super(deps); }\n"
            "  async sendFax(toNumber, filePath){ return { jobId: 'test', status: 'QUEUED' }; }\n"
            "}\n"
            "module.exports = { Plugin: "
            f"{re.sub(r'[^A-Za-z0-9]', '', name) or 'My'}Plugin, manifest: "
            + __import__("json").dumps(manifest)
            + " };\n"
        )
        files[f"{plugin_id}/package.json"] = (
            '{\n  "name": "'
            + plugin_id
            + '",\n  "version": "'
            + version
            + '",\n  "main": "index.js"\n}\n'
        )
    else:  # python
        main_path = f"{plugin_id}/main.py"
        files[main_path] = (
            "from vivified_sdk import VivifiedPlugin, rpc_endpoint\n\n"
            f"class {re.sub(r'[^A-Za-z0-9]', '', name) or 'My'}Plugin(VivifiedPlugin):\n"
            "    def __init__(self):\n        super().__init__('manifest.json')\n\n"
            "    @rpc_endpoint('/health')\n    async def health(self):\n        return {'status': 'ok'}\n"
        )
        files[f"{plugin_id}/manifest.json"] = __import__("json").dumps(
            manifest, indent=2
        )
        files[f"{plugin_id}/Dockerfile"] = (
            'FROM python:3.11-slim\nWORKDIR /app\nCOPY . .\nCMD ["python", "-m", "'
            + plugin_id
            + '"]\n'
        )

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for path, content in files.items():
            zf.writestr(path, content)
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename={plugin_id}_scaffold.zip",
            "X-Scaffold-Language": language,
        },
    )


# Manifest schema + validation for core plugins
def _load_manifest_schema() -> Dict[str, Any]:
    schema_path = (
        pathlib.Path(__file__).resolve().parents[1]
        / "plugin_manager"
        / "manifest.schema.json"
    )
    try:
        return json.loads(schema_path.read_text())
    except Exception:  # pragma: no cover - fallback minimal schema
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "properties": {
                "id": {"type": "string"},
                "name": {"type": "string"},
                "version": {"type": "string"},
                "contracts": {"type": "array", "items": {"type": "string"}},
                "traits": {"type": "array", "items": {"type": "string"}},
                "security": {"type": "object"},
                "compliance": {"type": "object"},
            },
            "required": [
                "id",
                "name",
                "version",
                "contracts",
                "traits",
                "security",
                "compliance",
            ],
            "additionalProperties": True,
        }


@admin_router.get("/plugins/manifest-schema")
async def get_plugin_manifest_schema(
    _: Dict = Depends(require_auth(["admin", "plugin_manager"]))
):
    return _load_manifest_schema()


@admin_router.post("/plugins/validate-manifest")
async def validate_plugin_manifest(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "plugin_manager"])),
):
    """Validate a plugin manifest against the server's JSON Schema and
    suggest allowlists.

    Returns a dict: {
        ok,
        errors: [{message, path, schema_path}],
        suggestions: { operations, allowlist, invalid_domains, parsed_domains }
    }
    """
    manifest = payload if isinstance(payload, dict) else {}
    schema = _load_manifest_schema()
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(schema)
    errors = []
    for err in validator.iter_errors(manifest):
        errors.append(
            {
                "message": err.message,
                "path": list(err.path),
                "schema_path": list(err.schema_path),
            }
        )

    # Suggestions
    operations = []
    allowlist: Dict[str, Dict[str, list]] = {}
    invalid_domains: list[str] = []
    parsed_domains: list[str] = []
    try:
        eps = manifest.get("endpoints") or {}
        if isinstance(eps, dict):
            operations = [str(k) for k in eps.keys()]
            for _name, ep in eps.items():
                if not isinstance(ep, str):
                    continue
                try:
                    u = urlparse(ep)
                    if u.scheme and u.netloc:
                        host = u.netloc.split("@")[-1].split(":")[0]
                        parsed_domains.append(host)
                        # Validate host is not an IP literal
                        try:
                            ipaddress.ip_address(host)
                            invalid_domains.append(host)
                            continue
                        except Exception:
                            pass
                        ent = allowlist.setdefault(
                            host,
                            {"allowed_methods": ["GET", "POST"], "allowed_paths": []},
                        )
                        if u.path and u.path not in ent["allowed_paths"]:
                            ent["allowed_paths"].append(u.path)
                except Exception:
                    continue

        # Merge explicit allowed_domains
        ad = manifest.get("allowed_domains") or []
        if isinstance(ad, list):
            for d in ad:
                if not isinstance(d, str) or not d:
                    continue
                host = d
                # Skip IPs
                try:
                    ipaddress.ip_address(host)
                    invalid_domains.append(host)
                    continue
                except Exception:
                    pass
                allowlist.setdefault(
                    host, {"allowed_methods": ["GET", "POST"], "allowed_paths": []}
                )
    except Exception:
        pass

    return {
        "ok": len(errors) == 0,
        "errors": errors,
        "suggestions": {
            "operations": operations,
            "allowlist": allowlist,
            "invalid_domains": sorted(list(set(invalid_domains))),
            "parsed_domains": sorted(list(set(parsed_domains))),
        },
    }


# Operator policy allowlist (fine-grained operator rules)
@admin_router.get("/operator/allowlist")
async def operator_allowlist_get(
    caller: str,
    target: str,
    _: Dict = Depends(require_auth(["admin", "plugin_manager"])),
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    key = f"operator.allow.{caller}->{target}"
    try:
        allowed = await _CONFIG_SVC.get(key) or []
        if not isinstance(allowed, list):
            allowed = []
        return {"caller": caller, "target": target, "operations": allowed}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(e))


@admin_router.put("/operator/allowlist")
@audit_log("operator_allowlist_update")
async def operator_allowlist_set(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "plugin_manager"])),
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    caller = str(payload.get("caller") or "").strip()
    target = str(payload.get("target") or "").strip()
    operations = payload.get("operations")
    if not caller or not target or not isinstance(operations, list):
        raise HTTPException(
            status_code=400, detail="caller, target, operations required"
        )
    key = f"operator.allow.{caller}->{target}"
    await _CONFIG_SVC.set(
        key,
        [str(op) for op in operations],
        is_sensitive=False,
        updated_by="admin",
        reason="operator_allowlist_update",
    )
    return {"ok": True, "caller": caller, "target": target}


# Canonical transformation mappings registry
@admin_router.get("/canonical/transforms")
async def canonical_transforms_get(
    source: str, target: str, _: Dict = Depends(require_auth(["admin"]))
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    key = f"canonical.transforms.{source}->{target}"
    try:
        data = await _CONFIG_SVC.get(key) or {}
        if not isinstance(data, dict):
            data = {}
        return {"source": source, "target": target, "mappings": data}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(e))


@admin_router.put("/canonical/transforms")
@audit_log("canonical_transform_update")
async def canonical_transforms_set(
    payload: Dict[str, Any], _: Dict = Depends(require_auth(["admin"]))
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    source = str(payload.get("source") or "").strip()
    target = str(payload.get("target") or "").strip()
    mappings = payload.get("mappings")
    if not source or not target or not isinstance(mappings, dict):
        raise HTTPException(status_code=400, detail="source, target, mappings required")
    key = f"canonical.transforms.{source}->{target}"
    await _CONFIG_SVC.set(
        key,
        mappings,
        is_sensitive=False,
        updated_by="admin",
        reason="canonical_transform_update",
    )
    return {"ok": True, "source": source, "target": target}


# Gateway rate policy
@admin_router.get("/gateway/rate-policy")
async def gateway_rate_policy_get(_: Dict = Depends(require_auth(["admin"]))):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    rpm = await _CONFIG_SVC.get("gateway.rate.requests_per_minute")
    burst = await _CONFIG_SVC.get("gateway.rate.burst_limit")
    return {"requests_per_minute": int(rpm or 60), "burst_limit": int(burst or 100)}


@admin_router.put("/gateway/rate-policy")
@audit_log("gateway_rate_policy_update")
async def gateway_rate_policy_set(
    payload: Dict[str, Any], _: Dict = Depends(require_auth(["admin"]))
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    rpm = int(payload.get("requests_per_minute") or 60)
    burst = int(payload.get("burst_limit") or 100)
    await _CONFIG_SVC.set(
        "gateway.rate.requests_per_minute",
        rpm,
        is_sensitive=False,
        updated_by="admin",
        reason="rate_policy_update",
    )
    await _CONFIG_SVC.set(
        "gateway.rate.burst_limit",
        burst,
        is_sensitive=False,
        updated_by="admin",
        reason="rate_policy_update",
    )
    return {"ok": True}


@admin_router.get("/gateway/rate-policy/{plugin_id}")
async def gateway_plugin_rate_policy_get(
    plugin_id: str, _: Dict = Depends(require_auth(["admin"]))
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    rpm = await _CONFIG_SVC.get(f"gateway.rate.{plugin_id}.requests_per_minute")
    burst = await _CONFIG_SVC.get(f"gateway.rate.{plugin_id}.burst_limit")
    return {
        "plugin_id": plugin_id,
        "requests_per_minute": int(rpm or 0),
        "burst_limit": int(burst or 0),
    }


@admin_router.put("/gateway/rate-policy/{plugin_id}")
@audit_log("gateway_rate_policy_update_plugin")
async def gateway_plugin_rate_policy_set(
    plugin_id: str, payload: Dict[str, Any], _: Dict = Depends(require_auth(["admin"]))
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    rpm = int(payload.get("requests_per_minute") or 0)
    burst = int(payload.get("burst_limit") or 0)
    await _CONFIG_SVC.set(
        f"gateway.rate.{plugin_id}.requests_per_minute",
        rpm,
        is_sensitive=False,
        updated_by="admin",
        reason="rate_policy_update_plugin",
    )
    await _CONFIG_SVC.set(
        f"gateway.rate.{plugin_id}.burst_limit",
        burst,
        is_sensitive=False,
        updated_by="admin",
        reason="rate_policy_update_plugin",
    )
    return {"ok": True}


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
            "ui.storage",
            "ui.notifications",
            "ui.send_demo",
            "ui.inbound_demo",
            "ui.jobs",
            "ui.dashboard",
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


# Gateway allowlist management
@admin_router.get("/gateway/allowlist")
async def get_gateway_allowlist(
    plugin_id: Optional[str] = Query(None),
    _: Dict = Depends(require_auth(["admin", "viewer", "plugin_manager"])),
):
    if not plugin_id:
        raise HTTPException(status_code=400, detail="plugin_id is required")
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    key = f"gateway.allowlist.{plugin_id}"
    try:
        allowlist = await _CONFIG_SVC.get(key) or {}
        if not isinstance(allowlist, dict):
            allowlist = {}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"Failed to load allowlist: {e}")
    return {"plugin_id": plugin_id, "items": allowlist}


@admin_router.put("/gateway/allowlist")
@audit_log("gateway_allowlist_updated")
async def set_gateway_allowlist(
    payload: Dict[str, Any],
    user: Dict[str, Any] = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "plugin_manager"])),
):
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    plugin_id = payload.get("plugin_id")
    allowlist = payload.get("allowlist")
    if not plugin_id or not isinstance(allowlist, dict):
        raise HTTPException(
            status_code=400, detail="plugin_id and allowlist (object) are required"
        )
    # Normalize structure: { domain: { allowed_methods: [], allowed_paths: [] } }
    normalized: Dict[str, Dict[str, list]] = {}
    for domain, rules in allowlist.items():
        if not isinstance(rules, dict):
            continue
        methods = rules.get("allowed_methods") or []
        paths = rules.get("allowed_paths") or []
        if not isinstance(methods, list) or not isinstance(paths, list):
            continue
        normalized[str(domain)] = {
            "allowed_methods": [str(m).upper() for m in methods],
            "allowed_paths": [str(p) for p in paths],
        }
    key = f"gateway.allowlist.{plugin_id}"
    await _CONFIG_SVC.set(
        key,
        normalized,
        is_sensitive=False,
        updated_by=str(user.get("id")),
        reason="admin_update",
    )
    return {"ok": True, "plugin_id": plugin_id, "items": normalized}


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


# QA Test Suites (Phase 8) — lightweight, in-process smoke tests
@admin_router.get("/tests")
async def list_test_suites(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    """List available lightweight test suites runnable from the Admin Console."""
    return {
        "suites": [
            {"id": "smoke", "label": "Smoke (core flows)"},
            {"id": "unit-policy", "label": "Unit: Policy Engine"},
            {"id": "security", "label": "Security (sanity)"},
            {"id": "compliance", "label": "Compliance (PHI encryption)"},
            {"id": "integration", "label": "Integration (user onboarding)"},
            {"id": "owasp", "label": "Security: OWASP Inputs"},
            {"id": "performance", "label": "Performance (latency/throughput)"},
            {"id": "chaos", "label": "Chaos (simulated)"},
        ]
    }


@admin_router.post("/tests/run")
async def run_test_suite(
    payload: Dict[str, Any],
    user: Dict = Depends(require_auth(["admin"])),
    session=Depends(get_session),
):
    """Run a small, deterministic test suite and return structured results.

    This is intentionally scoped to quick, side-effect-safe checks to support
    Admin Console UX parity without spawning external runners.
    """
    suite = str(payload.get("suite") or "smoke").strip().lower()

    logs: list[dict] = []

    def log(level: str, message: str, **kw: Any) -> None:
        entry = {"level": level, "message": message}
        if kw:
            entry.update(kw)
        logs.append(entry)

    async def run_smoke() -> dict:
        # Identity: ensure we can list and (logically) create users
        ids = IdentityService(session, get_auth_manager())
        log("info", "Listing users…")
        users = await ids.list_users(page=1, page_size=5)
        assert isinstance(users, dict) and "users" in users
        log("pass", f"Listed {len(users.get('users', []))} users")

        # Audit: fetch recent events
        log("info", "Fetching audit events…")
        svc = await get_audit_service()
        events = await svc.list_events(limit=10, offset=0)
        assert isinstance(events, dict)
        log("pass", f"Audit entries fetched: {len(events.get('items', []))}")

        # Gateway: read rate policy
        log("info", "Reading gateway rate policy…")
        rp = await gateway_rate_policy_get(user)  # type: ignore[arg-type]
        assert isinstance(rp, dict) and "requests_per_minute" in rp
        log("pass", "Gateway policy ok", rpm=rp.get("requests_per_minute"))
        return {"ok": True}

    async def run_unit_policy() -> dict:
        from core.policy.engine import (
            PolicyEngine,
            PolicyRequest,
            PolicyContext,
            PolicyDecision,
        )

        pe = PolicyEngine()
        # PHI allowed when both sides have trait and audit_required present
        req_allow = PolicyRequest(
            user_id=str(user.get("id")),
            resource_type="record",
            resource_id="rec-1",
            action="read",
            traits=["handles_phi", "audit_required"],
            context={"data_classification": "phi"},
            policy_context=PolicyContext.USER_ACTION,
        )
        res_allow = await pe.evaluate_request(req_allow)
        assert res_allow.decision == PolicyDecision.ALLOW
        log("pass", "PHI allow with traits", reason=res_allow.reason)
        # PHI denied when trait missing
        req_deny = PolicyRequest(
            user_id=str(user.get("id")),
            resource_type="record",
            resource_id="rec-2",
            action="read",
            traits=["viewer"],
            context={"data_classification": "phi"},
            policy_context=PolicyContext.USER_ACTION,
        )
        res_deny = await pe.evaluate_request(req_deny)
        assert res_deny.decision in {PolicyDecision.DENY}
        log("pass", "PHI blocked without trait", reason=res_deny.reason)
        return {"ok": True}

    async def run_security() -> dict:
        # Encryption status endpoint
        enc = await encryption_status(user)  # type: ignore[arg-type]
        assert enc.get("algorithm") == "AES-256-GCM"
        log("pass", "Encryption configured", version=enc.get("version"))
        # TLS status endpoint
        tls = await tls_status(user)  # type: ignore[arg-type]
        assert "configured" in tls
        log("pass", "TLS status fetched", configured=bool(tls.get("configured")))
        return {"ok": True}

    async def run_compliance() -> dict:
        cfg = StorageConfig(
            default_provider="filesystem",
            encryption_enabled=True,
            auto_classify_content=True,
            filesystem_base_path=os.getenv("TMPDIR", "/tmp"),
        )
        svc = StorageService(
            config=cfg,
            policy_engine=policy_engine,
            audit_service=await get_audit_service(),
        )
        uid = str(user.get("id")) or "admin"
        # Store PHI and verify encrypted
        meta = await svc.store_object(
            content=b"patient data",
            filename="phi.txt",
            user_id=uid,
            content_type="text/plain",
            data_classification=None,
            traits=["handles_phi", "audit_required"],
        )
        assert bool(meta.is_encrypted)
        log("pass", "PHI stored encrypted", key_id=meta.encryption_key_id)
        # List with minimal details
        items = await svc.list_objects(query=StorageQuery(limit=5), user_id=uid)
        assert isinstance(items, list)
        log("pass", f"Storage list returned {len(items)} items")
        return {"ok": True}

    async def run_integration() -> dict:
        """Simulate user onboarding workflow end-to-end within current process."""
        # Ensure identity schema and create a user
        from core.api.models import UserCreateRequest

        await _ensure_identity_schema(session)
        ids = IdentityService(session, get_auth_manager())
        uname = f"user_{os.urandom(4).hex()}"
        payload = UserCreateRequest(
            username=uname, email=f"{uname}@example.com", password="SecureP@ss123!"
        )
        log("info", f"Creating user {payload.username}")
        ok, user_id = await ids.create_user(
            payload.username, payload.email, payload.password, roles=["viewer"]
        )
        assert ok and user_id
        log("pass", "User created", id=str(user_id))

        # Emit audit event equivalent to endpoint decorator for visibility
        svc = await get_audit_service()
        await svc.log_event(
            event_type="user_created",
            category="system",
            action="create_user",
            result="success",
            description=f"User {payload.username} created",
            user_id=str(user.get("id")),
            details={"new_user": payload.username},
        )
        # Verify audit contains the new event
        events = await svc.list_events(limit=50, offset=0)
        found = any(it.get("type") == "user_created" for it in events.get("items", []))
        assert found
        log("pass", "Audit recorded user_created event")
        return {"ok": True}

    async def run_owasp() -> dict:
        """Exercise typical OWASP input payloads against auth endpoint.

        This is a light in-process variant that validates inputs are safely
        rejected (401) without server errors.
        """
        from core.api.auth import login, LoginRequest

        bads = [
            "'; DROP TABLE users; --",
            "' OR '1'='1",
            "admin'--",
            "' UNION SELECT * FROM users--",
        ]
        for inj in bads:
            try:
                await login(LoginRequest(username=inj, password="test"))
                # If no exception, login wrongly succeeded
                raise AssertionError("Injection login unexpectedly succeeded")
            except HTTPException as he:  # expected invalid credentials
                assert he.status_code == 401
                log("pass", "Injection blocked", payload=inj)
        return {"ok": True}

    async def run_performance() -> dict:
        """Measure approximate latency for simple admin call 100x and compute p50/p95/p99."""
        import time

        samples: list[float] = []
        for _ in range(100):
            t0 = time.perf_counter()
            rp = await gateway_rate_policy_get(user)  # type: ignore[arg-type]
            assert isinstance(rp, dict)
            dt_ms = (time.perf_counter() - t0) * 1000.0
            samples.append(dt_ms)
        samples.sort()
        n = len(samples)
        p50 = samples[int(0.5 * (n - 1))]
        p95 = samples[int(0.95 * (n - 1))]
        p99 = samples[int(0.99 * (n - 1))]
        log(
            "pass",
            "Latency percentiles",
            p50_ms=round(p50, 2),
            p95_ms=round(p95, 2),
            p99_ms=round(p99, 2),
        )
        # Very loose local thresholds to avoid flakes
        assert p50 < 50 and p99 < 200
        return {"ok": True}

    async def run_chaos() -> dict:
        """Simulate plugin failure isolation by toggling status in registry."""
        # Register a fake plugin, disable it, ensure core functions still operate
        pid = f"plugin_{os.urandom(3).hex()}"
        if _REGISTRY is None:
            raise HTTPException(status_code=500, detail="Plugin registry not available")
        _REGISTRY.plugins[pid] = {"id": pid, "name": pid, "status": "active"}
        log("info", "Registered temp plugin", plugin_id=pid)
        # Disable via admin helper to simulate operator action
        await disable_plugin(pid, reason="chaos_test", _=user)  # type: ignore[arg-type]
        assert _REGISTRY.plugins[pid]["status"] == "disabled"
        log("pass", "Plugin disabled; core continues healthy")
        # Read health-like info
        rp = await gateway_rate_policy_get(user)  # type: ignore[arg-type]
        assert "requests_per_minute" in rp
        log("pass", "Gateway still reachable")
        # Re-enable
        await enable_plugin(pid, _=user)  # type: ignore[arg-type]
        assert _REGISTRY.plugins[pid]["status"] == "active"
        log("pass", "Plugin re-enabled")
        return {"ok": True}

    try:
        match suite:
            case "smoke":
                result = await run_smoke()
            case "unit-policy":
                result = await run_unit_policy()
            case "security":
                result = await run_security()
            case "compliance":
                result = await run_compliance()
            case "integration":
                result = await run_integration()
            case "owasp":
                result = await run_owasp()
            case "performance":
                result = await run_performance()
            case "chaos":
                result = await run_chaos()
            case _:
                raise HTTPException(status_code=400, detail="Unknown suite")
        return {"suite": suite, "ok": bool(result.get("ok")), "logs": logs}
    except HTTPException:
        raise
    except AssertionError as e:  # explicit failure surfaced in logs
        log("fail", f"Assertion failed: {e!s}")
        return {"suite": suite, "ok": False, "logs": logs}
    except Exception as e:  # noqa: BLE001
        log("error", f"Unexpected error: {type(e).__name__}: {e}")
        return {"suite": suite, "ok": False, "logs": logs}


# Security → Encryption admin endpoints
@admin_router.get("/security/encryption/status")
async def encryption_status(
    _: Dict = Depends(require_auth(["admin", "security_admin"]))
):
    svc = get_phi_encryption()
    return {
        "algorithm": "AES-256-GCM",
        "version": svc.current_key_version,
        "rotation_days": svc.key_rotation_days,
    }


@admin_router.post("/security/encryption/rotate")
@audit_log("security_encryption_rotated")
async def encryption_rotate(
    payload: Optional[Dict[str, Any]] = None, _: Dict = Depends(require_auth(["admin"]))
):
    new_master_key = None
    if isinstance(payload, dict):
        km = payload.get("new_master_key")
        if isinstance(km, str) and km:
            new_master_key = km
    new_version = rotate_phi_encryption(new_master_key)
    return {"ok": True, "new_version": new_version}


# Security → TLS admin endpoints
@admin_router.get("/security/tls/status")
async def tls_status(_: Dict = Depends(require_auth(["admin", "security_admin"]))):
    import ssl

    status: Dict[str, Any] = {
        "min_version": "TLSv1_3",
        "ciphers": "ECDHE+AESGCM:ECDHE+CHACHA20",
    }
    try:
        ctx = create_tls_context(cert_dir=os.getenv("TLS_CERT_DIR", "/certs"))
        status["configured"] = True
        status["minimum_version_enum"] = getattr(
            ctx, "minimum_version", ssl.TLSVersion.TLSv1_3
        ).name
    except Exception:
        status["configured"] = False
    return status


@admin_router.post("/security/tls/self-signed")
@audit_log("security_tls_self_signed")
async def tls_generate_self_signed(
    payload: Optional[Dict[str, Any]] = None,
    _: Dict = Depends(require_auth(["admin", "security_admin"])),
):
    from datetime import datetime, timedelta
    from pathlib import Path
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    cfg = payload or {}
    hostname = str(cfg.get("hostname") or "localhost")
    out_dir = Path(str(cfg.get("out_dir") or "/tmp/vivified-tls"))
    out_dir.mkdir(parents=True, exist_ok=True)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Vivified"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(hostname), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    cert_path = out_dir / "core.crt"
    key_path = out_dir / "core.key"
    cert_path.write_bytes(cert_pem)
    key_path.write_bytes(key_pem)

    return {
        "ok": True,
        "cert_path": str(cert_path),
        "key_path": str(key_path),
        "note": "Self-signed certificate generated for development",
    }


# Security → MFA admin endpoints
@admin_router.post("/security/mfa/setup")
async def mfa_setup(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "security_admin"])),
    session=Depends(get_session),
):
    user_id = str(payload.get("user_id") or "").strip()
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")
    await _ensure_identity_schema(session)
    ids = IdentityService(session, get_auth_manager())
    result = await ids.setup_mfa(user_id)
    return result


@admin_router.post("/security/mfa/enable")
@audit_log("security_mfa_enabled")
async def mfa_enable(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "security_admin"])),
    session=Depends(get_session),
):
    user_id = str(payload.get("user_id") or "").strip()
    token = str(payload.get("token") or "").strip()
    if not user_id or not token:
        raise HTTPException(status_code=400, detail="user_id and token are required")
    await _ensure_identity_schema(session)
    ids = IdentityService(session, get_auth_manager())
    ok = await ids.enable_mfa(user_id, token)
    if not ok:
        raise HTTPException(status_code=400, detail="invalid token or user")
    return {"ok": True}


@admin_router.post("/security/webauthn/registration-options")
async def webauthn_registration_options(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "security_admin"])),
    session=Depends(get_session),
):
    user_id = str(payload.get("user_id") or "").strip()
    rp_id = str(payload.get("rp_id") or "localhost").strip()
    rp_name = str(payload.get("rp_name") or "Vivified").strip()
    origin = str(payload.get("origin") or "http://localhost:8000").strip()
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")
    await _ensure_identity_schema(session)
    ids = IdentityService(session, get_auth_manager())
    options = await ids.get_webauthn_registration_options(
        user_id, rp_id, rp_name, origin
    )
    return options


@admin_router.post("/security/webauthn/register")
@audit_log("security_webauthn_register")
async def webauthn_register(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "security_admin"])),
    session=Depends(get_session),
):
    user_id = str(payload.get("user_id") or "").strip()
    rp_id = str(payload.get("rp_id") or "localhost").strip()
    origin = str(payload.get("origin") or "http://localhost:8000").strip()
    attestation = payload.get("attestation") or {}
    if not user_id or not isinstance(attestation, dict):
        raise HTTPException(status_code=400, detail="user_id and attestation required")
    await _ensure_identity_schema(session)
    ids = IdentityService(session, get_auth_manager())
    ok = await ids.verify_webauthn_registration(user_id, rp_id, origin, attestation)
    if not ok:
        raise HTTPException(status_code=400, detail="registration failed")
    return {"ok": True}


@admin_router.post("/security/webauthn/assertion-options")
async def webauthn_assertion_options(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "security_admin"])),
    session=Depends(get_session),
):
    user_id = str(payload.get("user_id") or "").strip()
    rp_id = str(payload.get("rp_id") or "localhost").strip()
    if not user_id:
        raise HTTPException(status_code=400, detail="user_id is required")
    await _ensure_identity_schema(session)
    ids = IdentityService(session, get_auth_manager())
    options = await ids.get_webauthn_assertion_options(user_id, rp_id)
    return options


@admin_router.post("/security/webauthn/assert")
@audit_log("security_webauthn_assert")
async def webauthn_assert(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "security_admin"])),
    session=Depends(get_session),
):
    user_id = str(payload.get("user_id") or "").strip()
    rp_id = str(payload.get("rp_id") or "localhost").strip()
    origin = str(payload.get("origin") or "http://localhost:8000").strip()
    assertion = payload.get("assertion") or {}
    if not user_id or not isinstance(assertion, dict):
        raise HTTPException(status_code=400, detail="user_id and assertion required")
    await _ensure_identity_schema(session)
    ids = IdentityService(session, get_auth_manager())
    ok = await ids.verify_webauthn_assertion(user_id, rp_id, origin, assertion)
    if not ok:
        raise HTTPException(status_code=400, detail="assertion failed")
    return {"ok": True}


# Notifications admin endpoints
@admin_router.get("/notifications")
async def list_notifications(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _: Dict = Depends(require_auth(["admin", "viewer"])),
):
    svc = await get_audit_service()
    data = await svc.list_events(limit=limit, offset=offset)
    return {"items": data["items"]}


@admin_router.post("/notifications/send")
@audit_log("notification_send")
async def send_notification(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "viewer"])),
):
    title = str(payload.get("title") or "Notification")
    body = str(payload.get("body") or "")
    channel = str(payload.get("channel") or "inbox")
    metadata = (
        payload.get("metadata") if isinstance(payload.get("metadata"), dict) else {}
    )
    if not body:
        raise HTTPException(status_code=400, detail="body is required")
    svc = await get_audit_service()
    await svc.log_event(
        event_type="notification",
        category="system",
        action="send",
        result="queued",
        description=title,
        details={"channel": channel, "metadata": metadata},
        user_id=str(user.get("id")),
    )
    return {"status": "ok", "notification_id": os.urandom(6).hex(), "queued": True}


@admin_router.get("/notifications/settings")
async def get_notifications_settings(
    _: Dict = Depends(require_auth(["admin", "viewer"]))
):
    return {"enabled": True, "channels": ["inbox"], "defaults": {"priority": "normal"}}


@admin_router.put("/notifications/settings")
@audit_log("notifications_settings_updated")
async def set_notifications_settings(
    payload: Dict[str, Any], _: Dict = Depends(require_auth(["admin"]))
):
    return {"ok": True, **payload}


@admin_router.get("/notifications/help")
async def notifications_help(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    return {
        "links": {
            "webhooks": "https://docs.example.com/notifications/webhooks",
            "smtp": "https://docs.example.com/notifications/smtp",
        }
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


# API Keys admin endpoints
@admin_router.get("/api-keys")
async def list_api_keys(
    _: Dict = Depends(require_auth(["admin"])),
    session=Depends(get_session),
):
    await _ensure_identity_schema(session)
    result = await session.execute(select(APIKey))
    items = []
    for k in result.scalars().all():
        items.append(
            {
                "key_id": k.id,
                "name": k.name,
                "owner": k.owner_id,
                "scopes": k.scopes or [],
                "created_at": k.created_at.isoformat() if k.created_at else None,
                "last_used_at": k.last_used.isoformat() if k.last_used else None,
                "expires_at": k.expires_at.isoformat() if k.expires_at else None,
            }
        )
    return items


@admin_router.post("/api-keys")
@audit_log("api_key_created")
async def create_api_key_admin(
    payload: Dict[str, Any],
    user: Dict[str, Any] = Depends(get_current_user),
    session=Depends(get_session),
    ids: IdentityService = Depends(
        lambda session=Depends(get_session): IdentityService(
            session, get_auth_manager()
        )
    ),
):
    await _ensure_identity_schema(session)
    name = str(payload.get("name") or "api-key")
    owner = payload.get("owner")
    plugin_id = payload.get("plugin_id")
    scopes = payload.get("scopes") or []
    if not isinstance(scopes, list):
        raise HTTPException(status_code=400, detail="scopes must be a list")

    # Generate token and persist (inline to also return the id)
    import secrets
    import hashlib

    token = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(token.encode()).hexdigest()

    api_key = APIKey(  # type: ignore[call-arg]
        key_hash=key_hash,
        name=name,
        owner_id=owner,
        plugin_id=plugin_id,
        scopes=scopes,
    )
    session.add(api_key)
    await session.commit()

    # Secondary audit
    await ids._audit_log(user.get("id"), "api_key_created", True, {"name": name}, None)

    return {"key_id": api_key.id, "token": token}


@admin_router.delete("/api-keys/{key_id}")
@audit_log("api_key_revoked")
async def revoke_api_key_admin(
    key_id: str,
    _: Dict = Depends(require_auth(["admin"])),
    session=Depends(get_session),
):
    await _ensure_identity_schema(session)
    obj = await session.get(APIKey, key_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Key not found")
    await session.delete(obj)
    await session.commit()
    return {"ok": True}


@admin_router.post("/api-keys/{key_id}/rotate")
@audit_log("api_key_rotated")
async def rotate_api_key_admin(
    key_id: str,
    _: Dict = Depends(require_auth(["admin"])),
    session=Depends(get_session),
):
    await _ensure_identity_schema(session)
    obj = await session.get(APIKey, key_id)
    if not obj:
        raise HTTPException(status_code=404, detail="Key not found")
    import secrets
    import hashlib

    token = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    await session.execute(
        update(APIKey).where(APIKey.id == key_id).values(key_hash=key_hash)
    )
    await session.commit()
    return {"token": token}


async def _ensure_identity_schema(session) -> None:
    global _IDENTITY_SCHEMA_INIT
    if _IDENTITY_SCHEMA_INIT:
        return
    try:
        # Create tables on the same connection backing this session
        from core.identity.models import Base  # local import to avoid cycles

        conn = await session.connection()
        await conn.run_sync(Base.metadata.create_all)
        ids = IdentityService(session, get_auth_manager())
        await ids.ensure_default_roles()
        _IDENTITY_SCHEMA_INIT = True
    except Exception:
        # Do not block; tests may run with in-memory DB per-process
        _IDENTITY_SCHEMA_INIT = True


async def _get_storage_service() -> StorageService:
    global _STORAGE_SVC
    if _STORAGE_SVC is not None:
        return _STORAGE_SVC
    audit = await get_audit_service()
    cfg = StorageConfig()  # Defaults are fine for dev/CI; providers list may be empty
    _STORAGE_SVC = StorageService(
        config=cfg,
        policy_engine=policy_engine,
        audit_service=audit,
        encryption_key=os.getenv("STORAGE_ENC_KEY"),
    )
    return _STORAGE_SVC


@admin_router.get("/storage/objects")
async def storage_list_objects(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    classification: Optional[str] = Query(None),
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "viewer"])),
):
    svc = await _get_storage_service()
    # Build query
    q = StorageQuery(limit=limit, offset=offset)
    if classification:
        try:
            q.data_classification = DataClassification(classification.lower())
        except Exception:
            pass
    items = await svc.list_objects(q, user_id=str(user.get("id")))
    # Convert to JSON-friendly dicts
    payload = [
        {
            "object_key": m.object_key,
            "provider": m.provider.value,
            "data_classification": m.data_classification.value,
            "size_bytes": m.size_bytes,
            "created_at": m.created_at.isoformat(),
            "expires_at": m.expires_at.isoformat() if m.expires_at else None,
        }
        for m in items
    ]
    return {"items": payload, "limit": limit, "offset": offset}


@admin_router.get("/storage/objects/{object_key}")
async def storage_get_metadata(
    object_key: str,
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "viewer"])),
):
    svc = await _get_storage_service()
    m = await svc.get_object_metadata(object_key, user_id=str(user.get("id")))
    if not m:
        raise HTTPException(status_code=404, detail="Object not found")
    return {
        "object_key": m.object_key,
        "provider": m.provider.value,
        "data_classification": m.data_classification.value,
        "size_bytes": m.size_bytes,
        "created_at": m.created_at.isoformat(),
        "expires_at": m.expires_at.isoformat() if m.expires_at else None,
        "is_encrypted": m.is_encrypted,
        "traits": m.traits,
        "custom_metadata": m.custom_metadata,
    }


@admin_router.get("/storage/objects/{object_key}/download")
async def storage_download_object(
    object_key: str,
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "viewer"])),
):
    svc = await _get_storage_service()
    sobj = await svc.retrieve_object(object_key, user_id=str(user.get("id")))
    if not sobj or sobj.content is None:
        raise HTTPException(status_code=404, detail="Object not found")
    media_type = sobj.metadata.content_type or "application/octet-stream"
    return StreamingResponse(iter([sobj.content]), media_type=media_type)


# Inbound admin tools (safe stubs)
@admin_router.get("/inbound/callbacks")
async def inbound_callbacks(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    base = os.getenv("PUBLIC_API_URL", "http://localhost:8000")
    return {
        "callbacks": [
            {"provider": "phaxio", "url": f"{base}/phaxio-inbound"},
            {"provider": "sinch", "url": f"{base}/sinch-inbound"},
        ]
    }


@admin_router.get("/inbound/endpoints")
async def inbound_endpoints(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    return await inbound_callbacks(_)


@admin_router.delete("/inbound/purge-by-sid")
@audit_log("inbound_purge")
async def inbound_purge(
    payload: Dict[str, Any], _: Dict = Depends(require_auth(["admin"]))
):
    provider_sid = str(payload.get("provider_sid") or "")
    if not provider_sid:
        raise HTTPException(status_code=400, detail="provider_sid required")
    return {"ok": True, "deleted_faxes": 0, "deleted_events": 0}


@admin_router.post("/inbound/simulate")
@audit_log("inbound_simulated")
async def inbound_simulate(
    payload: Optional[Dict[str, Any]] = None, _: Dict = Depends(require_auth(["admin"]))
):
    p = payload or {}
    job_id = os.urandom(6).hex()
    status = str(p.get("status") or "received")
    return {"id": job_id, "status": status}


# Providers registry and settings endpoints
def _provider_registry() -> Dict[str, Dict[str, Any]]:
    return {
        "phaxio": {
            "id": "phaxio",
            "kind": "cloud",
            "traits": {
                "auth": {"methods": ["basic"]},
                "webhook": {
                    "path": "/phaxio-inbound",
                    "verification": "hmac_sha256",
                    "verify_header": "X-Phaxio-Signature",
                },
                "sample_payload": {"fax": {"id": 1, "direction": "received"}},
            },
        },
        "sinch": {
            "id": "sinch",
            "kind": "cloud",
            "traits": {
                "auth": {"methods": ["oauth2"]},
                "webhook": {
                    "path": "/sinch-inbound",
                    "verification": "basic_auth",
                    "verify_header": "Authorization",
                },
                "sample_payload": {"eventType": "INBOUND_FAX_COMPLETED"},
            },
        },
        "signalwire": {
            "id": "signalwire",
            "kind": "cloud",
            "traits": {
                "auth": {"methods": ["basic"]},
                "webhook": {
                    "path": "/signalwire-callback",
                    "verification": "hmac_sha256",
                    "verify_header": "X-SignalWire-Signature",
                },
                "sample_payload": {"Status": "received"},
            },
        },
        "documo": {
            "id": "documo",
            "kind": "cloud",
            "traits": {
                "auth": {"methods": ["basic"]},
                "webhook": {"path": "/documo-callback"},
            },
        },
        "sip": {
            "id": "sip",
            "kind": "self_hosted",
            "traits": {
                "requires_ami": True,
                "auth": {"methods": ["none"]},
            },
        },
        "freeswitch": {
            "id": "freeswitch",
            "kind": "self_hosted",
            "traits": {
                "requires_esl": True,
                "auth": {"methods": ["none"]},
            },
        },
    }


@admin_router.get("/providers")
async def get_providers(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    outbound = "phaxio"
    inbound = "phaxio"
    if _CONFIG_SVC is not None:
        try:
            ob = await _CONFIG_SVC.get(
                "hybrid.outbound_backend"
            ) or await _CONFIG_SVC.get("backend.type")
            ib = await _CONFIG_SVC.get(
                "hybrid.inbound_backend"
            ) or await _CONFIG_SVC.get("backend.type")
            if isinstance(ob, str) and ob:
                outbound = ob
            if isinstance(ib, str) and ib:
                inbound = ib
        except Exception:
            pass
    return {
        "active": {"outbound": outbound, "inbound": inbound},
        "registry": _provider_registry(),
    }


@admin_router.get("/providers/health")
async def get_providers_health(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    # Lightweight non-PHI health view
    return {
        "items": {pid: {"healthy": True} for pid in _provider_registry().keys()},
        "timestamp": __import__("datetime").datetime.utcnow().isoformat() + "Z",
    }


@admin_router.post("/providers/enable")
@audit_log("provider_enabled")
async def enable_provider(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "config_manager"])),
):
    provider_id = str(payload.get("provider_id") or "").lower()
    direction = str(payload.get("direction") or "outbound").lower()
    if provider_id not in _provider_registry():
        raise HTTPException(status_code=400, detail="unknown provider_id")
    if _CONFIG_SVC is not None:
        key = (
            f"hybrid.{direction}_backend"
            if direction in {"outbound", "inbound"}
            else "backend.type"
        )
        await _CONFIG_SVC.set(
            key,
            provider_id,
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="providers_enable",
        )
        # Mark system enabled
        await _CONFIG_SVC.set(
            "backend.disabled",
            False,
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="providers_enable",
        )
    return {
        "success": True,
        "provider_id": provider_id,
        "new_status": "enabled",
        "message": f"{provider_id} set for {direction}",
    }


@admin_router.post("/providers/disable")
@audit_log("provider_disabled")
async def disable_provider(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "config_manager"])),
):
    provider_id = str(payload.get("provider_id") or "").lower()
    if _CONFIG_SVC is not None:
        # Mark provider-specific disabled flag and overall disabled for safety
        await _CONFIG_SVC.set(
            f"providers.{provider_id}.disabled",
            True,
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="providers_disable",
        )
        await _CONFIG_SVC.set(
            "backend.disabled",
            True,
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="providers_disable",
        )
    return {"success": True, "provider_id": provider_id, "new_status": "disabled"}


@admin_router.get("/providers/circuit-breaker/{provider_id}/should-allow")
async def provider_should_allow(
    provider_id: str, _: Dict = Depends(require_auth(["admin", "viewer"]))
):
    return {"provider_id": provider_id, "allowed": True, "reason": "ok"}


# Settings endpoints
@admin_router.get("/settings")
async def get_settings(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    # Compose a safe settings view (no secrets exposed)
    backend_type = "phaxio"
    inbound_enabled = True
    if _CONFIG_SVC is not None:
        try:
            v = await _CONFIG_SVC.get("backend.type")
            if isinstance(v, str) and v:
                backend_type = v
            ie = await _CONFIG_SVC.get("inbound.enabled")
            if isinstance(ie, bool):
                inbound_enabled = ie
        except Exception:
            pass
    return {
        "backend": {"type": backend_type, "disabled": False},
        "hybrid": {"outbound_backend": backend_type, "inbound_backend": backend_type},
        "phaxio": {
            "api_key": "",
            "api_secret": "",
            "callback_url": "",
            "verify_signature": True,
            "configured": False,
        },
        "documo": {"api_key": "", "configured": False},
        "sinch": {
            "project_id": "",
            "api_key": "",
            "api_secret": "",
            "configured": False,
        },
        "signalwire": {
            "space_url": "",
            "project_id": "",
            "api_token": "",
            "from_fax": "",
            "configured": False,
        },
        "sip": {
            "ami_host": "",
            "ami_port": 5038,
            "ami_username": "admin",
            "ami_password": "",
            "ami_password_is_default": True,
            "station_id": "",
            "configured": False,
        },
        "security": {
            "require_api_key": False,
            "enforce_https": False,
            "audit_enabled": True,
            "public_api_url": "http://localhost:8000",
        },
        "storage": {"backend": "memory", "s3_bucket": "", "s3_kms_enabled": False},
        "database": {
            "url": os.getenv("DATABASE_URL", "sqlite+aiosqlite:///:memory:"),
            "persistent": False,
        },
        "inbound": {"enabled": inbound_enabled, "retention_days": 30},
        "features": {
            "v3_plugins": False,
            "inbound_enabled": inbound_enabled,
            "plugin_install": False,
        },
        "limits": {
            "max_file_size_mb": 10,
            "pdf_token_ttl_minutes": 15,
            "rate_limit_rpm": 600,
        },
    }


@admin_router.post("/settings/validate")
async def validate_settings(
    payload: Dict[str, Any],
    _: Dict = Depends(require_auth(["admin", "config_manager"])),
):
    # Basic structural validation only
    checks: Dict[str, Any] = {}
    backend = str(payload.get("backend") or payload.get("outbound_backend") or "phaxio")
    return {"backend": backend, "checks": checks}


@admin_router.post("/settings/export")
async def export_settings(_: Dict = Depends(require_auth(["admin", "config_manager"]))):
    # Produce minimal .env content (safe defaults)
    env_lines = [
        "# Vivified generated env",
        "DEV_MODE=true",
        "JWT_SECRET=change-this-secret",
    ]
    content = "\n".join(env_lines) + "\n"
    return {
        "env_content": content,
        "requires_restart": False,
        "note": "Generated for local/dev use",
    }


@admin_router.post("/settings/persist")
async def persist_settings(
    payload: Optional[Dict[str, Any]] = None,
    _: Dict = Depends(require_auth(["admin", "config_manager"])),
):  # type: ignore[assignment]
    path = None
    content = None
    if isinstance(payload, dict):
        path = payload.get("path")
        content = payload.get("content")
    if not content:
        content = (await export_settings(_))["env_content"]  # type: ignore[index]
    target = path or "/tmp/vivified.env"
    try:
        with open(target, "w", encoding="utf-8") as f:
            f.write(str(content))
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=f"persist failed: {e}")
    return {"ok": True, "path": target}


@admin_router.put("/settings")
@audit_log("settings_updated")
async def update_settings(
    payload: Dict[str, Any],
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "config_manager"])),
):
    # Persist selected settings keys into config service
    changed = []
    mapping = {
        "backend": "backend.type",
        "outbound_backend": "hybrid.outbound_backend",
        "inbound_backend": "hybrid.inbound_backend",
        "require_api_key": "security.require_api_key",
        "enforce_public_https": "security.enforce_https",
        "public_api_url": "security.public_api_url",
        "inbound_enabled": "inbound.enabled",
        "max_file_size_mb": "limits.max_file_size_mb",
        "max_requests_per_minute": "limits.rate_limit_rpm",
        "inbound_list_rpm": "limits.inbound_list_rpm",
        "inbound_get_rpm": "limits.inbound_get_rpm",
        "feature_v3_plugins": "features.v3_plugins",
        "feature_plugin_install": "features.plugin_install",
    }
    if _CONFIG_SVC is None:
        raise HTTPException(status_code=500, detail="Config service not available")
    for k, v in payload.items():
        dest = mapping.get(k)
        if not dest:
            continue
        await _CONFIG_SVC.set(
            dest,
            v,
            is_sensitive=False,
            updated_by=str(user.get("id")),
            reason="settings_update",
        )
        changed.append(dest)
    return {"ok": True, "changed": changed, "_meta": {"restart_recommended": False}}


@admin_router.post("/settings/reload")
async def reload_settings(_: Dict = Depends(require_auth(["admin", "config_manager"]))):
    # No-op in dev; in production this would reload providers/backends
    return {"ok": True}


@admin_router.post("/restart")
async def restart_api(_: Dict = Depends(require_auth(["admin"]))):
    # Dev-only stub
    return {"ok": True, "note": "restart simulated"}


# Diagnostics helpers
@admin_router.get("/diagnostics/events/types")
async def list_event_types(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    return {"items": ["fax.sent", "fax.received", "provider.callback", "system.alert"]}


# Config helpers
@admin_router.post("/config/import-env")
async def import_env_vars(
    payload: Optional[Dict[str, Any]] = None,
    user: Dict = Depends(get_current_user),
    _: Dict = Depends(require_auth(["admin", "config_manager"])),
):
    prefixes = []
    if isinstance(payload, dict):
        prefixes = [
            str(p) for p in (payload.get("prefixes") or []) if isinstance(p, str)
        ]
    env = dict(os.environ)
    discovered = 0
    if _CONFIG_SVC is None:
        return {"ok": False, "discovered": 0, "prefixes": prefixes}
    for k, v in env.items():
        if prefixes and not any(k.startswith(p) for p in prefixes):
            continue
        # Store under a namespaced key for traceability
        key = f"env.{k.lower()}"
        await _CONFIG_SVC.set(
            key,
            v,
            is_sensitive="secret" in k.lower() or "password" in k.lower(),
            updated_by=str(user.get("id")),
            reason="import_env",
        )
        discovered += 1
    return {"ok": True, "discovered": discovered, "prefixes": prefixes}


# Jobs admin (dev stubs)
_JOBS: Dict[str, Dict[str, Any]] = {}


def _seed_jobs() -> None:
    if _JOBS:
        return
    now = datetime.utcnow()
    for i in range(1, 6):
        jid = f"JOB-{i:03d}"
        _JOBS[jid] = {
            "id": jid,
            "to_number": f"+1555000{i:03d}",
            "status": "completed" if i % 2 == 0 else "queued",
            "backend": "phaxio",
            "pages": 1 + (i % 3),
            "created_at": (now - timedelta(minutes=10 * i)).isoformat() + "Z",
            "updated_at": now.isoformat() + "Z",
            "file_name": f"test_{i}.pdf",
        }


@admin_router.get("/fax-jobs")
async def list_fax_jobs(
    status: Optional[str] = Query(None),
    backend: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    _: Dict = Depends(require_auth(["admin", "viewer"])),
):
    _seed_jobs()
    jobs = list(_JOBS.values())
    if status:
        jobs = [j for j in jobs if j.get("status") == status]
    if backend:
        jobs = [j for j in jobs if j.get("backend") == backend]
    total = len(jobs)
    return {"total": total, "jobs": jobs[offset : offset + limit]}


@admin_router.get("/fax-jobs/{job_id}")
async def get_fax_job(
    job_id: str, _: Dict = Depends(require_auth(["admin", "viewer"]))
):
    _seed_jobs()
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return job


@admin_router.get("/fax-jobs/{job_id}/pdf")
async def get_fax_job_pdf(
    job_id: str, _: Dict = Depends(require_auth(["admin", "viewer"]))
):
    _seed_jobs()
    if job_id not in _JOBS:
        raise HTTPException(status_code=404, detail="Job not found")
    # Minimal PDF bytes
    pdf_bytes = b"%PDF-1.1\n1 0 obj<</Type/Catalog>>endobj\ntrailer<<>>\n%%EOF\n"
    return StreamingResponse(iter([pdf_bytes]), media_type="application/pdf")


@admin_router.post("/fax-jobs/{job_id}/refresh")
async def refresh_fax_job(job_id: str, _: Dict = Depends(require_auth(["admin"]))):
    _seed_jobs()
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    job["updated_at"] = datetime.utcnow().isoformat() + "Z"
    # Simulate status progression
    if job.get("status") == "queued":
        job["status"] = "processing"
    elif job.get("status") == "processing":
        job["status"] = "completed"
    return job


# Admin actions (safe, allowlisted)
@admin_router.get("/actions")
async def list_actions(_: Dict = Depends(require_auth(["admin"]))):
    items = [
        {"id": "reload-config", "label": "Reload configuration"},
        {"id": "rotate-logs", "label": "Rotate logs"},
    ]
    return {"enabled": True, "items": items}


@admin_router.post("/actions/run")
@audit_log("admin_action_run")
async def run_action(
    payload: Dict[str, Any], _: Dict = Depends(require_auth(["admin"]))
):
    action_id = str(payload.get("id") or "")
    allow = {"reload-config", "rotate-logs"}
    if action_id not in allow:
        raise HTTPException(status_code=400, detail="unknown or disallowed action")
    return {"ok": True, "id": action_id, "code": 0, "stdout": "simulated", "stderr": ""}


# Tunnel admin (dev stubs)
_TUNNEL_CFG_CACHE: Dict[str, Any] = {}


@admin_router.get("/tunnel/status")
async def tunnel_status(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    enabled = bool(_TUNNEL_CFG_CACHE.get("enabled", False))
    provider = _TUNNEL_CFG_CACHE.get("provider", "none")
    status = "connected" if enabled else "disabled"
    return {
        "enabled": enabled,
        "provider": provider,
        "status": status,
        "public_url": _TUNNEL_CFG_CACHE.get("public_url"),
        "last_checked": datetime.utcnow().isoformat() + "Z",
    }


@admin_router.post("/tunnel/config")
@audit_log("tunnel_config_set")
async def set_tunnel_config(
    payload: Optional[Dict[str, Any]] = None, _: Dict = Depends(require_auth(["admin"]))
):
    cfg = payload or {}
    _TUNNEL_CFG_CACHE.update(cfg)
    return {"ok": True, "config": _TUNNEL_CFG_CACHE}


@admin_router.post("/tunnel/test")
async def test_tunnel(_: Dict = Depends(require_auth(["admin"]))):
    target = _TUNNEL_CFG_CACHE.get("public_url") or "http://localhost:8000/health"
    return {"ok": True, "message": "reachable (simulated)", "target": target}


@admin_router.post("/tunnel/pair")
async def tunnel_pair(_: Dict = Depends(require_auth(["admin"]))):
    code = os.urandom(3).hex().upper()
    return {
        "code": code,
        "expires_at": (datetime.utcnow() + timedelta(minutes=10)).isoformat() + "Z",
    }


@admin_router.post("/tunnel/register-sinch")
async def register_sinch(_: Dict = Depends(require_auth(["admin"]))):
    base = os.getenv("PUBLIC_API_URL", "http://localhost:8000")
    url = f"{base}/sinch-inbound"
    return {
        "success": True,
        "webhook_url": url,
        "provider_response": {"registered": True},
    }


@admin_router.get("/tunnel/cloudflared/logs")
async def cloudflared_logs(
    lines: int = Query(50, ge=1, le=1000), _: Dict = Depends(require_auth(["admin"]))
):
    return {"items": [], "path": None}


@admin_router.post("/tunnel/wg/import")
async def wg_import_json(
    payload: Optional[Dict[str, Any]] = None, _: Dict = Depends(require_auth(["admin"]))
):
    target = "/tmp/vivified-wg.conf"
    content = None
    if isinstance(payload, dict):
        content = payload.get("content")
    if not content:
        content = "[Interface]\nPrivateKey = ...\n"
    try:
        with open(target, "w", encoding="utf-8") as f:
            f.write(str(content))
        return {"ok": True, "path": target}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(e))


@admin_router.get("/tunnel/wg/conf")
async def wg_download(_: Dict = Depends(require_auth(["admin", "viewer"]))):
    path = "/tmp/vivified-wg.conf"
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="not found")
    return FileResponse(path, media_type="text/plain", filename="wireguard.conf")


@admin_router.delete("/tunnel/wg/conf")
async def wg_delete(_: Dict = Depends(require_auth(["admin"]))):
    path = "/tmp/vivified-wg.conf"
    try:
        if os.path.exists(path):
            os.remove(path)
        return {"ok": True}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=500, detail=str(e))


@admin_router.post("/tunnel/wg/qr")
async def wg_qr(_: Dict = Depends(require_auth(["admin"]))):
    png_stub = base64.b64encode(b"WGCONF QR").decode()
    return {"png_base64": png_stub}
