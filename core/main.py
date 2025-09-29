from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime
import os
from typing import Dict, Any
from starlette.responses import FileResponse

from .plugin_manager.registry import PluginRegistry
from .api import admin_router, auth_router
from .api.dependencies import require_auth
from .identity.auth import rate_limit
from .api.admin import configure_admin_api
from .config.service import get_config_service
from .identity.auth import dev_issue_admin_token
from .messaging.service import MessagingService
from .canonical.service import CanonicalService
from .canonical.schema_registry import SchemaRegistry
from .gateway.service import GatewayService
from .audit.service import get_audit_service
from .policy.engine import policy_engine
from .monitoring.metrics import metrics_router
from .notifications.service import NotificationsService
from .api.notifications import notifications_router, configure_notifications_api


class AddTraceIdFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, "trace_id"):
            record.trace_id = "system"
        return True


logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s - %(name)s - %(levelname)s - trace_id=%(trace_id)s - %(message)s",
)
logger = logging.getLogger("vivified.core")
logger.addFilter(AddTraceIdFilter())

app = FastAPI(
    title="Vivified Core Platform",
    version="1.0.0",
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[o for o in os.getenv("ALLOWED_ORIGINS", "").split(",") if o],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


JWT_SECRET = os.getenv("JWT_SECRET", "change-this-secret")
registry = PluginRegistry(jwt_secret=JWT_SECRET)

# Initialize core services
audit_service = None  # Will be resolved on startup
messaging_service = None  # Will be initialized on startup
canonical_service = None  # Will be initialized on startup
schema_registry = SchemaRegistry()
gateway_service = None  # Will be initialized on startup
notifications_service = None  # Will be initialized on startup
storage_service = None  # Will be initialized when needed

# Wire admin API dependencies
configure_admin_api(config_service=get_config_service(), registry=registry)
app.include_router(admin_router)
app.include_router(auth_router)
app.include_router(metrics_router)
app.include_router(notifications_router)


class ManifestModel(BaseModel):
    id: str
    name: str
    version: str
    description: str | None = None
    contracts: list[str]
    traits: list[str]
    dependencies: list[str] | None = []
    allowed_domains: list[str] | None = []
    endpoints: Dict[str, str] | None = None
    security: Dict[str, Any]
    compliance: Dict[str, Any]


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0",
    }


@app.on_event("startup")
async def startup_event():
    logger.info("Vivified Core Platform starting")

    # Start core services
    try:
        # Resolve audit service and initialize dependent services lazily
        global audit_service, messaging_service, canonical_service, gateway_service, notifications_service
        audit_service = await get_audit_service()

        if messaging_service is None:
            messaging_service = MessagingService(audit_service, policy_engine)
        if canonical_service is None:
            canonical_service = CanonicalService(audit_service, policy_engine)
        if gateway_service is None:
            # Pass config service for allowlist hydration
            gateway_service = GatewayService(
                audit_service, policy_engine, get_config_service()
            )
        if notifications_service is None:
            notifications_service = NotificationsService(
                audit_service, messaging_service, policy_engine
            )

        await messaging_service.start()
        await canonical_service.start()
        await gateway_service.start()
        await notifications_service.start()
        configure_notifications_api(svc=notifications_service)
        logger.info("Core services started successfully")
    except Exception as e:
        logger.error(f"Failed to start core services: {e}")

    # Optional DB bootstrap for Identity
    if os.getenv("DB_INIT", "false").lower() in {"1", "true", "yes"}:
        try:
            from .database import get_engine, async_session_factory
            from .identity.service import IdentityService
            from .identity.auth import get_auth_manager

            engine = get_engine()
            async with engine.begin():
                pass
            # Create schema and defaults
            async with async_session_factory() as session:
                ids = IdentityService(session, get_auth_manager())
                await ids.init_schema(engine)
                await ids.ensure_default_roles()
                # Seed admin user if provided (only if credentials set)
                admin_user = os.getenv("ADMIN_USERNAME")
                admin_pass = os.getenv("ADMIN_PASSWORD")
                if admin_user and admin_pass:
                    await ids.ensure_admin_user(admin_user, admin_pass)
        except Exception as e:  # noqa: BLE001
            logger.exception("DB init failed: %s", e)


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Vivified Core Platform shutting down")

    # Stop core services
    try:
        if messaging_service is not None:
            await messaging_service.stop()
        if canonical_service is not None:
            await canonical_service.stop()
        if gateway_service is not None:
            await gateway_service.stop()
        if notifications_service is not None:
            await notifications_service.stop()
        logger.info("Core services stopped successfully")
    except Exception as e:
        logger.error(f"Error stopping core services: {e}")


@app.post("/plugins/register")
async def register_plugin(manifest: ManifestModel):
    try:
        result = await registry.register_plugin(manifest.model_dump())
        # Sync allowlists from manifest.allowed_domains into GatewayService
        try:
            if gateway_service is not None:
                allowed = manifest.allowed_domains or []
                for domain in allowed:
                    try:
                        await gateway_service.add_domain_allowlist(
                            plugin_id=manifest.id,
                            domain=str(domain),
                            allowed_methods=["GET", "POST"],
                            allowed_paths=[],
                        )
                    except Exception:
                        logger.debug(
                            "allowlist sync failed for %s", domain, exc_info=True
                        )
        except Exception:
            logger.debug("allowlist sync error", exc_info=True)
        return result
    except HTTPException as e:
        raise e
    except Exception as e:  # noqa: BLE001
        logger.exception("Plugin registration failed: %s", e)
        raise HTTPException(status_code=500, detail="Registration error")


@app.get("/plugins")
async def list_plugins():
    return {"plugins": list(registry.plugins.values())}


# Messaging endpoints
@app.post("/messaging/events")
async def publish_event(
    event_type: str,
    payload: Dict[str, Any],
    source_plugin: str,
    data_traits: list[str] | None = None,
    metadata: dict[str, str] | None = None,
):
    """Publish an event to the event bus."""
    try:
        if messaging_service is None:
            raise HTTPException(status_code=503, detail="Messaging service unavailable")
        event_id = await messaging_service.publish_event(
            event_type=event_type,
            payload=payload,
            source_plugin=source_plugin,
            data_traits=data_traits,
            metadata=metadata,
        )
        return {"event_id": event_id, "status": "published"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/messaging/stats")
async def get_messaging_stats():
    """Get messaging service statistics."""
    try:
        if messaging_service is None:
            raise HTTPException(status_code=503, detail="Messaging service unavailable")
        stats = await messaging_service.get_message_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Canonical service endpoints
@app.post("/canonical/normalize/user")
async def normalize_user(
    user_data: Dict[str, Any], source_plugin: str, target_plugin: str
):
    """Normalize user data to canonical format."""
    try:
        if canonical_service is None:
            raise HTTPException(status_code=503, detail="Canonical service unavailable")
        canonical_user = await canonical_service.normalize_user(
            user_data=user_data,
            source_plugin=source_plugin,
            target_plugin=target_plugin,
        )
        return canonical_user.dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/canonical/stats")
async def get_canonical_stats():
    """Get canonical service statistics."""
    try:
        if canonical_service is None:
            raise HTTPException(status_code=503, detail="Canonical service unavailable")
        stats = await canonical_service.get_transformation_stats()
        return stats
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Gateway service endpoints
@app.post("/gateway/proxy")
@rate_limit(
    limit=120,
    window_seconds=60,
    key_fn=lambda *a, **k: f"proxy:{k.get('plugin_id','unknown')}",
)
async def proxy_request(
    plugin_id: str,
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 30,
):
    """Proxy a request to an external API."""
    try:
        if gateway_service is None:
            raise HTTPException(status_code=503, detail="Gateway service unavailable")
        response = await gateway_service.proxy_request(
            plugin_id=plugin_id,
            method=method,
            url=url,
            headers=headers,
            body=body,
            timeout=timeout,
        )
        return response.dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/gateway/stats")
async def get_gateway_stats():
    """Get gateway service statistics."""
    try:
        if gateway_service is None:
            raise HTTPException(status_code=503, detail="Gateway service unavailable")
        stats = await gateway_service.get_stats()
        return stats.dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/gateway/allowlist/effective")
async def get_allowlist_effective(
    plugin_id: str | None = None,
    _: Dict = Depends(require_auth(["admin", "plugin_manager", "config_manager"])),
):
    """Admin: Inspect effective allowlist entries."""
    try:
        if gateway_service is None:
            raise HTTPException(status_code=503, detail="Gateway service unavailable")
        entries = await gateway_service.get_allowlist(plugin_id=plugin_id)
        # Pydantic models are JSON serializable
        return {"entries": [e.dict() for e in entries]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/gateway/allowlist/reload")
async def reload_allowlists(
    plugin_id: str | None = None,
    _: Dict = Depends(require_auth(["admin", "plugin_manager", "config_manager"])),
):
    """Admin: Preload/refresh gateway allowlists from config service."""
    try:
        if gateway_service is None:
            raise HTTPException(status_code=503, detail="Gateway service unavailable")
        count = await gateway_service.preload_allowlists(
            [plugin_id] if plugin_id else None
        )
        return {"ok": True, "loaded": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Operator lane endpoint (RPC via core gateway)
class OperatorRequestModel(BaseModel):
    caller_plugin: str
    payload: Dict[str, Any] | None = None
    timeout: int | None = 30


@app.post("/gateway/{target_plugin}/{operation}")
@rate_limit(
    limit=240,
    window_seconds=60,
    key_fn=lambda *a, **k: f"rpc:{getattr(k.get('req', None), 'caller_plugin', 'unknown')}",
)
async def operator_invoke(
    target_plugin: str, operation: str, req: OperatorRequestModel
):
    """Route an operator (RPC) call from one plugin to another.

    This minimal implementation forwards to the target plugin's declared endpoint
    using the plugin registry's manifest endpoints mapping.
    """
    try:
        # Policy check for operator lane
        try:
            from .policy.engine import PolicyRequest, PolicyContext, PolicyDecision

            pol = PolicyRequest(
                user_id=None,
                resource_type="operator",
                resource_id=f"{req.caller_plugin}->{target_plugin}:{operation}",
                action="operator_call",
                traits=[],
                context={"operation": operation},
                policy_context=PolicyContext.PLUGIN_INTERACTION,
                source_plugin=req.caller_plugin,
                target_plugin=target_plugin,
            )
            decision = await policy_engine.evaluate_request(pol)
            if getattr(decision, "decision", None) == PolicyDecision.DENY:
                raise HTTPException(
                    status_code=403, detail="Operator call denied by policy"
                )
        except Exception:
            # On errors evaluating policy, continue but log; defaults to allow in minimal engine
            logger.debug("operator policy evaluation failed", exc_info=True)

        # Resolve target plugin info
        target = registry.plugins.get(target_plugin)
        if not target or not isinstance(target, dict):
            raise HTTPException(status_code=404, detail="Target plugin not found")

        manifest = target.get("manifest") or {}
        endpoints = manifest.get("endpoints") or {}

        # Resolve endpoint by operation name or direct path
        endpoint_path = endpoints.get(operation) or endpoints.get(
            operation.replace("_", "-")
        )
        if not endpoint_path or not isinstance(endpoint_path, str):
            raise HTTPException(
                status_code=404, detail=f"Operation '{operation}' not found"
            )

        # Construct internal URL (docker/k8s service DNS) — default to plugin_id:8080
        plugin_host = manifest.get("host") or target_plugin
        plugin_port = manifest.get("port") or 8080
        target_url = f"http://{plugin_host}:{plugin_port}{endpoint_path}"

        # Forward request
        import httpx

        async with httpx.AsyncClient(timeout=req.timeout or 30) as client:
            resp = await client.post(
                target_url,
                json=req.payload or {},
                headers={
                    "X-Caller-Plugin": req.caller_plugin,
                    "X-Trace-Id": os.getenv("TRACE_ID", "system"),
                    "Authorization": f"Bearer {registry.plugins.get(req.caller_plugin, {}).get('token', '')}",
                },
            )
        if resp.status_code >= 400:
            raise HTTPException(status_code=resp.status_code, detail=resp.text)
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}

        # Audit operator call
        try:
            await get_audit_service().log_event(  # type: ignore[attr-defined]
                event_type="operator_call",
                category="operator",
                action=operation,
                result="success",
                description=f"{req.caller_plugin} -> {target_plugin}:{operation}",
                resource_type="operator",
                resource_id=target_url,
                plugin_id=req.caller_plugin,
                details={"status": resp.status_code},
            )
        except Exception:
            logger.debug("operator call audit failed", exc_info=True)
        return data
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        logger.exception("Operator call failed: %s", e)
        raise HTTPException(status_code=500, detail="Internal gateway error")


class HeartbeatModel(BaseModel):
    health: str | None = "healthy"


@app.post("/plugins/{plugin_id}/heartbeat")
async def plugin_heartbeat(plugin_id: str, status: HeartbeatModel):
    ok = await registry.heartbeat(plugin_id, status.model_dump())
    if not ok:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return {"status": "ok"}


class PluginConfigModel(BaseModel):
    enabled: bool | None = True
    settings: Dict[str, Any] | None = {}


@app.get("/plugins/{plugin_id}/config")
async def get_plugin_config(
    plugin_id: str,  # noqa: ARG001 - reserved for future use
    _: Dict = Depends(require_auth(["admin", "plugin_manager"])),
):
    # Phase 1 stub: return a safe, empty config
    return {"enabled": True, "settings": {}}


@app.put("/plugins/{plugin_id}/config")
async def set_plugin_config(
    plugin_id: str,  # noqa: ARG001 - reserved for future use
    payload: PluginConfigModel,
    _: Dict = Depends(require_auth(["admin", "plugin_manager"])),
):
    # Phase 1 stub: accept payload but do not persist; respond shape-compatible
    return {"ok": True, "path": "in-memory"}


class DevLoginRequest(BaseModel):
    enabled: bool | None = True


@app.post("/auth/dev-login")
@rate_limit(limit=10, window_seconds=60, key="dev_login")
async def dev_login(_: DevLoginRequest):
    """Issue a short-lived admin token for development when DEV_MODE is enabled."""
    try:
        token = dev_issue_admin_token()
    except PermissionError:
        raise HTTPException(status_code=403, detail="Dev login disabled")
    return {"token": token, "expires_in": 1800}


# Admin Console static hosting (SPA)
def _admin_ui_dist() -> str:
    """Resolve absolute path to built Admin UI dist directory."""
    here = os.path.dirname(__file__)
    dist = os.path.join(here, "admin_ui", "dist")
    return os.path.abspath(dist)


_DIST_DIR = _admin_ui_dist()
INDEX_FILE = os.path.join(_DIST_DIR, "index.html")


@app.get("/admin/ui", include_in_schema=False)
async def admin_ui_root():
    if os.path.exists(INDEX_FILE):
        return FileResponse(INDEX_FILE)
    # Fallback lightweight placeholder to satisfy health and tests
    return (
        FileResponse(
            path=(
                os.path.join(os.path.dirname(__file__), "admin_ui", "index.html")
                if os.path.exists(
                    os.path.join(os.path.dirname(__file__), "admin_ui", "index.html")
                )
                else None
            ),  # type: ignore[arg-type]
        )
        if os.path.exists(
            os.path.join(os.path.dirname(__file__), "admin_ui", "index.html")
        )
        else _admin_ui_placeholder()
    )


@app.get("/admin/ui/{path:path}", include_in_schema=False)
async def admin_ui_spa(path: str):
    # Prevent path traversal and serve SPA index fallback when file not found
    safe_root = _DIST_DIR
    requested = os.path.abspath(os.path.normpath(os.path.join(safe_root, path)))
    if requested.startswith(safe_root) and os.path.isfile(requested):
        return FileResponse(requested)
    if os.path.exists(INDEX_FILE):
        return FileResponse(INDEX_FILE)
    return _admin_ui_placeholder()


def _admin_ui_placeholder():
    from fastapi.responses import HTMLResponse

    html = (
        "<!doctype html><html><head><meta charset='utf-8'><title>Vivified Admin UI</title>"
        "</head><body><h1>Vivified Admin UI</h1><p>Placeholder UI loaded.</p></body></html>"
    )
    return HTMLResponse(content=html, media_type="text/html")


# Canonical Schemas stubs to satisfy Admin UI until registry is implemented
class SchemaUpsertModel(BaseModel):
    name: str
    major: int
    minor: int | None = 0
    patch: int | None = 0
    schema_data: Dict[str, Any] | None = None


@app.get("/schemas/{name}")
async def list_schemas(name: str, _: Dict = Depends(require_auth(["admin"]))):
    versions = schema_registry.list_versions(name)
    return {"name": name, "versions": versions}


@app.get("/schemas/{name}/active/{major}")
async def get_active_schema(
    name: str, major: int, _: Dict = Depends(require_auth(["admin"]))
):
    active = schema_registry.get_active(name, major)
    return {
        "name": name,
        "major": major,
        "active": (active.schema_data if active else None),
    }


@app.post("/schemas")
async def upsert_schema(
    payload: SchemaUpsertModel, _: Dict = Depends(require_auth(["admin"]))
):
    ver = (payload.major, payload.minor or 0, payload.patch or 0)
    schema_registry.upsert(payload.name, ver, payload.schema_data or {})
    try:
        await get_audit_service().log_event(  # type: ignore[attr-defined]
            event_type="schema_upsert",
            category="canonical",
            action="upsert",
            result="success",
            description=f"Upsert schema {payload.name} {ver}",
            resource_type="canonical_schema",
            resource_id=f"{payload.name}:{ver}",
        )
    except Exception:
        logger.debug("schema upsert audit failed", exc_info=True)
    return {"ok": True, "name": payload.name, "version": list(ver)}


class SchemaActivateModel(BaseModel):
    name: str
    major: int
    minor: int | None = 0
    patch: int | None = 0


@app.post("/schemas/activate")
async def activate_schema(
    payload: SchemaActivateModel, _: Dict = Depends(require_auth(["admin"]))
):
    ver = (payload.major, payload.minor or 0, payload.patch or 0)
    ok = schema_registry.activate(payload.name, ver)
    if not ok:
        raise HTTPException(status_code=404, detail="Schema version not found")
    try:
        await get_audit_service().log_event(  # type: ignore[attr-defined]
            event_type="schema_activate",
            category="canonical",
            action="activate",
            result="success",
            description=f"Activate schema {payload.name} {ver}",
            resource_type="canonical_schema",
            resource_id=f"{payload.name}:{ver}",
        )
    except Exception:
        logger.debug("schema activate audit failed", exc_info=True)
    return {"ok": True, "name": payload.name, "version": list(ver)}
