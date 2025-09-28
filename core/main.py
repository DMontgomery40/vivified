from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime
import os
from typing import Dict, Any, List
from starlette.responses import FileResponse

from .plugin_manager.registry import PluginRegistry
from .api import admin_router, auth_router
from .api.dependencies import require_auth
from .api.admin import configure_admin_api
from .config.service import get_config_service
from .identity.auth import dev_issue_admin_token
from .messaging.service import MessagingService
from .canonical.service import CanonicalService
from .gateway.service import GatewayService
from .audit.service import get_audit_service
from .policy.engine import policy_engine


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
gateway_service = None  # Will be initialized on startup
storage_service = None  # Will be initialized when needed

# Wire admin API dependencies
configure_admin_api(config_service=get_config_service(), registry=registry)
app.include_router(admin_router)
app.include_router(auth_router)


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
        global audit_service, messaging_service, canonical_service, gateway_service
        audit_service = await get_audit_service()

        if messaging_service is None:
            messaging_service = MessagingService(audit_service, policy_engine)
        if canonical_service is None:
            canonical_service = CanonicalService(audit_service, policy_engine)
        if gateway_service is None:
            gateway_service = GatewayService(audit_service, policy_engine)

        await messaging_service.start()
        await canonical_service.start()
        await gateway_service.start()
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
        logger.info("Core services stopped successfully")
    except Exception as e:
        logger.error(f"Error stopping core services: {e}")


@app.post("/plugins/register")
async def register_plugin(manifest: ManifestModel):
    try:
        result = await registry.register_plugin(manifest.model_dump())
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
    data_traits: List[str] = None,
    metadata: Dict[str, str] = None,
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
async def proxy_request(
    plugin_id: str,
    method: str,
    url: str,
    headers: Dict[str, str] = None,
    body: bytes = None,
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


if os.path.isdir(_DIST_DIR):
    INDEX_FILE = os.path.join(_DIST_DIR, "index.html")

    @app.get("/admin/ui", include_in_schema=False)
    async def admin_ui_root():
        if os.path.exists(INDEX_FILE):
            return FileResponse(INDEX_FILE)
        raise HTTPException(status_code=404, detail="Admin UI not built")

    @app.get("/admin/ui/{path:path}", include_in_schema=False)
    async def admin_ui_spa(path: str):
        # Prevent path traversal and serve SPA index fallback when file not found
        safe_root = _DIST_DIR
        requested = os.path.abspath(os.path.normpath(os.path.join(safe_root, path)))
        if requested.startswith(safe_root) and os.path.isfile(requested):
            return FileResponse(requested)
        if os.path.exists(INDEX_FILE):
            return FileResponse(INDEX_FILE)
        raise HTTPException(status_code=404, detail="Admin UI not built")
