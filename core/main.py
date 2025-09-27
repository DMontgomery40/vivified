from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime
import os
from typing import Dict, Any

from .plugin_manager.registry import PluginRegistry
from .api import admin_router, auth_router
from .api.admin import configure_admin_api
from .config.service import get_config_service
from .identity.auth import dev_issue_admin_token


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


class HeartbeatModel(BaseModel):
    health: str | None = "healthy"


@app.post("/plugins/{plugin_id}/heartbeat")
async def plugin_heartbeat(plugin_id: str, status: HeartbeatModel):
    ok = await registry.heartbeat(plugin_id, status.model_dump())
    if not ok:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return {"status": "ok"}


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
