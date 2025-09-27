from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import logging
from datetime import datetime
import os
from typing import Dict, Any

from .plugin_manager.registry import PluginRegistry


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

