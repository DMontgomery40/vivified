from __future__ import annotations
from fastapi import FastAPI, HTTPException, Depends, Body
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import logging
from datetime import datetime
import os
import asyncio
from typing import Dict, Any, Optional, List
from starlette.responses import FileResponse

from .plugin_manager.registry import PluginRegistry
from .api import admin_router, auth_router
from .api.dependencies import require_auth, get_current_user
from .identity.auth import rate_limit
from .api.admin import configure_admin_api
from .config.service import get_config_service
from .identity.auth import dev_issue_admin_token
from .messaging.service import MessagingService
from .canonical.service import CanonicalService
from .canonical.schema_registry import SchemaRegistry
from .canonical.schema_loader import load_builtin_schemas
from .gateway.service import GatewayService
from .audit.service import get_audit_service
from .policy.engine import policy_engine
from .monitoring.metrics import metrics_router
from .notifications.service import NotificationsService
from .api.notifications import notifications_router, configure_notifications_api
from .automation.service import AutomationService
from .api.automation import automation_router, configure_automation_api
from .ai.service import RAGService
from .api.admin_ai import ai_router as admin_ai_router, configure_ai_api
from starlette.responses import JSONResponse, StreamingResponse
import json


async def _migrate_env_to_config():
    """Bootstrap ConfigService from env for dev convenience.

    Only sets values that are currently unset in ConfigService.
    """
    try:
        # Allow disabling migration in production or CI
        if os.getenv("CONFIG_ENV_MIGRATE", "true").lower() not in {"1", "true", "yes"}:
            return
        cfg = get_config_service()
        # Provider
        prov_env = os.getenv("AI_LLM_PROVIDER")
        if prov_env and not await cfg.get("ai.llm.provider"):
            await cfg.set(
                "ai.llm.provider",
                prov_env,
                is_sensitive=False,
                updated_by="system",
                reason="env_migration",
            )
        # OpenAI
        o_base = os.getenv("OPENAI_BASE_URL")
        if o_base:
            cur = await cfg.get("ai.connectors.openai") or {}
            if not cur.get("base_url"):
                await cfg.set(
                    "ai.connectors.openai",
                    {**cur, "base_url": o_base},
                    is_sensitive=False,
                    updated_by="system",
                    reason="env_migration",
                )
        o_model = os.getenv("OPENAI_DEFAULT_MODEL") or os.getenv("AI_LLM_MODEL")
        if o_model:
            cur = await cfg.get("ai.connectors.openai") or {}
            if not cur.get("default_model"):
                await cfg.set(
                    "ai.connectors.openai",
                    {**cur, "default_model": o_model},
                    is_sensitive=False,
                    updated_by="system",
                    reason="env_migration",
                )
        o_key = os.getenv("OPENAI_API_KEY") or os.getenv("AI_OPENAI_API_KEY")
        if o_key and not await cfg.get("secrets.ai.openai.api_key"):
            await cfg.set(
                "secrets.ai.openai.api_key",
                o_key,
                is_sensitive=True,
                updated_by="system",
                reason="env_migration",
            )
        # Anthropic
        a_base = os.getenv("ANTHROPIC_BASE_URL")
        if a_base:
            cur = await cfg.get("ai.connectors.anthropic") or {}
            if not cur.get("base_url"):
                await cfg.set(
                    "ai.connectors.anthropic",
                    {**cur, "base_url": a_base},
                    is_sensitive=False,
                    updated_by="system",
                    reason="env_migration",
                )
        a_model = os.getenv("ANTHROPIC_DEFAULT_MODEL")
        if a_model:
            cur = await cfg.get("ai.connectors.anthropic") or {}
            if not cur.get("default_model"):
                await cfg.set(
                    "ai.connectors.anthropic",
                    {**cur, "default_model": a_model},
                    is_sensitive=False,
                    updated_by="system",
                    reason="env_migration",
                )
        a_key = os.getenv("ANTHROPIC_API_KEY")
        if a_key and not await cfg.get("secrets.ai.anthropic.api_key"):
            await cfg.set(
                "secrets.ai.anthropic.api_key",
                a_key,
                is_sensitive=True,
                updated_by="system",
                reason="env_migration",
            )
        # Tool-calling
        tc = os.getenv("AI_AGENT_TOOL_CALLING")
        if tc and not await cfg.get("ai.agent.tool_calling"):
            await cfg.set(
                "ai.agent.tool_calling",
                tc.lower() in {"1", "true", "yes"},
                is_sensitive=False,
                updated_by="system",
                reason="env_migration",
            )
        # RAG root
        rag_root = os.getenv("RAG_ROOT")
        if rag_root and not await cfg.get("ai.rag.root"):
            await cfg.set(
                "ai.rag.root",
                rag_root,
                is_sensitive=False,
                updated_by="system",
                reason="env_migration",
            )
    except Exception:
        logger.debug("env->config migration failed", exc_info=True)


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
ai_rag_service = None  # Will be initialized on startup
_rag_update_task = None  # Background updater task

# Wire admin API dependencies
configure_admin_api(config_service=get_config_service(), registry=registry)
app.include_router(admin_router)
app.include_router(auth_router)
app.include_router(metrics_router)
app.include_router(notifications_router)
app.include_router(automation_router)
app.include_router(admin_ai_router)


class ManifestModel(BaseModel):
    id: str
    name: str
    version: str
    description: Optional[str] = None
    contracts: List[str]
    traits: List[str]
    dependencies: List[str] = Field(default_factory=list)
    allowed_domains: List[str] = Field(default_factory=list)
    endpoints: Optional[Dict[str, str]] = None
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
        global audit_service
        global messaging_service
        global canonical_service
        global gateway_service
        global notifications_service
        global automation_service
        global ai_rag_service
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
        if "automation_service" not in globals() or automation_service is None:  # type: ignore[name-defined]
            automation_service = AutomationService(
                audit_service, messaging_service, policy_engine
            )

        # Load any built-in canonical JSON Schemas (idempotent)
        try:
            loaded = load_builtin_schemas(schema_registry)
            if loaded:
                logger.info("Loaded %d built-in canonical schemas", loaded)
        except Exception:
            logger.debug("builtin schema load failed", exc_info=True)

        await messaging_service.start()
        await canonical_service.start()
        await gateway_service.start()
        await notifications_service.start()
        await automation_service.start()  # type: ignore[arg-type]
        configure_notifications_api(svc=notifications_service)
        configure_automation_api(svc=automation_service)  # type: ignore[arg-type]
        # Initialize AI RAG service and admin endpoints
        if ai_rag_service is None:
            # Default to Redis for RAG; if not available, RAGService gracefully falls back to memory
            ai_rag_service = RAGService(
                os.getenv("REDIS_URL", "redis://localhost:6379/0")
            )
        configure_ai_api(rag_service=ai_rag_service)  # type: ignore[arg-type]
        await _migrate_env_to_config()

        # Optional: auto-train RAG on startup when enabled (dev/local only)
        try:
            _load_dotenv_if_present()
            if os.getenv("AI_AUTO_TRAIN", "false").lower() in {"1", "true", "yes"}:
                # Train on repo root; respects .ragignore/.gitignore
                await ai_rag_service.train(["."])  # type: ignore[union-attr]
            # Seed gateway allowlist for AI proxy if not present
            try:
                cfg = get_config_service()
                await cfg.set(
                    "gateway.allowlist.ai-core",
                    {
                        "api.openai.com": {
                            "allowed_methods": ["POST", "GET"],
                            "allowed_paths": ["/v1/"],
                        },
                        "api.anthropic.com": {
                            "allowed_methods": ["POST", "GET"],
                            "allowed_paths": ["/v1/"],
                        },
                    },
                    is_sensitive=False,
                    updated_by="system",
                    reason="ai_default_allowlist",
                )
                if gateway_service is not None:
                    await gateway_service.preload_allowlists(["ai-core"])  # type: ignore[arg-type]
            except Exception:
                logger.debug("AI allowlist preload failed", exc_info=True)
        except Exception:
            logger.debug("AI auto-train failed", exc_info=True)

        # Start periodic RAG updater (default every 20 minutes)
        try:
            _start_rag_updater()
        except Exception:
            logger.debug("RAG updater failed to start", exc_info=True)
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
        # Stop RAG updater
        if _rag_update_task is not None:
            try:
                _rag_update_task.cancel()
            except Exception:
                pass
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
    data_traits: Optional[List[str]] = None,
    metadata: Optional[Dict[str, str]] = None,
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


@app.post("/canonical/normalize/message")
async def normalize_message(
    message_data: Dict[str, Any], source_plugin: str, target_plugin: str
):
    """Normalize message data to canonical format."""
    try:
        if canonical_service is None:
            raise HTTPException(status_code=503, detail="Canonical service unavailable")
        canonical_msg = await canonical_service.normalize_message(
            message_data=message_data,
            source_plugin=source_plugin,
            target_plugin=target_plugin,
        )
        return canonical_msg.dict()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/canonical/normalize/event")
async def normalize_event(
    event_data: Dict[str, Any], source_plugin: str, target_plugin: str
):
    """Normalize event data to canonical format."""
    try:
        if canonical_service is None:
            raise HTTPException(status_code=503, detail="Canonical service unavailable")
        canonical_evt = await canonical_service.normalize_event(
            event_data=event_data,
            source_plugin=source_plugin,
            target_plugin=target_plugin,
        )
        return canonical_evt.dict()
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
    plugin_id: Optional[str] = None,
    method: Optional[str] = None,
    url: Optional[str] = None,
    headers: Optional[Dict[str, str]] = None,
    body: Optional[bytes] = None,
    timeout: Optional[int] = None,
    payload: Optional[Dict[str, Any]] = Body(default=None),
):
    """Proxy a request to an external API.

    Accepts parameters either via query string or JSON body. Body keys (if provided):
      { plugin_id, method, url, headers, body, timeout }
    """
    try:
        if gateway_service is None:
            raise HTTPException(status_code=503, detail="Gateway service unavailable")

        # Merge from JSON body when not provided as query params
        src = payload or {}
        plugin_id = plugin_id or src.get("plugin_id")
        method = method or src.get("method")
        url = url or src.get("url")
        headers = headers or src.get("headers")
        timeout = timeout or src.get("timeout") or 30
        body_in = body if body is not None else src.get("body")
        # Support explicit JSON payload
        if body_in is None and isinstance(src.get("json"), (dict, list)):
            try:
                body_in = json.dumps(src.get("json")).encode()
                headers = headers or src.get("headers") or {}
                if isinstance(headers, dict) and not headers.get("Content-Type"):
                    headers["Content-Type"] = "application/json"
            except Exception:
                body_in = None

        # Normalize body to bytes if it is a list[int] or string
        if body_in is None:
            body_bytes: Optional[bytes] = None
        elif isinstance(body_in, (bytes, bytearray)):
            body_bytes = bytes(body_in)
        elif isinstance(body_in, list) and all(isinstance(b, int) for b in body_in):
            body_bytes = bytes(body_in)
        elif isinstance(body_in, str):
            body_bytes = body_in.encode()
        else:
            # Attempt JSON dump then encode
            try:
                body_bytes = json.dumps(body_in).encode()
            except Exception:
                body_bytes = None

        if not (plugin_id and method and url):
            raise HTTPException(
                status_code=422, detail="plugin_id, method, url are required"
            )

        response = await gateway_service.proxy_request(
            plugin_id=plugin_id,
            method=method,
            url=url,
            headers=headers,
            body=body_bytes,
            timeout=int(timeout),
        )
        return response.dict()
    except HTTPException:
        raise
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
    plugin_id: Optional[str] = None,
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
    plugin_id: Optional[str] = None,
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
def _is_safe_plugin_host(host: str) -> bool:
    """Allow only simple service-like hostnames to avoid SSRF.

    Accepts alphanumerics, dash and underscore. Rejects dots, schemes, ports.
    """
    import re

    if not isinstance(host, str) or not host:
        return False
    if "://" in host or "/" in host or ":" in host:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9_-]+", host))


def _is_safe_endpoint_path(path: str) -> bool:
    """Endpoint path must be an absolute path and not contain scheme or host."""
    if not isinstance(path, str) or not path:
        return False
    if not path.startswith("/"):
        return False
    if "://" in path:
        return False
    return True


class OperatorRequestModel(BaseModel):
    caller_plugin: str
    payload: Optional[Dict[str, Any]] = None
    timeout: Optional[int] = 30


@app.post("/gateway/{target_plugin}/{operation}")
@rate_limit(
    limit=240,
    window_seconds=60,
    key_fn=lambda *a, **k: f"rpc:{getattr(k.get('req', None), 'caller_plugin', 'unknown')}",
)
async def operator_invoke(target_plugin: str, operation: str, req: Dict[str, Any]):
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
                resource_id=f"{(req or {}).get('caller_plugin','unknown')}->{target_plugin}:{operation}",
                action="operator_call",
                traits=[],
                context={"operation": operation},
                policy_context=PolicyContext.PLUGIN_INTERACTION,
                source_plugin=(req or {}).get("caller_plugin", "unknown"),
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

        # Enforce operator allowlist from config
        try:
            from .config.service import get_config_service

            caller = (req or {}).get("caller_plugin", "unknown")
            key = f"operator.allow.{caller}->{target_plugin}"
            allowed = await get_config_service().get(key) or []
            if isinstance(allowed, list):
                opset = {str(op) for op in allowed}
                if operation not in opset:
                    raise HTTPException(
                        status_code=403,
                        detail="Operator call not allowed for this operation",
                    )
        except HTTPException:
            raise
        except Exception:
            logger.debug("operator allowlist lookup failed", exc_info=True)

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

        # Enforce safe host and path
        if not _is_safe_plugin_host(str(plugin_host)):
            raise HTTPException(status_code=400, detail="Unsafe plugin host")
        if not _is_safe_endpoint_path(str(endpoint_path)):
            raise HTTPException(status_code=400, detail="Unsafe endpoint path")
        target_url = f"http://{plugin_host}:{plugin_port}{endpoint_path}"

        # Forward request
        import httpx

        timeout = int((req or {}).get("timeout") or 30)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.post(
                target_url,
                json=(req or {}).get("payload") or {},
                headers={
                    "X-Caller-Plugin": caller,
                    "X-Trace-Id": os.getenv("TRACE_ID", "system"),
                    "Authorization": f"Bearer {registry.plugins.get(caller, {}).get('token', '')}",
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
                description=f"{caller} -> {target_plugin}:{operation}",
                resource_type="operator",
                resource_id=target_url,
                plugin_id=caller,
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
    health: Optional[str] = "healthy"


@app.post("/plugins/{plugin_id}/heartbeat")
async def plugin_heartbeat(plugin_id: str, status: HeartbeatModel):
    ok = await registry.heartbeat(plugin_id, status.model_dump())
    if not ok:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return {"status": "ok"}


# Minimal MCP server health endpoints (SSE/HTTP)
@app.get("/mcp/sse/health")
async def mcp_sse_health():
    return JSONResponse({"ok": True, "transport": "sse"})


@app.get("/mcp/http/health")
async def mcp_http_health():
    return JSONResponse({"ok": True, "transport": "http"})


@app.get("/mcp/sse")
async def mcp_sse():
    async def eventgen():
        yield "event: ping\n\n"
        yield 'data: {"ok": true}\n\n'

    return StreamingResponse(eventgen(), media_type="text/event-stream")


@app.get("/mcp/http/tools")
async def mcp_http_tools():
    return JSONResponse(
        {
            "tools": [
                {
                    "id": "rag.query",
                    "name": "rag_query",
                    "description": "Query internal RAG index for relevant docs.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"q": {"type": "string"}},
                        "required": ["q"],
                    },
                    "endpoint": "/mcp/http/tools/rag/query",
                }
            ]
        }
    )


@app.post("/mcp/http/tools/rag/query")
async def mcp_rag_query(
    payload: Dict[str, Any], user: Dict = Depends(get_current_user)
):
    # Enforce viewer/admin traits
    _ = await require_auth(["admin", "viewer"])(lambda u: u)(user)  # type: ignore[misc]
    global ai_rag_service
    if ai_rag_service is None:
        ai_rag_service = RAGService(os.getenv("REDIS_URL"))
    q = (payload.get("q") or payload.get("query") or "").strip()
    if not q:
        raise HTTPException(status_code=400, detail="query required")
    res = await ai_rag_service.query(q, user_traits=(user.get("traits") or []))  # type: ignore[union-attr]
    return {"items": res}


class PluginConfigModel(BaseModel):
    enabled: Optional[bool] = True
    settings: Optional[Dict[str, Any]] = {}


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
    enabled: Optional[bool] = True


@app.post("/auth/dev-login")
@rate_limit(limit=10, window_seconds=60, key="dev_login")
async def dev_login(_: Optional[Dict[str, Any]] = None):
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


def _load_dotenv_if_present() -> None:
    """Lightweight .env loader for local/dev without extra deps."""
    env_path = os.path.join(os.getcwd(), ".env")
    if not os.path.exists(env_path):
        return
    try:
        with open(env_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                if "=" not in s:
                    continue
                k, v = s.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        logger.debug(".env load failed", exc_info=True)


def _start_rag_updater() -> None:
    """Start background task that re-trains RAG every N minutes."""
    global _rag_update_task
    if _rag_update_task is not None:
        return

    interval_min = int(os.getenv("RAG_UPDATE_INTERVAL_MINUTES", "20") or 20)

    async def _runner():
        # Run immediately, then on interval
        try:
            if ai_rag_service is not None:
                await ai_rag_service.train(["."])  # type: ignore[union-attr]
        except Exception:
            logger.debug("initial RAG update failed", exc_info=True)
        while True:
            try:
                await asyncio.sleep(max(60, interval_min * 60))
                if ai_rag_service is not None:
                    await ai_rag_service.train(["."])  # type: ignore[union-attr]
            except asyncio.CancelledError:
                break
            except Exception:
                logger.debug("periodic RAG update failed", exc_info=True)

    _rag_update_task = asyncio.create_task(_runner())


# Canonical Schemas stubs to satisfy Admin UI until registry is implemented
class SchemaUpsertModel(BaseModel):
    name: str
    major: int
    minor: Optional[int] = 0
    patch: Optional[int] = 0
    schema_data: Optional[Dict[str, Any]] = None


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
    if payload.schema_data is not None:
        if not isinstance(payload.schema_data, dict):
            raise HTTPException(status_code=400, detail="schema_data must be an object")
        has_type = isinstance(payload.schema_data.get("type"), str)
        has_dollar = "$schema" in payload.schema_data
        if not (has_type or has_dollar):
            raise HTTPException(
                status_code=400, detail="schema_data must include 'type' or '$schema'"
            )
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
    minor: Optional[int] = 0
    patch: Optional[int] = 0


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


class SchemaValidationRequest(BaseModel):
    payload: Dict[str, Any]
    major: Optional[int] = None
    version: Optional[str] = None  # x.y.z


@app.post("/schemas/{name}/validate")
async def validate_payload_against_schema(
    name: str, req: SchemaValidationRequest, _: Dict = Depends(require_auth(["admin"]))
):
    """Validate a JSON payload against a registered canonical JSON Schema.

    Selects the schema by explicit version (x.y.z) if provided, otherwise uses the
    active schema for the given major version.
    """
    try:
        # Resolve version
        ver_tuple = None
        if req.version:
            try:
                parts = [int(p) for p in req.version.split(".")]
                if len(parts) != 3:
                    raise ValueError("version must be x.y.z")
                ver_tuple = (parts[0], parts[1], parts[2])
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid version string")
        else:
            if req.major is None:
                raise HTTPException(status_code=400, detail="major or version required")
            active = schema_registry.get_active(name, int(req.major))
            if not active:
                raise HTTPException(
                    status_code=404, detail="Active schema not found for major"
                )
            ver_tuple = active.version

        # Locate schema data
        schema_obj = schema_registry._schemas.get(name, {}).get(ver_tuple)  # type: ignore[attr-defined]
        if not schema_obj:
            raise HTTPException(status_code=404, detail="Schema version not found")
        schema = schema_obj.schema_data or {}

        # Validate payload
        from jsonschema import validate as js_validate
        from jsonschema.exceptions import ValidationError

        try:
            js_validate(instance=req.payload, schema=schema)
        except ValidationError as ve:  # noqa: F841
            return {
                "ok": False,
                "error": str(ve.message),
                "path": list(ve.path),
                "schema_path": list(ve.schema_path),
                "version": list(ver_tuple),
            }
        return {"ok": True, "version": list(ver_tuple)}
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        logger.exception("Schema validation failed: %s", e)
        raise HTTPException(status_code=500, detail="Validation error")
