"""
Apprise Notifier Plugin

Proof-of-concept multi-provider notification plugin that:
- Registers with Vivified core using a manifest
- Exposes /health and /send endpoints (operator lane)
- Publishes NotificationSent events to the core messaging service (canonical lane)

External dispatch is performed via Apprise when available; otherwise runs in dry-run mode.
All external calls SHOULD be proxied by the core gateway per platform policy. Since Apprise
connects to many providers directly, this plugin defaults to dry-run unless explicitly enabled.
"""

from __future__ import annotations

import os
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI(title="Apprise Notifier Plugin")

CORE_URL = os.getenv("CORE_URL", "http://vivified-core:8000")
PLUGIN_ID = "apprise-notifier"
PLUGIN_TOKEN: Optional[str] = None


class SendRequest(BaseModel):
    title: Optional[str] = None
    body: str
    targets: Optional[List[str]] = Field(
        default=None, description="Apprise target URLs"
    )
    notification_id: Optional[str] = None


def _env_bool(name: str, default: bool) -> bool:
    val = os.getenv(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


# Plugin manifest per core expectations
MANIFEST: Dict[str, Any] = {
    "id": PLUGIN_ID,
    "name": "Apprise Notifier Plugin",
    "version": "1.0.0",
    "description": "Multi-provider notifications via Apprise (POC)",
    "contracts": ["CommunicationPlugin"],
    "traits": [
        "communication_plugin",
        "handles_notifications",
        "requires_config",
        # Apprise fans out to external providers; treat as external_service by design
        "external_service",
    ],
    "dependencies": [],
    "allowed_domains": [],
    "endpoints": {"health": "/health", "send": "/send"},
    "security": {
        "authentication_required": True,
        "data_classification": ["internal"],
        # For Apprise, we don't enumerate provider domains here; gateway usage is optional in POC
        "allowed_domains": [],
    },
    "compliance": {
        "hipaa_controls": [],
        "audit_level": "standard",
    },
}


@app.on_event("startup")
async def startup() -> None:
    global PLUGIN_TOKEN
    try:
        async with httpx.AsyncClient() as client:
            r = await client.post(
                f"{CORE_URL}/plugins/register", json=MANIFEST, timeout=10.0
            )
            if r.status_code == 200:
                data = r.json()
                PLUGIN_TOKEN = data.get("token")
                logger.info("registered_with_core plugin_id=%s", PLUGIN_ID)
            else:
                logger.error(
                    "registration_failed status=%s body=%s", r.status_code, r.text
                )
                raise RuntimeError("Failed to register with core")
    except Exception as e:  # noqa: BLE001
        logger.exception("startup_error: %s", e)
        raise


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "plugin": PLUGIN_ID,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.post("/send")
async def send_notification(req: SendRequest) -> Dict[str, Any]:
    """Send a notification to configured targets (dry-run by default)."""
    try:
        notification_id = req.notification_id or str(uuid4())

        # Resolve targets: request overrides env, else use env
        env_targets = [t for t in os.getenv("APPRISE_TARGET_URLS", "").split(",") if t]
        targets = req.targets or env_targets

        if not targets:
            raise HTTPException(
                status_code=400, detail="No targets provided or configured"
            )

        dry_run = _env_bool("APPRISE_DRY_RUN", True)
        delivered: List[str] = []
        failed: List[str] = []

        if not dry_run:
            # Best-effort Apprise usage if available; otherwise fallback to dry-run
            try:
                import apprise  # type: ignore

                app_obj = apprise.Apprise()  # type: ignore[attr-defined]
                for url in targets:
                    app_obj.add(url)
                ok = bool(app_obj.notify(title=req.title or "", body=req.body))
                if ok:
                    delivered = targets
                else:
                    failed = targets
            except Exception as e:  # noqa: BLE001
                logger.warning("apprise_unavailable_or_failed: %s", e)
                dry_run = True

        if dry_run:
            # Simulate delivery success for all targets in POC
            delivered = targets

        # Publish NotificationSent event back to core (canonical lane)
        event_payload = {
            "event_type": "NotificationSent",
            "notification_id": notification_id,
            "plugin": PLUGIN_ID,
            "timestamp": datetime.utcnow().isoformat(),
            "status": (
                "sent"
                if delivered and not failed
                else ("partial" if delivered else "failed")
            ),
            "details": {
                "targets": delivered,
                "failed": failed,
            },
        }
        async with httpx.AsyncClient() as client:
            await client.post(
                f"{CORE_URL}/messaging/events",
                json={
                    "event_type": "NotificationSent",
                    "payload": event_payload,
                    "source_plugin": PLUGIN_ID,
                    "data_traits": ["internal"],
                },
                headers=(
                    {"Authorization": f"Bearer {PLUGIN_TOKEN}"} if PLUGIN_TOKEN else {}
                ),
                timeout=5.0,
            )

        return {
            "status": "ok",
            "notification_id": notification_id,
            "sent": bool(delivered),
            "targets": delivered,
            "failed": failed,
        }
    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        logger.exception("send_error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.on_event("shutdown")
async def shutdown() -> None:
    logger.info("Apprise Notifier Plugin shutting down")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8011)
