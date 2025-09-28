"""
Pushover Notifier Plugin

Simple notification plugin that sends messages via the Pushover API.
Integrates with Vivified core:
- Registers with manifest
- Exposes /health and /send endpoints
- Publishes NotificationSent events

External requests should go through core gateway proxy; plugin attempts proxy first and
falls back to dry-run if domain is not allowlisted.
"""

from __future__ import annotations

import os
import logging
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import uuid4

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel


logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

app = FastAPI(title="Pushover Notifier Plugin")

CORE_URL = os.getenv("CORE_URL", "http://vivified-core:8000")
PLUGIN_ID = "pushover-notifier"
PLUGIN_TOKEN: Optional[str] = None


class SendRequest(BaseModel):
    message: str
    title: Optional[str] = None
    notification_id: Optional[str] = None
    # Optional override; ignored unless ALLOW_USER_OVERRIDE=true
    user_key: Optional[str] = None


def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in {"1", "true", "yes", "on"}


MANIFEST: Dict[str, Any] = {
    "id": PLUGIN_ID,
    "name": "Pushover Notifier Plugin",
    "version": "1.0.0",
    "description": "Send push notifications using Pushover",
    "contracts": ["CommunicationPlugin"],
    "traits": [
        "communication_plugin",
        "handles_notifications",
        "requires_config",
        "external_service",
    ],
    "dependencies": [],
    "allowed_domains": ["api.pushover.net"],
    "endpoints": {"health": "/health", "send": "/send"},
    "security": {
        "authentication_required": True,
        "data_classification": ["internal"],
        "allowed_domains": ["api.pushover.net"],
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
async def send(req: SendRequest) -> Dict[str, Any]:
    try:
        token = os.getenv("PUSHOVER_API_TOKEN")
        default_user = os.getenv("PUSHOVER_USER_KEY")
        allow_override = _env_bool("ALLOW_USER_OVERRIDE", False)

        if not token or not default_user:
            # Respect requires_config: respond but mark as dry-run
            logger.warning(
                "missing_config: PUSHOVER_API_TOKEN/PUSHOVER_USER_KEY not set"
            )
            return {
                "status": "queued",
                "sent": False,
                "dry_run": True,
                "reason": "Missing config",
            }

        user_key = req.user_key if (allow_override and req.user_key) else default_user
        payload = {
            "token": token,
            "user": user_key,
            "message": req.message,
        }
        if req.title:
            payload["title"] = req.title

        notification_id = req.notification_id or str(uuid4())

        # Prefer gateway proxy; fallback to dry-run if blocked
        proxied_ok = False
        resp_status: Optional[int] = None
        resp_body: Optional[str] = None

        try:
            async with httpx.AsyncClient() as client:
                proxy_res = await client.post(
                    f"{CORE_URL}/gateway/proxy",
                    json={
                        "plugin_id": PLUGIN_ID,
                        "method": "POST",
                        "url": "https://api.pushover.net/1/messages.json",
                        "headers": {
                            "Content-Type": "application/x-www-form-urlencoded"
                        },
                        "body": httpx.QueryParams(payload).encode(),
                        "timeout": 10,
                    },
                    headers=(
                        {"Authorization": f"Bearer {PLUGIN_TOKEN}"}
                        if PLUGIN_TOKEN
                        else {}
                    ),
                    timeout=15.0,
                )
                if proxy_res.status_code == 200:
                    data = proxy_res.json()
                    proxied_ok = data.get("success", False)
                    resp_status = data.get("status_code")
                    # Body is base64 in some impls; here it's raw bytes -> captured as string via json
                    resp_body = str(data.get("body"))[:2048]
                else:
                    resp_status = proxy_res.status_code
                    resp_body = proxy_res.text
        except Exception as e:  # noqa: BLE001
            logger.warning("gateway_proxy_failed: %s", e)

        # Publish NotificationSent event
        status = "sent" if proxied_ok else "queued"
        event_payload = {
            "event_type": "NotificationSent",
            "notification_id": notification_id,
            "plugin": PLUGIN_ID,
            "timestamp": datetime.utcnow().isoformat(),
            "status": status,
            "details": {
                "pushover_status": resp_status,
                "response": (resp_body or "")[:512],
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
            "status": status,
            "notification_id": notification_id,
            "sent": proxied_ok,
            "dry_run": not proxied_ok,
        }

    except HTTPException:
        raise
    except Exception as e:  # noqa: BLE001
        logger.exception("pushover_send_error: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


@app.on_event("shutdown")
async def shutdown() -> None:
    logger.info("Pushover Notifier Plugin shutting down")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8012)
