"""
Plugin message delivery adapters.

Provides HTTP delivery to target plugins using the plugin registry and
manifest-declared endpoints. Keeps logic small and dependency-light.
"""

from __future__ import annotations

import logging
from typing import Optional, Dict, Any

import os

from .models import Message

logger = logging.getLogger(__name__)


def _is_safe_plugin_host(host: str) -> bool:
    """Allow only simple service-like hostnames to avoid SSRF.

    Accepts alphanumerics, dash and underscore. Rejects dots, schemes, ports.
    Matches validation in core.main.
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


class PluginDispatcher:
    """Resolves plugin endpoints and delivers messages via HTTP."""

    def __init__(self, registry: Any):
        self._registry = registry

    def _resolve_inbox_endpoint(self, target_plugin: str) -> Optional[str]:
        try:
            target = self._registry.plugins.get(target_plugin)  # type: ignore[attr-defined]
            if not target or not isinstance(target, dict):
                return None
            manifest = target.get("manifest") or {}
            endpoints = manifest.get("endpoints") or {}
            # Preferred well-known keys
            for key in ("message.receive", "messages.receive", "inbox", "message"):
                if isinstance(endpoints, dict) and isinstance(endpoints.get(key), str):
                    return str(endpoints[key])
            # Fallback conventional path if not declared
            return "/inbox"
        except Exception:
            return None

    def _resolve_host_port(self, target_plugin: str) -> Optional[tuple[str, int]]:
        try:
            target = self._registry.plugins.get(target_plugin)  # type: ignore[attr-defined]
            if not target or not isinstance(target, dict):
                return None
            manifest = target.get("manifest") or {}
            host = manifest.get("host") or target_plugin
            port = int(manifest.get("port") or 8080)
            if not _is_safe_plugin_host(str(host)):
                return None
            return str(host), port
        except Exception:
            return None

    async def deliver_message(self, message: Message, source_plugin: str) -> bool:
        """POST a canonical message to the target plugin inbox endpoint.

        Headers include caller and an optional token for the caller plugin if
        present in the registry.
        """
        if not message.target_plugin:
            return False
        target_plugin = message.target_plugin
        endpoint = self._resolve_inbox_endpoint(target_plugin)
        hp = self._resolve_host_port(target_plugin)
        if not endpoint or not _is_safe_endpoint_path(endpoint) or not hp:
            logger.warning("message delivery resolve failed: target=%s", target_plugin)
            return False

        host, port = hp
        url = f"http://{host}:{port}{endpoint}"

        try:
            import httpx

            # Caller token (if any)
            caller_info: Dict[str, Any] = (
                self._registry.plugins.get(source_plugin, {})  # type: ignore[attr-defined]
                if source_plugin
                else {}
            )
            headers = {
                "X-Caller-Plugin": source_plugin,
                "X-Trace-Id": os.getenv("TRACE_ID", "system"),
            }
            tok = caller_info.get("token")
            if isinstance(tok, str) and tok:
                headers["Authorization"] = f"Bearer {tok}"

            payload = message.model_dump(mode="json")

            timeout = int(os.getenv("MESSAGE_DELIVERY_TIMEOUT", "30") or 30)
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.post(url, json=payload, headers=headers)
                if resp.status_code >= 400:
                    logger.info(
                        "message delivery failed: %s -> %s status=%s",
                        source_plugin,
                        target_plugin,
                        resp.status_code,
                    )
                    return False
            return True
        except Exception as e:  # noqa: BLE001
            logger.debug("message delivery exception: %s", e, exc_info=True)
            return False

    def list_targets(self) -> list[str]:
        try:
            return list(self._registry.plugins.keys())  # type: ignore[attr-defined]
        except Exception:
            return []

