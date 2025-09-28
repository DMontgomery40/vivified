from __future__ import annotations

from typing import Any, AsyncIterator, Callable, Dict, Optional
import os
import httpx


class VivifiedClient:
    def __init__(self, base_url: Optional[str] = None, token: Optional[str] = None):
        self.base_url = base_url or os.getenv("VIVIFIED_BASE_URL", "http://localhost:8000")
        self.token = token or os.getenv("VIVIFIED_TOKEN")
        self._client = httpx.AsyncClient(base_url=self.base_url, headers=self._headers())

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def aclose(self) -> None:
        await self._client.aclose()

    # publish_event
    async def publish_event(self, event_type: str, payload: Dict[str, Any], source_plugin: str, data_traits: Optional[list[str]] = None) -> Dict[str, Any]:
        body = {
            "event_type": event_type,
            "payload": payload,
            "source_plugin": source_plugin,
            "data_traits": data_traits or [],
        }
        r = await self._client.post("/messaging/events", json=body)
        r.raise_for_status()
        return r.json()

    # subscribe (server-push placeholder; SDK exposes callback registration but relies on API later)
    async def subscribe(self, event_type: str, handler: Callable[[Dict[str, Any]], Any]) -> None:
        # Placeholder: No server push implemented; method kept for parity.
        return None

    # call_plugin (operator lane via gateway)
    async def call_plugin(self, target_plugin: str, operation: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        path = f"/gateway/{target_plugin}/{operation}"
        r = await self._client.post(path, json=payload)
        r.raise_for_status()
        return r.json()

    # call_external (proxy lane)
    async def call_external(self, plugin_id: str, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None, body: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        req = {"plugin_id": plugin_id, "url": url, "method": method, "headers": headers or {}, "body": body}
        r = await self._client.post("/gateway/proxy", json=req)
        r.raise_for_status()
        return r.json()

    # get_config
    async def get_config(self) -> Dict[str, Any]:
        r = await self._client.get("/admin/config")
        r.raise_for_status()
        return r.json()

    # set_config
    async def set_config(self, key: str, value: Any, is_sensitive: bool = False, reason: Optional[str] = None) -> Dict[str, Any]:
        body = {"key": key, "value": value, "is_sensitive": is_sensitive, "reason": reason}
        r = await self._client.put("/admin/config", json=body)
        r.raise_for_status()
        return r.json()

