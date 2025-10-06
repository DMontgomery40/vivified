from __future__ import annotations

import os
import secrets
from typing import Any, Dict, Optional

import httpx


class IntegrationClientError(Exception):
    """Mapped error from integrations sidecar to core taxonomy."""

    def __init__(self, public_code: str, status_code: int, message: str = ""):
        super().__init__(message or public_code)
        self.public_code = public_code
        self.status_code = status_code


def _map_error(err: Dict[str, Any], status: int) -> IntegrationClientError:
    code = str((err.get("error", {}) or {}).get("code") or "")
    msg = str((err.get("error", {}) or {}).get("message") or "")

    c = code.lower()
    if status >= 500 or "service.unavailable" in c or "mongo.unavailable" in c:
        return IntegrationClientError(
            "integration.unavailable", 503, msg or "Service unavailable"
        )
    if c.startswith("oauth."):
        return IntegrationClientError(
            "integration.oauth_failed", 400, msg or "OAuth failed"
        )
    if "revoke_failed" in c or "credential.delete_failed" in c:
        return IntegrationClientError(
            "integration.revoke_failed", 502, msg or "Revoke failed"
        )
    return IntegrationClientError("integration.bad_request", 400, msg or "Bad request")


class ExternalPluginClient:
    """HTTP client for the integrations sidecar (Node service).

    All methods pass an internal token header and propagate a correlation ID.
    """

    def __init__(
        self,
        host: str,
        provider: str,
        internal_token_env: str = "INTEGRATIONS_INTERNAL_TOKEN",
    ):
        self.host = host.rstrip("/")
        self.provider = provider
        self._token = os.getenv(internal_token_env, "")

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self._token:
            headers["X-Internal-Auth"] = self._token
            headers["X-Internal-Token"] = self._token  # legacy compatibility
        try:
            headers["X-Request-Id"] = secrets.token_hex(8)
        except Exception:
            headers["X-Request-Id"] = "vivified"
        return headers

    async def get_oauth_url(self, user_id: str, state: str) -> Dict[str, Any]:
        url = f"{self.host}/oauth_url/{self.provider}"
        params = {"userId": user_id, "state": state}
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(url, params=params, headers=self._headers())
        if r.status_code == 200:
            return r.json()
        try:
            data = r.json()
        except Exception:
            data = {"error": {"code": "service.unavailable", "message": r.text}}
        raise _map_error(data, r.status_code)

    async def exchange_code(
        self, user_id: str, code: str, state: str
    ) -> Dict[str, Any]:
        url = f"{self.host}/oauth_cb/{self.provider}"
        payload = {"userId": user_id, "code": code, "state": state}
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.post(url, json=payload, headers=self._headers())
        if r.status_code == 200:
            return r.json()
        try:
            data = r.json()
        except Exception:
            data = {"error": {"code": "service.unavailable", "message": r.text}}
        raise _map_error(data, r.status_code)

    async def status(self, user_id: str) -> Dict[str, Any]:
        url = f"{self.host}/status/{self.provider}"
        params = {"userId": user_id}
        async with httpx.AsyncClient(timeout=5.0) as client:
            r = await client.get(url, params=params, headers=self._headers())
        if r.status_code == 200:
            return r.json()
        try:
            data = r.json()
        except Exception:
            data = {"error": {"code": "service.unavailable", "message": r.text}}
        raise _map_error(data, r.status_code)

    async def revoke(self, user_id: str) -> Dict[str, Any]:
        url = f"{self.host}/revoke/{self.provider}"
        payload = {"userId": user_id}
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.post(url, json=payload, headers=self._headers())
        if r.status_code == 200:
            return r.json()
        try:
            data = r.json()
        except Exception:
            data = {"error": {"code": "service.unavailable", "message": r.text}}
        raise _map_error(data, r.status_code)
