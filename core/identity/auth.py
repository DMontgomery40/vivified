"""
Identity and authentication helpers for Vivified Core.

This module provides a minimal, secure-by-default JWT-based auth manager
and FastAPI dependencies to protect endpoints during Phase 2. It also
exposes lightweight decorators used elsewhere in the codebase.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Callable, Awaitable
import asyncio
import time
import os
import functools
import logging

try:
    import jwt as _pyjwt  # type: ignore
    from typing import Any as _Any  # local alias to avoid polluting module scope

    jwt: _Any = _pyjwt  # type: ignore[assignment]
except Exception:  # pragma: no cover - lightweight fallback for test envs
    import base64
    import json

    class _FallbackJWT:
        @staticmethod
        def encode(payload, _secret, algorithm="HS256"):
            return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode()

        @staticmethod
        def decode(token, _secret, algorithms=None):  # noqa: ARG002
            data = base64.urlsafe_b64decode(token.encode() + b"==").decode()
            return json.loads(data)

    jwt = _FallbackJWT()  # type: ignore[assignment]
from fastapi import Depends, Header, HTTPException

logger = logging.getLogger(__name__)


class AuthManager:
    """JWT manager for users and plugins."""

    def __init__(self, jwt_secret: str):
        if not jwt_secret or jwt_secret == "change-this-secret":
            logger.warning(
                "Using default/weak JWT secret. Set JWT_SECRET in production."
            )
        self.jwt_secret = jwt_secret

    def generate_user_token(
        self, user_id: str, traits: List[str], expires_minutes: int = 15
    ) -> str:
        now = datetime.now(tz=timezone.utc)
        payload = {
            "sub": user_id,
            "type": "user",
            "traits": traits or [],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
            "jti": os.urandom(8).hex(),
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    def generate_plugin_token(self, plugin_id: str, traits: List[str]) -> str:
        now = datetime.now(tz=timezone.utc)
        payload = {
            "plugin_id": plugin_id,
            "type": "plugin",
            "traits": traits or [],
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(days=30)).timestamp()),
            "jti": os.urandom(8).hex(),
        }
        return jwt.encode(payload, self.jwt_secret, algorithm="HS256")

    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        try:
            return jwt.decode(token, self.jwt_secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            logger.info("JWT expired")
            return None
        except jwt.InvalidTokenError as e:  # noqa: PERF203
            logger.info("Invalid JWT: %s", e)
            return None


# Global accessors (simple service locator for app wiring)
_AUTH_MANAGER: Optional[AuthManager] = None


def get_auth_manager() -> AuthManager:
    global _AUTH_MANAGER
    if _AUTH_MANAGER is None:
        _AUTH_MANAGER = AuthManager(os.getenv("JWT_SECRET", "change-this-secret"))
    return _AUTH_MANAGER


async def get_current_user(
    authorization: Optional[str] = Header(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
) -> Dict[str, Any]:
    """FastAPI dependency that extracts and verifies the current user from JWT.

    Returns a dict: {"id": str, "traits": List[str], "claims": Dict}
    """
    # DEV bootstrap: accept X-API-Key or Bearer with special value
    if DEV_MODE:
        bootstrap = "bootstrap_admin_only"
        if (x_api_key and x_api_key == bootstrap) or (
            authorization
            and authorization.lower().startswith("bearer ")
            and authorization.split(" ", 1)[1] == bootstrap
        ):
            traits = [
                "admin",
                "config_manager",
                "plugin_manager",
                "audit_viewer",
                "viewer",
            ]
            return {
                "id": "dev-admin",
                "traits": traits,
                "claims": {"sub": "dev-admin", "type": "user", "traits": traits},
            }

    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(
            status_code=401, detail="Missing or invalid Authorization header"
        )

    token = authorization.split(" ", 1)[1]
    claims = get_auth_manager().verify_token(token)
    if not claims or claims.get("type") != "user":
        raise HTTPException(status_code=401, detail="Invalid token")

    return {
        "id": str(claims.get("sub")),
        "traits": claims.get("traits", []),
        "claims": claims,
    }


def require_auth(
    required_traits: Optional[List[str]] = None,
) -> Callable[[Dict[str, Any]], Awaitable[None]]:
    """Returns a dependency that enforces presence of required traits.

    Usage in FastAPI routes:
      @router.get(..., dependencies=[Depends(require_auth(["admin"]))])
    """

    async def _dep(user: Dict[str, Any] = Depends(get_current_user)) -> None:
        if not required_traits:
            return
        utraits = set(user.get("traits", []))
        # Admin always allowed
        if "admin" in utraits:
            return
        if not any(trait in utraits for trait in required_traits):
            raise HTTPException(
                status_code=403, detail="Forbidden: insufficient traits"
            )

    return _dep


class _RateLimiterBackend:
    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:  # pragma: no cover - interface
        raise NotImplementedError


class _MemoryRateLimiter(_RateLimiterBackend):
    def __init__(self) -> None:
        self._lock = asyncio.Lock()
        self._buckets: Dict[str, Dict[str, float | int]] = {}

    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        now = time.monotonic()
        async with self._lock:
            bucket = self._buckets.get(key)
            if not bucket:
                self._buckets[key] = {"count": 1, "reset": now + window_seconds}
                return True

            reset = float(bucket.get("reset", now))
            count = int(bucket.get("count", 0))
            if now > reset:
                # reset window
                bucket["count"] = 1
                bucket["reset"] = now + window_seconds
                return True

            if count < limit:
                bucket["count"] = count + 1
                return True

            return False


class _RedisRateLimiter(_RateLimiterBackend):
    def __init__(self, url: str) -> None:
        self._url = url
        self._client = None

    async def _client_lazy(self):
        if self._client is None:
            import redis.asyncio as redis  # type: ignore

            self._client = redis.from_url(self._url)
        return self._client

    async def allow(self, key: str, limit: int, window_seconds: int) -> bool:
        client = await self._client_lazy()
        # Use atomic INCR with expiry as a sliding window approximation
        pipe = client.pipeline()
        pipe.incr(key)
        pipe.expire(key, window_seconds)
        try:
            count, _ = await pipe.execute()
        except Exception:  # noqa: BLE001
            # Fallback soft-fail: allow
            return True
        return int(count) <= limit


_RATE_BACKEND: Optional[_RateLimiterBackend] = None


def _get_rate_backend() -> _RateLimiterBackend:
    global _RATE_BACKEND
    if _RATE_BACKEND is not None:
        return _RATE_BACKEND
    backend = os.getenv("RATE_LIMIT_BACKEND", "memory").lower()
    if backend == "redis" and os.getenv("REDIS_URL"):
        _RATE_BACKEND = _RedisRateLimiter(os.getenv("REDIS_URL", "redis://localhost:6379/0"))
    else:
        _RATE_BACKEND = _MemoryRateLimiter()
    return _RATE_BACKEND


def rate_limit(
    limit: int = 60,
    window_seconds: int = 60,
    key: Optional[str] = None,
    key_fn: Optional[Callable[[tuple, dict], str]] = None,
) -> Callable:
    """Rate limit decorator using memory or Redis backend.

    - limit: max requests per window
    - window_seconds: window length
    - key: static key (e.g., "dev_login")
    - key_fn: function receiving (args, kwargs) returning a dynamic key
    """

    def _decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def _wrapper(*args, **kwargs):
            k = key or (key_fn(*args, **kwargs) if key_fn else func.__name__)
            allowed = await _get_rate_backend().allow(k, limit, window_seconds)
            if not allowed:
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            return await func(*args, **kwargs)

        return _wrapper

    return _decorator


def audit_phi_access(func: Callable) -> Callable:
    """Decorator hook used by storage service to mark PHI access.

    This implementation just forwards the call; PHI auditing happens
    inside the storage service via AuditService.log_event.
    """

    @functools.wraps(func)
    async def _wrapper(*args, **kwargs):
        return await func(*args, **kwargs)

    return _wrapper


# Developer-only helper route support
DEV_MODE = os.getenv("DEV_MODE", "false").lower() in {"1", "true", "yes"}


def dev_issue_admin_token() -> str:
    """Issue a short-lived admin token for local/dev usage."""
    if not DEV_MODE:
        raise PermissionError("Dev login disabled")
    traits = ["admin", "config_manager", "plugin_manager", "audit_viewer", "viewer"]
    return get_auth_manager().generate_user_token(
        "dev-admin", traits, expires_minutes=30
    )
