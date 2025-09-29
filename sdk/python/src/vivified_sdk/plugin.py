"""
Vivified Python Plugin SDK (minimal scaffolding)

This lightweight SDK enables developers to write plugins against the Vivified
platform while keeping runtime dependencies minimal. It provides:

- Base class: VivifiedPlugin
- Decorators: @event_handler, @rpc_endpoint, @require_traits, @audit_log, @track_metrics
- Types: SecurityContext, CanonicalModels (stubs)

The decorators are no-ops at definition time and allow the core to introspect
metadata if needed. This keeps unit tests fast and dev ergonomics simple.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict, List, Optional
import asyncio
import functools


# ----------------------- Types & Stubs -----------------------


@dataclass
class SecurityContext:
    user_id: str
    purpose: str = "treatment"
    roles: List[str] = field(default_factory=list)
    traits: List[str] = field(default_factory=list)


class CanonicalModels:
    """Placeholder for canonical model helpers (future expansion)."""

    @staticmethod
    def to_user(data: Dict[str, Any]) -> Dict[str, Any]:
        return data

    @staticmethod
    def from_user(data: Dict[str, Any]) -> Dict[str, Any]:
        return data


# ----------------------- Decorators -----------------------


def _attach_meta(fn: Callable[..., Any], key: str, value: Any) -> None:
    meta = getattr(fn, "__vivified_meta__", {})
    meta[key] = value
    setattr(fn, "__vivified_meta__", meta)


def event_handler(event_type: str) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Mark an async function as a handler for a specific event type."""

    def wrapper(fn: Callable[..., Awaitable[Any]]):
        _attach_meta(fn, "event_handler", {"event_type": event_type})
        return fn

    return wrapper


def rpc_endpoint(path: str) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Mark an async function as an RPC endpoint at a given path."""

    def wrapper(fn: Callable[..., Awaitable[Any]]):
        _attach_meta(fn, "rpc_endpoint", {"path": path})
        return fn

    return wrapper


def require_traits(traits: List[str]) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Require certain traits to execute the function."""

    def wrapper(fn: Callable[..., Awaitable[Any]]):
        _attach_meta(fn, "require_traits", {"traits": list(traits or [])})

        @functools.wraps(fn)
        async def guarded(*args, **kwargs):
            # Soft enforcement placeholder: real enforcement happens in core policy.
            return await fn(*args, **kwargs)

        return guarded

    return wrapper


def audit_log(event: str) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Annotate function to emit an audit log on success/failure (handled by core)."""

    def wrapper(fn: Callable[..., Awaitable[Any]]):
        _attach_meta(fn, "audit_log", {"event": event})

        @functools.wraps(fn)
        async def audited(*args, **kwargs):
            # Placeholder: allow function to run; core may wrap for audit
            return await fn(*args, **kwargs)

        return audited

    return wrapper


def track_metrics(metric_name: str) -> Callable[[Callable[..., Awaitable[Any]]], Callable[..., Awaitable[Any]]]:
    """Annotate function to track metrics (handled by core/sidecar)."""

    def wrapper(fn: Callable[..., Awaitable[Any]]):
        _attach_meta(fn, "track_metrics", {"metric": metric_name})

        @functools.wraps(fn)
        async def metered(*args, **kwargs):
            return await fn(*args, **kwargs)

        return metered

    return wrapper


# ----------------------- Base Plugin -----------------------


class VivifiedPlugin:
    """Base class for Vivified plugins.

    Provides basic lifecycle hooks and convenience members used by example code
    in docs/runbooks.
    """

    def __init__(self, manifest_path: Optional[str] = None):
        self.manifest_path = manifest_path or "manifest.json"
        self.event_bus = _EventBusClient()
        self.rpc_client = _RpcClient()
        self.notification = _NotificationClient()
        self._bg_tasks: list[asyncio.Task] = []

    async def initialize(self) -> None:  # to be overridden
        return None

    async def shutdown(self) -> None:
        for t in self._bg_tasks:
            t.cancel()
        self._bg_tasks.clear()

    def init_metrics(self) -> None:  # placeholder
        return None


# ----------------------- Light Clients -----------------------


class _EventBusClient:
    async def subscribe(self, event_types: List[str], callback: Callable[..., Any]) -> None:
        return None

    async def publish(self, event_type: str, payload: Dict[str, Any], *, data_traits: Optional[List[str]] = None) -> None:
        return None


class _RpcClient:
    async def call(self, service: str, operation: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {"ok": True}


class _NotificationClient:
    async def send_emergency_alert(self, payload: Dict[str, Any]) -> None:
        return None

