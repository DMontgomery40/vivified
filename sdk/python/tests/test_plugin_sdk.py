import asyncio
import pytest
from typing import Optional
from vivified_sdk import (
    VivifiedPlugin,
    event_handler,
    rpc_endpoint,
    require_traits,
    audit_log,
    track_metrics,
    SecurityContext,
)


class MyPlugin(VivifiedPlugin):
    def __init__(self):
        super().__init__("manifest.json")
        self.initialized = False

    async def initialize(self):
        self.initialized = True

    @rpc_endpoint("/api/echo")
    @require_traits(["handles_public"])  # soft-enforced in SDK
    @audit_log("echo_call")
    @track_metrics("echo_calls")
    async def echo(self, data: dict, context: Optional[SecurityContext] = None) -> dict:
        return {"ok": True, "echo": data, "user": getattr(context, "user_id", None)}


@pytest.mark.asyncio
async def test_plugin_lifecycle_and_decorators():
    p = MyPlugin()
    assert hasattr(p, "event_bus") and hasattr(p, "rpc_client") and hasattr(p, "notification")
    await p.initialize()
    assert p.initialized is True

    # Verify metadata is attached by decorators
    meta = getattr(p.echo, "__vivified_meta__", {})
    assert meta.get("rpc_endpoint", {}).get("path") == "/api/echo"
    assert meta.get("require_traits", {}).get("traits") == ["handles_public"]
    assert meta.get("audit_log", {}).get("event") == "echo_call"
    assert meta.get("track_metrics", {}).get("metric") == "echo_calls"

    # Call function
    res = await p.echo({"hi": 1}, SecurityContext(user_id="u1"))
    assert res["ok"] is True and res["echo"] == {"hi": 1}
