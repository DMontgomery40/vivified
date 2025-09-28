import asyncio
import pytest
from vivified_sdk import VivifiedClient


@pytest.mark.asyncio
async def test_client_smoke_methods_exist():
    c = VivifiedClient(base_url="http://localhost:8000")
    assert hasattr(c, "publish_event")
    assert hasattr(c, "subscribe")
    assert hasattr(c, "call_plugin")
    assert hasattr(c, "call_external")
    assert hasattr(c, "get_config")
    assert hasattr(c, "set_config")
    await c.aclose()

