import os
from fastapi.testclient import TestClient


os.environ["DEV_MODE"] = "true"

from core.main import app  # noqa: E402


def _get_admin_token(client: TestClient) -> str:
    r = client.post("/auth/dev-login", json={"enabled": True})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_gateway_allowlist_roundtrip():
    client = TestClient(app)
    token = _get_admin_token(client)
    auth = {"Authorization": f"Bearer {token}"}

    plugin_id = "example-plugin"

    # Initial (likely empty)
    r = client.get(f"/admin/gateway/allowlist?plugin_id={plugin_id}", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json().get("plugin_id") == plugin_id

    # Update
    payload = {
        "plugin_id": plugin_id,
        "allowlist": {
            "api.example.com": {
                "allowed_methods": ["get", "POST"],
                "allowed_paths": ["/v1/*", "/health"],
            }
        },
    }
    r = client.put("/admin/gateway/allowlist", json=payload, headers=auth)
    assert r.status_code == 200, r.text
    assert r.json().get("ok") is True

    # Verify
    r = client.get(f"/admin/gateway/allowlist?plugin_id={plugin_id}", headers=auth)
    assert r.status_code == 200, r.text
    items = r.json().get("items") or {}
    assert "api.example.com" in items
    rule = items["api.example.com"]
    assert set(rule["allowed_methods"]) == {"GET", "POST"}
    assert set(rule["allowed_paths"]) == {"/v1/*", "/health"}

