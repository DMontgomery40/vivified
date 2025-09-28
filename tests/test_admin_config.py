import os

# Enable dev mode before importing app
os.environ["DEV_MODE"] = "true"

from fastapi.testclient import TestClient  # noqa: E402
from core.main import app  # noqa: E402
from core.identity.auth import get_auth_manager  # noqa: E402


def get_admin_token(client: TestClient) -> str:
    resp = client.post("/auth/dev-login", json={"enabled": True})
    assert resp.status_code == 200, resp.text
    return resp.json()["token"]


def test_admin_config_roundtrip():
    client = TestClient(app)
    token = get_admin_token(client)

    # Set brand config
    payload = {
        "key": "ui.brand",
        "value": {"title": "Vivified", "primary": "#6D28D9", "accent": "#22D3EE"},
        "is_sensitive": False,
        "reason": "branding update",
    }
    r = client.put(
        "/admin/config", json=payload, headers={"Authorization": f"Bearer {token}"}
    )
    assert r.status_code == 200, r.text

    # Read back
    r = client.get("/admin/config", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("ui.brand", {}).get("title") == "Vivified"


def test_admin_config_forbidden_without_traits():
    client = TestClient(app)
    # Create a non-admin token
    token = get_auth_manager().generate_user_token(
        "user-1", traits=["viewer"], expires_minutes=15
    )
    r = client.get("/admin/config", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code in (401, 403)
