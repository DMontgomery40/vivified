import os
from fastapi.testclient import TestClient


os.environ["DEV_MODE"] = "true"

from core.main import app  # noqa: E402


def _auth(client: TestClient):
    r = client.post("/auth/dev-login", json={"enabled": True})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_get_providers_and_health():
    client = TestClient(app)
    auth = _auth(client)
    r = client.get("/admin/providers", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "active" in data and "registry" in data
    assert isinstance(data["registry"], dict) and len(data["registry"]) > 0

    r2 = client.get("/admin/providers/health", headers=auth)
    assert r2.status_code == 200
    h = r2.json()
    assert "items" in h


def test_settings_flow_export_persist():
    client = TestClient(app)
    auth = _auth(client)

    # Get settings
    r = client.get("/admin/settings", headers=auth)
    assert r.status_code == 200
    s = r.json()
    assert "backend" in s and "security" in s

    # Update a setting
    r = client.put("/admin/settings", headers=auth, json={"backend": "phaxio", "require_api_key": False})
    assert r.status_code == 200

    # Export env
    r = client.post("/admin/settings/export", headers=auth)
    assert r.status_code == 200
    env = r.json()["env_content"]
    assert "JWT_SECRET" in env

    # Persist to server
    r = client.post("/admin/settings/persist", headers=auth, json={})
    assert r.status_code == 200
    assert r.json().get("ok") is True

