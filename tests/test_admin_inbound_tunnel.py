import os
from fastapi.testclient import TestClient


os.environ["DEV_MODE"] = "true"

from core.main import app  # noqa: E402


def _auth(client: TestClient):
    r = client.post("/auth/dev-login", json={"enabled": True})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_inbound_tools_and_actions_and_tunnel():
    client = TestClient(app)
    auth = _auth(client)

    # Inbound callbacks
    r = client.get("/admin/inbound/callbacks", headers=auth)
    assert r.status_code == 200
    assert "callbacks" in r.json()

    # Simulate inbound
    r = client.post("/admin/inbound/simulate", headers=auth, json={"status": "received"})
    assert r.status_code == 200
    assert r.json()["status"] == "received"

    # Actions list
    r = client.get("/admin/actions", headers=auth)
    assert r.status_code == 200
    items = r.json()["items"]
    assert any(i["id"] == "reload-config" for i in items)

    # Run action
    r = client.post("/admin/actions/run", headers=auth, json={"id": "reload-config"})
    assert r.status_code == 200
    assert r.json()["ok"] is True

    # Tunnel status
    r = client.get("/admin/tunnel/status", headers=auth)
    assert r.status_code == 200
    
    # Set tunnel config
    r = client.post("/admin/tunnel/config", headers=auth, json={"enabled": True, "provider": "cloudflare"})
    assert r.status_code == 200
    
    # Test tunnel
    r = client.post("/admin/tunnel/test", headers=auth)
    assert r.status_code == 200
    
    # WG import + delete
    r = client.post("/admin/tunnel/wg/import", headers=auth, json={"content": "[Interface]\nPrivateKey=...\n"})
    assert r.status_code == 200
    r = client.delete("/admin/tunnel/wg/conf", headers=auth)
    assert r.status_code == 200

