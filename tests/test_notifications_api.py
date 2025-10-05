import os
from fastapi.testclient import TestClient

os.environ["DEV_MODE"] = "true"

from core.main import app  # noqa: E402


def _get_admin_token(client: TestClient) -> str:
    r = client.post("/auth/dev-login", json={"enabled": True})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_notifications_endpoints():
    client = TestClient(app)
    token = _get_admin_token(client)
    auth = {"Authorization": f"Bearer {token}"}

    # Settings get/put
    r = client.get("/admin/notifications/settings", headers=auth)
    assert r.status_code == 200
    s = r.json()
    assert isinstance(s.get("enabled"), bool)

    r = client.put(
        "/admin/notifications/settings", json={"dry_run": True}, headers=auth
    )
    assert r.status_code == 200
    assert r.json().get("dry_run") is True

    # Send and Inbox
    r = client.post("/admin/notifications/send", json={"body": "hello"}, headers=auth)
    assert r.status_code == 200
    nid = r.json().get("notification_id")
    assert isinstance(nid, str) and nid

    r = client.get("/admin/notifications", headers=auth)
    assert r.status_code == 200
    items = r.json().get("items", [])
    assert isinstance(items, list)
