import os
from fastapi.testclient import TestClient


os.environ["DEV_MODE"] = "true"

from core.main import app  # noqa: E402


def _get_admin_token(client: TestClient) -> str:
    r = client.post("/auth/dev-login", json={"enabled": True})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_admin_api_keys_crud():
    client = TestClient(app)
    token = _get_admin_token(client)
    auth = {"Authorization": f"Bearer {token}"}

    # Create
    r = client.post(
        "/admin/api-keys",
        json={"name": "Test Key", "scopes": ["fax:send", "keys:manage"]},
        headers=auth,
    )
    assert r.status_code == 200, r.text
    created = r.json()
    key_id = created["key_id"]
    assert created["token"] and isinstance(created["token"], str)

    # List
    r = client.get("/admin/api-keys", headers=auth)
    assert r.status_code == 200, r.text
    items = r.json()
    assert any(k["key_id"] == key_id for k in items)

    # Rotate
    r = client.post(f"/admin/api-keys/{key_id}/rotate", headers=auth)
    assert r.status_code == 200, r.text
    assert r.json().get("token")

    # Revoke
    r = client.delete(f"/admin/api-keys/{key_id}", headers=auth)
    assert r.status_code == 200, r.text

    # List (ensure removed)
    r = client.get("/admin/api-keys", headers=auth)
    assert r.status_code == 200, r.text
    items2 = r.json()
    assert not any(k["key_id"] == key_id for k in items2)
