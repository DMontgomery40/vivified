from fastapi.testclient import TestClient

from core.main import app


def _auth(client: TestClient):
    r = client.post("/auth/dev-login", json={"enabled": True})
    assert r.status_code == 200
    token = r.json()["token"]
    return {"Authorization": f"Bearer {token}"}


def test_builtin_schema_loaded_and_validates():
    with TestClient(app) as client:
        headers = _auth(client)

        # Built-in schema should be available (auto-activated for major 1)
        r = client.get("/schemas/observability.log_event/active/1", headers=headers)
        assert r.status_code == 200
        body = r.json()
        assert body.get("active") is not None

        # Valid payload
        payload = {
            "timestamp": "2024-01-01T00:00:00Z",
            "severity": "INFO",
            "message": "ok",
        }
        r2 = client.post(
            "/schemas/observability.log_event/validate",
            headers=headers,
            json={"payload": payload, "major": 1},
        )
        assert r2.status_code == 200, r2.text
        v = r2.json()
        assert v.get("ok") is True

        # Invalid payload: missing message
        bad = {"timestamp": "2024-01-01T00:00:00Z", "severity": "INFO"}
        r3 = client.post(
            "/schemas/observability.log_event/validate",
            headers=headers,
            json={"payload": bad, "major": 1},
        )
        assert r3.status_code == 200
        v3 = r3.json()
        assert v3.get("ok") is False

