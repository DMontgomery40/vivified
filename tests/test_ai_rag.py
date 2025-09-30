import os
from fastapi.testclient import TestClient


os.environ["DEV_MODE"] = "true"

from core.main import app  # noqa: E402


def _auth() -> dict:
    return {"Authorization": "Bearer bootstrap_admin_only"}


def test_ai_status_and_train_and_query():
    client = TestClient(app)
    auth = _auth()

    # Check status
    r = client.get("/admin/ai/status", headers=auth)
    assert r.status_code == 200, r.text
    before = int(r.json().get("docs_indexed", 0))

    # Train (defaults to docs + internal-plans)
    r2 = client.post("/admin/ai/train", headers=auth, json={})
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body.get("ok") is True
    assert isinstance(body.get("indexed"), int)
    assert body.get("total", 0) >= before

    # Query
    r3 = client.post("/admin/ai/query", headers=auth, json={"q": "Vivified"})
    assert r3.status_code == 200, r3.text
    items = r3.json().get("items") or []
    assert isinstance(items, list)

    # Agent run
    r4 = client.post("/admin/ai/agent/run", headers=auth, json={"prompt": "What is Vivified?"})
    assert r4.status_code == 200, r4.text
    assert "result" in r4.json()

