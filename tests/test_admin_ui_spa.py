import os
from fastapi.testclient import TestClient


# Enable dev mode before importing the app
os.environ["DEV_MODE"] = "true"

# Ensure SPA dist exists before importing app so routes are mounted
_dist_dir = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "core", "admin_ui", "dist")
)
os.makedirs(_dist_dir, exist_ok=True)
_index_path = os.path.join(_dist_dir, "index.html")
if not os.path.exists(_index_path):
    with open(_index_path, "w", encoding="utf-8") as _f:
        _f.write("<html><body>UI OK</body></html>")

from core.main import app  # noqa: E402


def _ensure_dist():
    # Already created at import; keep function for clarity
    assert os.path.isdir(_dist_dir)
    assert os.path.isfile(_index_path)


def _get_admin_token(client: TestClient) -> str:
    r = client.post("/auth/dev-login", json={"enabled": True})
    assert r.status_code == 200, r.text
    return r.json()["token"]


def test_spa_serves_index_and_fallback():
    _ensure_dist()
    client = TestClient(app)
    r = client.get("/admin/ui")
    assert r.status_code == 200
    assert r.headers.get("content-type", "").startswith("text/html")

    r2 = client.get("/admin/ui/tools/plugins")
    assert r2.status_code == 200
    assert r2.headers.get("content-type", "").startswith("text/html")


def test_ui_config_etag_and_flags():
    client = TestClient(app)
    token = _get_admin_token(client)
    r1 = client.get("/admin/ui-config", headers={"Authorization": f"Bearer {token}"})
    assert r1.status_code == 200, r1.text
    etag = r1.headers.get("etag") or r1.headers.get("ETag")
    data = r1.json()
    assert isinstance(data.get("features", {}), dict)
    # Required flags present with safe defaults
    feats = data["features"]
    assert "admin_console" in feats and isinstance(
        feats["admin_console"].get("enabled"), bool
    )
    assert "plugins" in feats and isinstance(feats["plugins"].get("enabled"), bool)
    assert "v3_plugins" in feats and isinstance(
        feats["v3_plugins"].get("enabled"), bool
    )
    assert isinstance(feats.get("plugin_install"), bool)
    assert isinstance(feats.get("sessions_enabled"), bool)
    assert isinstance(feats.get("csrf_enabled"), bool)
    # ETag conditional request returns 304
    if etag:
        r2 = client.get(
            "/admin/ui-config",
            headers={"Authorization": f"Bearer {token}", "If-None-Match": etag},
        )
        assert r2.status_code == 304


def test_stub_endpoints_and_traits():
    client = TestClient(app)
    token = _get_admin_token(client)
    auth = {"Authorization": f"Bearer {token}"}

    # Marketplace
    r = client.get("/admin/marketplace/plugins", headers=auth)
    assert r.status_code == 200
    assert r.json().get("plugins") == []

    # Health
    r = client.get("/admin/health-status", headers=auth)
    assert r.status_code == 200
    d = r.json()
    assert "backend_healthy" in d and "timestamp" in d

    # Diagnostics
    r = client.post("/admin/diagnostics/run", headers=auth)
    assert r.status_code == 200
    dd = r.json()
    assert "checks" in dd and "summary" in dd

    # Plugin config GET/PUT
    r = client.get("/plugins/example/config", headers=auth)
    assert r.status_code == 200
    pc = r.json()
    assert isinstance(pc.get("enabled"), bool)
    assert isinstance(pc.get("settings"), dict)

    r = client.put(
        "/plugins/example/config",
        json={"enabled": True, "settings": {"bucket": "x"}},
        headers=auth,
    )
    assert r.status_code == 200
    assert r.json().get("ok") is True

    # Traits include dev UI traits when DEV_MODE=true
    r = client.get("/admin/user/traits", headers=auth)
    assert r.status_code == 200
    traits = set(r.json().get("traits", []))
    assert "role.admin" in traits
    assert "ui.plugins" in traits and "ui.config" in traits and "ui.audit" in traits
    # In dev we do not auto-enable risky surfaces by default
    assert "ui.terminal" not in traits and "ui.send" not in traits
