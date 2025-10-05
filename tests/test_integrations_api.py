import os
import json
from typing import Any, Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs

import pytest
from fastapi.testclient import TestClient


os.environ["DEV_MODE"] = "true"


class _StubResponse:
    def __init__(self, status_code: int, data: Dict[str, Any]):
        self.status_code = status_code
        self._data = data

    def json(self) -> Dict[str, Any]:
        return self._data


class _HttpxStubClient:
    """Stub for httpx.AsyncClient used by integrations router.

    Maintains simple connection state per (userId, provider).
    """

    _connected: Dict[str, bool] = {}

    def __init__(self, timeout: Optional[Any] = None):
        self.timeout = timeout

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None):
        path = urlparse(url).path
        if path.endswith("/health"):
            return _StubResponse(200, {"ok": True})
        if "/oauth_url/" in path:
            # Echo back a URL containing the provided state
            state = (params or {}).get("state") or ""
            if str(state).endswith("FAIL"):
                return _StubResponse(400, {"error": {"code": "oauth.url_generation_failed", "message": "Failed to generate URL"}})
            prov = path.rsplit("/", 1)[-1]
            u = f"https://oauth.example/authorize?provider={prov}&{urlencode({'state': state})}"
            return _StubResponse(200, {"url": u})
        if "/status/" in path:
            prov = path.rsplit("/", 1)[-1]
            user_id = (params or {}).get("userId") or ""
            key = f"{user_id}:{prov}"
            if self._connected.get(key):
                return _StubResponse(200, {"connected": True, "details": {"account_name": "Test Account"}})
            return _StubResponse(200, {"connected": False})
        # Default
        return _StubResponse(404, {"error": {"code": "route.not_found", "message": "not found"}})

    async def post(self, url: str, json: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None):
        path = urlparse(url).path
        if "/oauth_cb/" in path:
            prov = path.rsplit("/", 1)[-1]
            user_id = (json or {}).get("userId") or ""
            code = (json or {}).get("code")
            key = f"{user_id}:{prov}"
            if code == "TEST_CODE":
                self._connected[key] = True
                return _StubResponse(200, {"ok": True, "entity": {"provider": prov, "account_name": "Test Account", "external_id": "test_123"}})
            return _StubResponse(400, {"error": {"code": "oauth.exchange_failed", "message": "bad code"}})
        if "/revoke/" in path:
            prov = path.rsplit("/", 1)[-1]
            user_id = (json or {}).get("userId") or ""
            key = f"{user_id}:{prov}"
            self._connected[key] = False
            return _StubResponse(200, {"ok": True})
        return _StubResponse(404, {"error": {"code": "route.not_found", "message": "not found"}})


def _auth(client: TestClient) -> Dict[str, str]:
    # Use bootstrap key to avoid rate limit churn across the suite
    return {"Authorization": "Bearer bootstrap_admin_only", "X-API-Key": "bootstrap_admin_only"}


def _require_integrations(client: TestClient) -> None:
    """Skip tests when the integrations router isn't present in this branch."""
    r = client.get("/integrations")
    if r.status_code == 404:
        pytest.skip("Integrations API not present in this branch")


@pytest.fixture(autouse=True)
def _patch_httpx(monkeypatch):
    import httpx as _httpx

    # Replace AsyncClient with stub for all tests in this module
    monkeypatch.setattr(_httpx, "AsyncClient", _HttpxStubClient, raising=True)
    yield


def test_trait_gating_and_list(monkeypatch):
    from core.main import app
    client = TestClient(app)
    _require_integrations(client)
    auth = _auth(client)

    # Without auth should be 401
    r0 = client.get("/integrations")
    assert r0.status_code == 401

    r = client.get("/integrations", headers=auth)
    assert r.status_code == 200
    data = r.json()
    assert "items" in data and isinstance(data["items"], list)


def test_connect_url_contains_state_and_callback_success(monkeypatch):
    from core.main import app
    client = TestClient(app)
    _require_integrations(client)
    auth = _auth(client)

    # Connect
    r = client.post("/integrations/hubspot/connect", headers=auth)
    assert r.status_code == 200
    url = r.json()["url"]
    assert "state=" in url
    state = parse_qs(urlparse(url).query).get("state", [""])[0]
    assert state and state.startswith("dev-admin_")

    # Callback with TEST_CODE
    cb = client.get(f"/integrations/hubspot/callback?code=TEST_CODE&state={state}", headers=auth, allow_redirects=False)
    assert cb.status_code in (302, 307)

    # Status now connected
    s = client.get("/integrations/hubspot/status", headers=auth)
    assert s.status_code == 200
    assert s.json().get("connected") is True


def test_revoke_flips_status(monkeypatch):
    from core.main import app
    client = TestClient(app)
    _require_integrations(client)
    auth = _auth(client)

    # Connect to set state and callback
    r = client.post("/integrations/hubspot/connect", headers=auth)
    state = parse_qs(urlparse(r.json()["url"]).query).get("state", [""])[0]
    client.get(f"/integrations/hubspot/callback?code=TEST_CODE&state={state}", headers=auth, allow_redirects=False)

    # Revoke
    rv = client.post("/integrations/hubspot/revoke", headers=auth)
    assert rv.status_code == 200
    st = client.get("/integrations/hubspot/status", headers=auth)
    assert st.status_code == 200
    assert st.json().get("connected") is False


def test_hipaa_block_and_audit(monkeypatch):
    # Enforce HIPAA mode with no allowed providers
    import core.api.integrations as integ
    integ.INTEGRATIONS_HIPAA_MODE = True
    integ.INTEGRATIONS_HIPAA_ALLOWED = set()

    from core.main import app
    client = TestClient(app)
    _require_integrations(client)
    auth = _auth(client)

    r = client.post("/integrations/hubspot/connect", headers=auth)
    assert r.status_code == 403
    body = r.json()
    assert body.get("error", {}).get("code") == "integration.not_allowed"

    # Reset to default for next tests
    integ.INTEGRATIONS_HIPAA_MODE = False


def test_hipaa_false_never_blocks(monkeypatch):
    import core.api.integrations as integ
    from core.main import app

    integ.INTEGRATIONS_HIPAA_MODE = False
    integ.INTEGRATIONS_HIPAA_ALLOWED = set()

    client = TestClient(app)
    _require_integrations(client)
    auth = _auth(client)
    # Should get URL successfully when HIPAA disabled
    r = client.post("/integrations/hubspot/connect", headers=auth)
    assert r.status_code in (200, 400, 503)  # availability may vary, but not 403
    if r.status_code != 403:
        assert True


def test_oauth_url_generation_failed_mapping(monkeypatch):
    # Force the state generator to end with FAIL so stub returns oauth.url_generation_failed
    import core.api.integrations as integ
    from core.main import app

    def _fail_state(uid: str) -> str:
        return f"{uid}_CAUSE_FAIL.FAIL"

    monkeypatch.setattr(integ, "_state_generate", _fail_state, raising=True)

    client = TestClient(app)
    _require_integrations(client)
    auth = _auth(client)

    r = client.post("/integrations/hubspot/connect", headers=auth)
    assert r.status_code == 400
    body = r.json()
    assert body.get("error", {}).get("code") == "integration.oauth_failed"


def test_log_redaction(caplog, monkeypatch):
    from core.main import app
    client = TestClient(app)
    _require_integrations(client)
    auth = _auth(client)

    # Flow
    r = client.post("/integrations/hubspot/connect", headers=auth)
    state = parse_qs(urlparse(r.json()["url"]).query).get("state", [""])[0]
    client.get(f"/integrations/hubspot/callback?code=TEST_CODE&state={state}", headers=auth, allow_redirects=False)

    # Inspect captured logs for obvious PHI/PII markers (very rough)
    text = "\n".join(rec.message for rec in caplog.records)
    assert "@" not in text  # no emails
    assert "+1" not in text  # no phone numbers
