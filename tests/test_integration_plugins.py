from __future__ import annotations

import os
from fastapi.testclient import TestClient

from core.main import app


def _auth_headers() -> dict[str, str]:
    return {"Authorization": "Bearer bootstrap_admin_only"}


def test_list_integration_providers_and_flags():
    with TestClient(app) as client:
        # Admin auth
        r = client.get("/plugins/integration/providers", headers=_auth_headers())
        assert r.status_code == 200
        data = r.json()
        assert "providers" in data
        keys = {p["key"] for p in data["providers"]}
        # Expect the three built-in shims
        assert {"hubspot", "gmail", "discord"}.issubset(keys)


def test_hipaa_mode_blocks_all_by_manifest():
    # In HIPAA mode, none of the current manifests are eligible; all actions must be blocked
    os.environ["INTEGRATIONS_HIPAA_MODE"] = "true"
    try:
        with TestClient(app) as client:
            for prov in ("hubspot", "gmail", "discord"):
                r = client.post(f"/plugins/integration/{prov}/connect", headers=_auth_headers())
                assert r.status_code == 403
                assert r.json().get("detail") == "integration.not_allowed"
    finally:
        os.environ.pop("INTEGRATIONS_HIPAA_MODE", None)

