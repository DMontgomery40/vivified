import os
from fastapi.testclient import TestClient


# Enable DEV bootstrap: allows using special bootstrap key without login
os.environ["DEV_MODE"] = "true"

from core.main import app  # noqa: E402


def _llm_manifest(plugin_id: str) -> dict:
    return {
        "id": plugin_id,
        "name": "Generic LLM Plugin",
        "version": "1.0.0",
        "description": "Generic LLM integration",
        "contracts": ["CommunicationPlugin"],
        "traits": ["communication_plugin", "external_service", "requires_config", "handles_pii"],
        "dependencies": [],
        # Core will sync these into the gateway allowlist at registration time
        "allowed_domains": [
            "api.openai.com",
            "api.anthropic.com",
        ],
        # Include fully qualified endpoints to exercise manifest validator suggestions
        "endpoints": {
            "generate_openai": "https://api.openai.com/v1/chat/completions",
            "generate_anthropic": "https://api.anthropic.com/v1/messages",
        },
        # Security must conform to manifest.schema.json
        "security": {
            "authentication": "api_key",
            "header": "Authorization",
            "scheme": "Bearer"
        },
        "compliance": {"hipaa_controls": ["164.312(a)", "164.312(e)"], "audit_level": "detailed"},
    }


def test_llm_plugin_registers_and_syncs_allowlist():
    client = TestClient(app)
    # Use bootstrap admin key to avoid rate limiter on dev-login
    auth = {"Authorization": "Bearer bootstrap_admin_only"}

    plugin_id = "llm-generic-test"
    manifest = _llm_manifest(plugin_id)

    # Register plugin
    r = client.post("/plugins/register", json=manifest)
    assert r.status_code == 200, r.text
    data = r.json()
    assert data.get("plugin_id") == plugin_id
    assert data.get("token")

    # Inspect effective allowlist (runtime view from GatewayService)
    r = client.get(f"/gateway/allowlist/effective?plugin_id={plugin_id}", headers=auth)
    assert r.status_code == 200, r.text
    entries = r.json().get("entries") or []
    domains = {e.get("domain") for e in entries}
    # Both OpenAI and Anthropic domains should be present
    assert "api.openai.com" in domains
    assert "api.anthropic.com" in domains


def test_llm_manifest_validation_suggests_allowlist_from_endpoints():
    client = TestClient(app)
    auth = {"Authorization": "Bearer bootstrap_admin_only"}

    payload = _llm_manifest("llm-validate-only")
    r = client.post("/admin/plugins/validate-manifest", json=payload, headers=auth)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("ok") is True, body

    suggestions = body.get("suggestions") or {}
    allowlist = suggestions.get("allowlist") or {}
    assert "api.openai.com" in allowlist
    assert "api.anthropic.com" in allowlist
    # Ensure suggested methods normalization and path extraction are present
    for host in ("api.openai.com", "api.anthropic.com"):
        rule = allowlist[host]
        assert set(m.upper() for m in (rule.get("allowed_methods") or [])) >= {"GET", "POST"}
        assert isinstance(rule.get("allowed_paths"), list)
