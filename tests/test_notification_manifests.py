import uuid
from fastapi.testclient import TestClient

from core.main import app


def _manifest_apprise(pid: str) -> dict:
    return {
        "id": pid,
        "name": "Apprise Notifier Plugin",
        "version": "1.0.0",
        "description": "Multi-provider notifications via Apprise (POC)",
        "contracts": ["CommunicationPlugin"],
        "traits": [
            "communication_plugin",
            "handles_notifications",
            "requires_config",
            "external_service",
        ],
        "dependencies": [],
        "allowed_domains": [],
        "endpoints": {"health": "/health", "send": "/send"},
        "security": {
            "authentication_required": True,
            "data_classification": ["internal"],
            "allowed_domains": [],
        },
        "compliance": {"hipaa_controls": [], "audit_level": "standard"},
    }


def _manifest_pushover(pid: str) -> dict:
    return {
        "id": pid,
        "name": "Pushover Notifier Plugin",
        "version": "1.0.0",
        "description": "Send push notifications using Pushover",
        "contracts": ["CommunicationPlugin"],
        "traits": [
            "communication_plugin",
            "handles_notifications",
            "requires_config",
            "external_service",
        ],
        "dependencies": [],
        "allowed_domains": ["api.pushover.net"],
        "endpoints": {"health": "/health", "send": "/send"},
        "security": {
            "authentication_required": True,
            "data_classification": ["internal"],
            "allowed_domains": ["api.pushover.net"],
        },
        "compliance": {"hipaa_controls": [], "audit_level": "standard"},
    }


def test_register_notification_manifests_and_publish_event():
    with TestClient(app) as client:

        # Register Apprise
        apprise_id = f"apprise-notifier-test-{uuid.uuid4().hex[:8]}"
        r1 = client.post("/plugins/register", json=_manifest_apprise(apprise_id))
        assert r1.status_code == 200, r1.text
        assert r1.json().get("plugin_id") == apprise_id
        assert r1.json().get("token")

        # Register Pushover
        pushover_id = f"pushover-notifier-test-{uuid.uuid4().hex[:8]}"
        r2 = client.post("/plugins/register", json=_manifest_pushover(pushover_id))
        assert r2.status_code == 200, r2.text
        assert r2.json().get("plugin_id") == pushover_id
        assert r2.json().get("token")

        # Publish a NotificationSent event (canonical path)
        evt = client.post(
            f"/messaging/events?event_type=NotificationSent&source_plugin={apprise_id}",
            json={
                "payload": {
                    "event_type": "NotificationSent",
                    "notification_id": "test-123",
                    "plugin": apprise_id,
                    "status": "sent",
                    "details": {"targets": ["noop"]},
                },
                "data_traits": ["internal"],
            },
        )
        assert evt.status_code == 200, evt.text
        assert evt.json().get("status") == "published"
