import asyncio
import json

from core.audit.service import AuditService
from core.messaging.event_bus import EventBus
from core.messaging.models import Event, Message, MessageType, DataClassification
from core.policy.engine import PolicyEngine
from core.gateway.proxy import ProxyHandler
from core.gateway.models import DomainAllowlist, ProxyRequest, ProxyMethod
from core.main import _is_safe_plugin_host, _is_safe_endpoint_path


async def _run(coro):
    return await coro


def test_audit_redaction_masks_phi_pii_fields():
    svc = AuditService()
    details = {
        "email": "jane@example.com",
        "patient_id": "abc123",
        "nested": {"ssn": "123-45-6789", "ok": 42},
        "note": "hello",
    }

    async def _emit():
        await svc.log_event(
            event_type="unit_test",
            category="security",
            action="emit",
            result="success",
            description="redaction",
            details=details,
        )
        return await svc.list_events(limit=1)

    out = asyncio.get_event_loop().run_until_complete(_emit())
    assert out["items"], "no audit items returned"
    item = out["items"][0]
    payload = json.dumps(item)
    assert "jane@example.com" not in payload
    assert "123-45-6789" not in payload
    # Masked markers are present
    assert "[REDACTED]" in payload


def test_proxy_allowlist_blocks_unlisted_domain_and_ip():
    svc = AuditService()
    handler = ProxyHandler(audit_service=svc, config_service=None)
    allow = {
        "example.com": DomainAllowlist(
            plugin_id="p1", domain="example.com", allowed_methods=[ProxyMethod.GET]
        )
    }

    # Unlisted domain should be blocked
    req1 = ProxyRequest(
        plugin_id="p1", method=ProxyMethod.GET, url="http://evil.com/api"
    )
    ok1 = asyncio.get_event_loop().run_until_complete(
        handler._is_request_allowed(req1, allow)
    )
    assert ok1 is False

    # Literal IP host should be blocked
    req2 = ProxyRequest(
        plugin_id="p1", method=ProxyMethod.GET, url="http://127.0.0.1/api"
    )
    ok2 = asyncio.get_event_loop().run_until_complete(
        handler._is_request_allowed(req2, allow)
    )
    assert ok2 is False

    # Allowed domain but disallowed path
    allow["example.com"].allowed_paths = ["/v1/"]
    req3 = ProxyRequest(
        plugin_id="p1", method=ProxyMethod.GET, url="http://example.com/v2/x"
    )
    ok3 = asyncio.get_event_loop().run_until_complete(
        handler._is_request_allowed(req3, allow)
    )
    assert ok3 is False


def test_event_bus_policy_blocks_phi_event_without_traits():
    svc = AuditService()
    eng = PolicyEngine()
    bus = EventBus(audit_service=svc, policy_engine=eng)

    evt = Event(event_type="user_updated", source_plugin="p1", data_traits=["phi"], payload={})
    ok = asyncio.get_event_loop().run_until_complete(bus._can_publish_event("p1", evt))
    assert ok is False


def test_event_bus_policy_blocks_phi_message_without_traits():
    svc = AuditService()
    eng = PolicyEngine()
    bus = EventBus(audit_service=svc, policy_engine=eng)

    msg = Message(
        message_type=MessageType.REQUEST,
        source_plugin="p1",
        target_plugin="p2",
        data_classification=DataClassification.PHI,
        payload={"patient": "x"},
    )
    ok = asyncio.get_event_loop().run_until_complete(bus._can_send_message("p1", msg))
    assert ok is False


def test_operator_lane_sanitizes_host_and_path():
    # Unsafe hosts
    assert _is_safe_plugin_host("plugin-service") is True
    assert _is_safe_plugin_host("plugin.service") is False
    assert _is_safe_plugin_host("http://evil.com") is False
    assert _is_safe_plugin_host("127.0.0.1") is False
    assert _is_safe_plugin_host("plugin:8080") is False

    # Unsafe paths
    assert _is_safe_endpoint_path("/ok/path") is True
    assert _is_safe_endpoint_path("http://evil.com/") is False
    assert _is_safe_endpoint_path("relative") is False
