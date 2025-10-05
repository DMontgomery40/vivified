import asyncio
from core.policy.engine_enhanced import (
    EnhancedPolicyEngine,
    PolicyRequest,
    PolicyContext,
    PolicyDecision,
)


def run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def test_phi_access_requires_traits_and_audit():
    eng = EnhancedPolicyEngine()
    req = PolicyRequest(
        user_id="u",
        resource_type="storage_object",
        resource_id="obj1",
        action="read",
        traits=[],
        context={"data_classification": "phi"},
    )
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.DENY
    assert "phi" in res.reason

    # With handles_phi but missing audit_required -> still deny
    req.traits = ["handles_phi"]
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.DENY
    assert "audit" in res.reason

    # With audit_required present -> allow
    req.traits = ["handles_phi", "audit_required", "encryption_required"]
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.ALLOW


def test_pii_access_policy():
    eng = EnhancedPolicyEngine()
    req = PolicyRequest(
        user_id="u",
        resource_type="message",
        resource_id="m1",
        action="send",
        traits=[],
        context={"data_classification": "pii"},
    )
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.DENY

    req.traits = ["handles_pii", "audit_required"]
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.ALLOW


def test_confidential_requires_trait():
    eng = EnhancedPolicyEngine()
    req = PolicyRequest(
        user_id="u",
        resource_type="doc",
        resource_id="d1",
        action="read",
        traits=[],
        context={"data_classification": "confidential"},
    )
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.DENY

    req.traits = ["handles_confidential"]
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.ALLOW


def test_plugin_and_config_management_require_proper_traits():
    eng = EnhancedPolicyEngine()
    # Plugin register requires plugin_manager
    req = PolicyRequest(
        user_id="u",
        resource_type="plugin",
        resource_id="p1",
        action="register",
        traits=[],
        context={},
    )
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.DENY
    req.traits = ["plugin_manager"]
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.ALLOW

    # Config write requires config_manager
    req = PolicyRequest(
        user_id="u",
        resource_type="config",
        resource_id="k",
        action="write",
        traits=[],
        context={},
    )
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.DENY
    req.traits = ["config_manager"]
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.ALLOW


def test_ui_feature_gating():
    eng = EnhancedPolicyEngine()
    # Without ui.plugins trait deny 'plugins' feature
    req = PolicyRequest(
        user_id="u",
        resource_type="ui_feature",
        resource_id="plugins",
        action="access",
        traits=[],
        context={},
    )
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.DENY

    # With ui.plugins -> allow
    req.traits = ["ui.plugins"]
    res = run(eng.evaluate_request(req))
    assert res.decision == PolicyDecision.ALLOW


def test_user_ui_traits_mapping_for_admin_and_viewer():
    eng = EnhancedPolicyEngine()
    traits_admin = eng.get_user_ui_traits(["admin"])  # adds role.admin and core UI traits
    assert "ui.plugins" in traits_admin and "ui.audit" in traits_admin

    traits_viewer = eng.get_user_ui_traits(["viewer"])  # minimal
    assert "role.viewer" in traits_viewer
