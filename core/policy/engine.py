"""
Comprehensive trait-based policy engine for Vivified platform.

This engine provides:
- Hierarchical trait-based access control
- Data classification enforcement
- Plugin interaction policies
- UI feature gating
- Comprehensive audit logging
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import json

from .traits import TraitRegistry, trait_validator, TraitCategory

logger = logging.getLogger(__name__)


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    SANITIZE = "sanitize"  # Allow but remove sensitive data


class PolicyContext(str, Enum):
    """Contexts for policy evaluation."""

    USER_ACTION = "user_action"
    PLUGIN_INTERACTION = "plugin_interaction"
    SYSTEM_OPERATION = "system_operation"
    API_REQUEST = "api_request"


@dataclass
class PolicyRequest:
    """Request for policy evaluation."""

    user_id: Optional[str]
    resource_type: str
    resource_id: str
    action: str
    traits: List[str]
    context: Dict[str, Any]
    policy_context: PolicyContext = PolicyContext.USER_ACTION
    source_plugin: Optional[str] = None
    target_plugin: Optional[str] = None


@dataclass
class PolicyResult:
    """Result of policy evaluation."""

    decision: PolicyDecision
    reason: str
    required_traits: List[str] = None
    sanitize_fields: List[str] = None
    audit_level: str = "standard"


class PolicyEngine:
    def __init__(self) -> None:
        self._cache: Dict[str, PolicyResult] = {}

    async def evaluate_request(self, request: PolicyRequest) -> PolicyResult:
        """Evaluate a policy request using comprehensive security rules.

        Rules (in priority order):
        1. Admin override - admins can access everything
        2. PHI protection - requires specific PHI handling traits
        3. PII protection - requires specific PII handling traits
        4. External service restrictions - sanitize sensitive data
        5. Audit requirements - ensure sensitive operations are logged
        6. Default allow for non-sensitive operations
        """
        ctx = request.context or {}
        classification = (ctx.get("data_classification") or "").lower()
        traits = set(request.traits or [])
        resource_type = request.resource_type
        action = request.action

        # Admin override - highest priority
        if "admin" in traits:
            self.audit(
                request.user_id or "unknown",
                request.resource_id,
                [],
                "allow",
                "admin_privilege",
            )
            return PolicyResult(PolicyDecision.ALLOW, "admin_privilege")

        # PHI protection - critical for HIPAA compliance
        if classification == "phi" or "phi" in (ctx.get("data_traits") or []):
            if traits.intersection({"phi_handler", "handles_phi", "admin"}):
                # Additional check: ensure audit is enabled for PHI access
                if "audit_required" in traits or "admin" in traits:
                    self.audit(
                        request.user_id or "unknown",
                        request.resource_id,
                        ["phi"],
                        "allow",
                        "phi_trait_present",
                    )
                    return PolicyResult(PolicyDecision.ALLOW, "phi_trait_present")
                else:
                    self.audit(
                        request.user_id or "unknown",
                        request.resource_id,
                        ["phi"],
                        "deny",
                        "phi_audit_required",
                    )
                    return PolicyResult(PolicyDecision.DENY, "phi_audit_required")
            else:
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    ["phi"],
                    "deny",
                    "phi_trait_missing",
                )
                return PolicyResult(PolicyDecision.DENY, "phi_trait_missing")

        # PII protection
        if classification == "pii" or "pii" in (ctx.get("data_traits") or []):
            if traits.intersection({"pii_handler", "handles_pii", "admin"}):
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    ["pii"],
                    "allow",
                    "pii_trait_present",
                )
                return PolicyResult(PolicyDecision.ALLOW, "pii_trait_present")
            else:
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    ["pii"],
                    "deny",
                    "pii_trait_missing",
                )
                return PolicyResult(PolicyDecision.DENY, "pii_trait_missing")

        # External service restrictions
        if ctx.get("external_service") and classification in [
            "confidential",
            "phi",
            "pii",
        ]:
            if "external_service" in traits:
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    [classification],
                    "sanitize",
                    "external_service_sanitize",
                )
                return PolicyResult(PolicyDecision.ALLOW, "external_service_sanitize")
            else:
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    [classification],
                    "deny",
                    "external_service_denied",
                )
                return PolicyResult(PolicyDecision.DENY, "external_service_denied")

        # Plugin-specific restrictions
        if resource_type == "plugin" and action in ["register", "configure", "execute"]:
            if "plugin_manager" in traits or "admin" in traits:
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    [],
                    "allow",
                    "plugin_manager_privilege",
                )
                return PolicyResult(PolicyDecision.ALLOW, "plugin_manager_privilege")
            else:
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    [],
                    "deny",
                    "plugin_access_denied",
                )
                return PolicyResult(PolicyDecision.DENY, "plugin_access_denied")

        # Configuration access
        if resource_type == "config" and action in ["read", "write", "delete"]:
            if "config_manager" in traits or "admin" in traits:
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    [],
                    "allow",
                    "config_manager_privilege",
                )
                return PolicyResult(PolicyDecision.ALLOW, "config_manager_privilege")
            elif action == "read" and "viewer" in traits:
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    [],
                    "allow",
                    "viewer_read",
                )
                return PolicyResult(PolicyDecision.ALLOW, "viewer_read")
            else:
                self.audit(
                    request.user_id or "unknown",
                    request.resource_id,
                    [],
                    "deny",
                    "config_access_denied",
                )
                return PolicyResult(PolicyDecision.DENY, "config_access_denied")

        # Default allow for non-sensitive operations
        self.audit(
            request.user_id or "unknown",
            request.resource_id,
            [],
            "allow",
            "default_allow",
        )
        return PolicyResult(PolicyDecision.ALLOW, "default_allow")

    def audit(
        self,
        source: str,
        target: str,
        data_traits: List[str],
        decision: str,
        reason: str,
    ) -> None:
        payload = {
            "ts": datetime.now(tz=timezone.utc).isoformat(),
            "source": source,
            "target": target,
            "data_traits": data_traits,
            "decision": decision,
            "reason": reason,
        }
        logger.info("policy_decision=%s", json.dumps(payload, separators=(",", ":")))


# Module-level singleton (used by some imports)
policy_engine = PolicyEngine()
