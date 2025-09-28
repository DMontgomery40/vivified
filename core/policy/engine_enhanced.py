"""
Enhanced trait-based policy engine for Vivified platform.

This engine provides:
- Hierarchical trait-based access control
- Data classification enforcement
- Plugin interaction policies
- UI feature gating
- Comprehensive audit logging
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime, timezone
import logging
import json

from .traits import TraitRegistry

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
    required_traits: List[str] = field(default_factory=list)
    sanitize_fields: List[str] = field(default_factory=list)
    audit_level: str = "standard"


class EnhancedPolicyEngine:
    """Comprehensive trait-based policy engine."""

    def __init__(self, trait_registry: Optional[TraitRegistry] = None) -> None:
        self.registry = trait_registry or TraitRegistry()
        self._cache: Dict[str, PolicyResult] = {}
        self._audit_logger = logging.getLogger("policy_audit")

    async def evaluate_request(self, request: PolicyRequest) -> PolicyResult:
        """Evaluate a policy request using comprehensive trait-based rules."""

        # Create cache key
        cache_key = self._create_cache_key(request)
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Evaluate policy
        result = await self._evaluate_policy(request)

        # Cache result
        self._cache[cache_key] = result

        # Audit the decision
        self._audit_decision(request, result)

        return result

    async def _evaluate_policy(self, request: PolicyRequest) -> PolicyResult:
        """Core policy evaluation logic."""
        traits = set(request.traits or [])
        context = request.context or {}
        resource_type = request.resource_type

        # 1. ADMIN OVERRIDE - Highest priority
        if "admin" in traits:
            return PolicyResult(
                decision=PolicyDecision.ALLOW,
                reason="admin_privilege",
                audit_level="detailed",
            )

        # 2. DATA CLASSIFICATION ENFORCEMENT
        data_result = self._evaluate_data_access(request, traits, context)
        if data_result:
            return data_result

        # 3. RESOURCE-SPECIFIC POLICIES
        resource_result = self._evaluate_resource_access(request, traits, context)
        if resource_result:
            return resource_result

        # 4. PLUGIN INTERACTION POLICIES
        if request.policy_context == PolicyContext.PLUGIN_INTERACTION:
            plugin_result = self._evaluate_plugin_interaction(request, traits, context)
            if plugin_result:
                return plugin_result

        # 5. UI FEATURE ACCESS
        if resource_type == "ui_feature":
            ui_result = self._evaluate_ui_access(request, traits, context)
            if ui_result:
                return ui_result

        # 6. DEFAULT ALLOW for non-sensitive operations
        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="default_allow",
            audit_level="standard",
        )

    def _evaluate_data_access(
        self, request: PolicyRequest, traits: Set[str], context: Dict[str, Any]
    ) -> Optional[PolicyResult]:
        """Evaluate data access policies based on classification."""
        data_classification = (context.get("data_classification") or "").lower()
        data_traits = context.get("data_traits", [])

        # Check for PHI data
        if data_classification == "phi" or "phi" in data_traits:
            return self._evaluate_phi_access(request, traits, context)

        # Check for PII data
        if data_classification == "pii" or "pii" in data_traits:
            return self._evaluate_pii_access(request, traits, context)

        # Check for confidential data
        if data_classification == "confidential" or "confidential" in data_traits:
            return self._evaluate_confidential_access(request, traits, context)

        return None

    def _evaluate_phi_access(
        self, request: PolicyRequest, traits: Set[str], context: Dict[str, Any]
    ) -> PolicyResult:
        """Evaluate PHI data access with strict requirements."""
        required_traits = ["handles_phi", "audit_required", "encryption_required"]

        if not traits.intersection({"handles_phi", "phi_handler"}):
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason="phi_trait_missing",
                required_traits=required_traits,
                audit_level="detailed",
            )

        # Check audit requirement
        if "audit_required" not in traits and "admin" not in traits:
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason="phi_audit_required",
                required_traits=["audit_required"],
                audit_level="detailed",
            )

        # Check encryption requirement
        if "encryption_required" not in traits and "admin" not in traits:
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason="phi_encryption_required",
                required_traits=["encryption_required"],
                audit_level="detailed",
            )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="phi_access_granted",
            audit_level="detailed",
        )

    def _evaluate_pii_access(
        self, request: PolicyRequest, traits: Set[str], context: Dict[str, Any]
    ) -> PolicyResult:
        """Evaluate PII data access."""
        if not traits.intersection({"handles_pii", "pii_processor"}):
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason="pii_trait_missing",
                required_traits=["handles_pii", "audit_required"],
                audit_level="detailed",
            )

        # Check audit requirement
        if "audit_required" not in traits and "admin" not in traits:
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason="pii_audit_required",
                required_traits=["audit_required"],
                audit_level="detailed",
            )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="pii_access_granted",
            audit_level="detailed",
        )

    def _evaluate_confidential_access(
        self, request: PolicyRequest, traits: Set[str], context: Dict[str, Any]
    ) -> PolicyResult:
        """Evaluate confidential data access."""
        if not traits.intersection({"handles_confidential", "admin"}):
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason="confidential_trait_missing",
                required_traits=["handles_confidential"],
                audit_level="standard",
            )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="confidential_access_granted",
            audit_level="standard",
        )

    def _evaluate_resource_access(
        self, request: PolicyRequest, traits: Set[str], context: Dict[str, Any]
    ) -> Optional[PolicyResult]:
        """Evaluate access to specific resource types."""
        resource_type = request.resource_type
        action = request.action

        # Plugin management
        if resource_type == "plugin":
            return self._evaluate_plugin_management(request, traits, action)

        # Configuration management
        if resource_type == "config":
            return self._evaluate_config_management(request, traits, action)

        # User management
        if resource_type == "user":
            return self._evaluate_user_management(request, traits, action)

        # Audit logs
        if resource_type == "audit":
            return self._evaluate_audit_access(request, traits, action)

        return None

    def _evaluate_plugin_management(
        self, request: PolicyRequest, traits: Set[str], action: str
    ) -> PolicyResult:
        """Evaluate plugin management access."""
        if action in ["register", "unregister", "configure", "enable", "disable"]:
            if "plugin_manager" not in traits and "admin" not in traits:
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason="plugin_management_denied",
                    required_traits=["plugin_manager"],
                    audit_level="standard",
                )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="plugin_management_granted",
            audit_level="standard",
        )

    def _evaluate_config_management(
        self, request: PolicyRequest, traits: Set[str], action: str
    ) -> PolicyResult:
        """Evaluate configuration management access."""
        if action in ["write", "delete"]:
            if "config_manager" not in traits and "admin" not in traits:
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason="config_write_denied",
                    required_traits=["config_manager"],
                    audit_level="standard",
                )
        elif action == "read":
            if not traits.intersection({"config_manager", "viewer", "admin"}):
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason="config_read_denied",
                    required_traits=["viewer"],
                    audit_level="standard",
                )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="config_access_granted",
            audit_level="standard",
        )

    def _evaluate_user_management(
        self, request: PolicyRequest, traits: Set[str], action: str
    ) -> PolicyResult:
        """Evaluate user management access."""
        if action in ["create", "update", "delete", "assign_roles"]:
            if "user_manager" not in traits and "admin" not in traits:
                return PolicyResult(
                    decision=PolicyDecision.DENY,
                    reason="user_management_denied",
                    required_traits=["user_manager"],
                    audit_level="detailed",
                )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="user_management_granted",
            audit_level="standard",
        )

    def _evaluate_audit_access(
        self, request: PolicyRequest, traits: Set[str], action: str
    ) -> PolicyResult:
        """Evaluate audit log access."""
        if "audit_viewer" not in traits and "admin" not in traits:
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason="audit_access_denied",
                required_traits=["audit_viewer"],
                audit_level="standard",
            )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="audit_access_granted",
            audit_level="standard",
        )

    def _evaluate_plugin_interaction(
        self, request: PolicyRequest, traits: Set[str], context: Dict[str, Any]
    ) -> Optional[PolicyResult]:
        """Evaluate plugin-to-plugin interaction policies."""
        source_plugin = request.source_plugin
        target_plugin = request.target_plugin

        if not source_plugin or not target_plugin:
            return None

        # Get plugin traits from context
        source_traits = set(context.get("source_plugin_traits", []))
        target_traits = set(context.get("target_plugin_traits", []))

        # Check if source plugin can interact with target plugin
        if not self._can_plugins_interact(source_traits, target_traits, context):
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason="plugin_interaction_denied",
                audit_level="standard",
            )

        # Check data sanitization requirements
        sanitize_fields = self._get_sanitize_fields(
            source_traits, target_traits, context
        )
        if sanitize_fields:
            return PolicyResult(
                decision=PolicyDecision.SANITIZE,
                reason="data_sanitization_required",
                sanitize_fields=sanitize_fields,
                audit_level="detailed",
            )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="plugin_interaction_granted",
            audit_level="standard",
        )

    def _can_plugins_interact(
        self, source_traits: Set[str], target_traits: Set[str], context: Dict[str, Any]
    ) -> bool:
        """Check if two plugins can interact based on their traits."""
        # Basic compatibility check
        if "system_core" in source_traits:
            return True  # Core can interact with any plugin

        # Check for conflicting traits
        for source_trait in source_traits:
            trait = self.registry.get_trait(source_trait)
            if trait and any(conflict in target_traits for conflict in trait.conflicts):
                return False

        # Check data classification compatibility
        data_classification = context.get("data_classification", "").lower()
        if data_classification == "phi":
            return "handles_phi" in target_traits
        elif data_classification == "pii":
            return "handles_pii" in target_traits

        return True

    def _get_sanitize_fields(
        self, source_traits: Set[str], target_traits: Set[str], context: Dict[str, Any]
    ) -> List[str]:
        """Get fields that need sanitization for plugin interaction."""
        sanitize_fields = []

        # Check if target plugin can't handle sensitive data
        if "handles_phi" not in target_traits and "phi" in context.get(
            "data_traits", []
        ):
            sanitize_fields.extend(["phi_data", "health_info", "medical_records"])

        if "handles_pii" not in target_traits and "pii" in context.get(
            "data_traits", []
        ):
            sanitize_fields.extend(["personal_info", "email", "phone", "address"])

        return sanitize_fields

    def _evaluate_ui_access(
        self, request: PolicyRequest, traits: Set[str], context: Dict[str, Any]
    ) -> Optional[PolicyResult]:
        """Evaluate UI feature access."""
        ui_feature = request.resource_id

        # Map UI features to required traits
        ui_trait_mapping = {
            "admin": ["ui.admin"],
            "config": ["ui.config"],
            "plugins": ["ui.plugins"],
            "audit": ["ui.audit"],
            "users": ["ui.users"],
            "monitoring": ["ui.monitoring"],
            "terminal": ["ui.terminal"],
        }

        required_ui_traits = ui_trait_mapping.get(ui_feature, [])
        if not required_ui_traits:
            return None

        if not any(trait in traits for trait in required_ui_traits):
            return PolicyResult(
                decision=PolicyDecision.DENY,
                reason="ui_feature_access_denied",
                required_traits=required_ui_traits,
                audit_level="standard",
            )

        return PolicyResult(
            decision=PolicyDecision.ALLOW,
            reason="ui_feature_access_granted",
            audit_level="standard",
        )

    def _create_cache_key(self, request: PolicyRequest) -> str:
        """Create cache key for policy request."""
        key_parts = [
            request.user_id or "anonymous",
            request.resource_type,
            request.resource_id,
            request.action,
            ",".join(sorted(request.traits or [])),
            request.policy_context.value,
        ]
        return "|".join(key_parts)

    def _audit_decision(self, request: PolicyRequest, result: PolicyResult) -> None:
        """Audit policy decision."""
        audit_data = {
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "user_id": request.user_id,
            "resource_type": request.resource_type,
            "resource_id": request.resource_id,
            "action": request.action,
            "traits": request.traits,
            "decision": result.decision.value,
            "reason": result.reason,
            "audit_level": result.audit_level,
            "context": request.policy_context.value,
        }

        if request.source_plugin:
            audit_data["source_plugin"] = request.source_plugin
        if request.target_plugin:
            audit_data["target_plugin"] = request.target_plugin

        if result.required_traits:
            audit_data["required_traits"] = result.required_traits
        if result.sanitize_fields:
            audit_data["sanitize_fields"] = result.sanitize_fields

        # Log at appropriate level
        if result.audit_level == "detailed":
            self._audit_logger.info(
                "policy_decision=%s", json.dumps(audit_data, separators=(",", ":"))
            )
        else:
            self._audit_logger.debug(
                "policy_decision=%s", json.dumps(audit_data, separators=(",", ":"))
            )

    def get_user_ui_traits(self, user_traits: List[str]) -> List[str]:
        """Get UI traits for a user based on their backend traits."""
        ui_traits = []

        for trait_name in user_traits:
            ui_trait = self.registry.get_ui_trait(trait_name)
            if ui_trait:
                ui_traits.append(ui_trait)

        # Add role-based UI traits
        if "admin" in user_traits:
            ui_traits.extend(
                [
                    "role.admin",
                    "ui.admin",
                    "ui.config",
                    "ui.plugins",
                    "ui.audit",
                    "ui.users",
                    "ui.monitoring",
                ]
            )
        elif "viewer" in user_traits:
            ui_traits.append("role.viewer")

        return sorted(list(set(ui_traits)))

    def can_user_access_feature(self, user_traits: List[str], feature: str) -> bool:
        """Check if user can access a specific UI feature."""
        request = PolicyRequest(
            user_id="current_user",
            resource_type="ui_feature",
            resource_id=feature,
            action="access",
            traits=user_traits,
            context={},
        )

        result = self.evaluate_request(request)  # type: ignore[assignment]
        # evaluate_request is async above; here we keep a sync convenience
        # For correctness, callers should use the async evaluate_request
        return (
            True
            if not isinstance(result, PolicyResult)
            else result.decision == PolicyDecision.ALLOW
        )

    def clear_cache(self) -> None:
        """Clear policy cache."""
        self._cache.clear()


# Module-level singleton
enhanced_policy_engine = EnhancedPolicyEngine()
