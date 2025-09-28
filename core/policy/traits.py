"""
Comprehensive trait registry and validator for Vivified platform.

This module provides a complete traits-based architecture with:
- Hierarchical trait categories
- Comprehensive trait validation
- Trait compatibility checking
- UI trait mapping
- Plugin trait enforcement
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Optional, Tuple, List, Set, Any
import logging

logger = logging.getLogger(__name__)


class TraitCategory(str, Enum):
    """Categories for organizing traits."""

    ROLE = "role"  # User roles and permissions
    CAPABILITY = "capability"  # What the user/plugin can do
    DATA_ACCESS = "data_access"  # Data classification access
    UI_FEATURE = "ui_feature"  # UI elements and features
    PLUGIN_TYPE = "plugin_type"  # Plugin categories
    SECURITY = "security"  # Security-related traits
    COMPLIANCE = "compliance"  # Compliance requirements
    SYSTEM = "system"  # System-level traits


@dataclass
class Trait:
    """Represents a single trait with metadata."""

    name: str
    description: str
    category: TraitCategory
    requires: List[str] = field(default_factory=list)  # Required traits
    conflicts: List[str] = field(default_factory=list)  # Conflicting traits
    ui_label: Optional[str] = None  # Human-readable label for UI
    ui_icon: Optional[str] = None  # Icon for UI
    is_sensitive: bool = False  # Requires special handling
    is_legacy: bool = False  # Deprecated trait
    aliases: List[str] = field(default_factory=list)  # Alternative names


class TraitRegistry:
    """Central registry for all platform traits."""

    def __init__(self) -> None:
        self._traits: Dict[str, Trait] = {}
        self._categories: Dict[TraitCategory, Set[str]] = {
            cat: set() for cat in TraitCategory
        }
        self._ui_mapping: Dict[str, str] = {}  # Backend trait -> UI trait
        self._load_defaults()

    def _load_defaults(self) -> None:
        """Load all default traits for the platform."""

        # ROLE TRAITS - User roles and permissions
        role_traits = [
            Trait(
                name="admin",
                description="Full system administration access",
                category=TraitCategory.ROLE,
                ui_label="Administrator",
                ui_icon="admin_panel_settings",
                is_sensitive=True,
            ),
            Trait(
                name="viewer",
                description="Read-only access to system resources",
                category=TraitCategory.ROLE,
                ui_label="Viewer",
                ui_icon="visibility",
            ),
            Trait(
                name="developer",
                description="Plugin development and testing access",
                category=TraitCategory.ROLE,
                ui_label="Developer",
                ui_icon="code",
                requires=["viewer"],
            ),
            Trait(
                name="operator",
                description="System operations and monitoring",
                category=TraitCategory.ROLE,
                ui_label="Operator",
                ui_icon="settings",
                requires=["viewer"],
            ),
        ]

        # CAPABILITY TRAITS - What users/plugins can do
        capability_traits = [
            Trait(
                name="config_manager",
                description="Can modify system configuration",
                category=TraitCategory.CAPABILITY,
                ui_label="Configuration Manager",
                ui_icon="tune",
                requires=["admin"],
            ),
            Trait(
                name="plugin_manager",
                description="Can manage plugins and extensions",
                category=TraitCategory.CAPABILITY,
                ui_label="Plugin Manager",
                ui_icon="extension",
                requires=["admin"],
            ),
            Trait(
                name="user_manager",
                description="Can manage users and roles",
                category=TraitCategory.CAPABILITY,
                ui_label="User Manager",
                ui_icon="people",
                requires=["admin"],
            ),
            Trait(
                name="audit_viewer",
                description="Can view audit logs and system events",
                category=TraitCategory.CAPABILITY,
                ui_label="Audit Viewer",
                ui_icon="description",
                requires=["admin", "operator"],
            ),
            Trait(
                name="system_monitor",
                description="Can monitor system health and metrics",
                category=TraitCategory.CAPABILITY,
                ui_label="System Monitor",
                ui_icon="monitor",
                requires=["operator"],
            ),
        ]

        # DATA ACCESS TRAITS - Data classification access
        data_access_traits = [
            Trait(
                name="handles_phi",
                description="Can process Protected Health Information",
                category=TraitCategory.DATA_ACCESS,
                ui_label="PHI Handler",
                ui_icon="health_and_safety",
                is_sensitive=True,
                requires=["audit_required"],
            ),
            Trait(
                name="handles_pii",
                description="Can process Personally Identifiable Information",
                category=TraitCategory.DATA_ACCESS,
                ui_label="PII Handler",
                ui_icon="person",
                is_sensitive=True,
                requires=["audit_required"],
            ),
            Trait(
                name="handles_confidential",
                description="Can process confidential business data",
                category=TraitCategory.DATA_ACCESS,
                ui_label="Confidential Data Handler",
                ui_icon="lock",
                is_sensitive=True,
            ),
            Trait(
                name="handles_public",
                description="Can process public data only",
                category=TraitCategory.DATA_ACCESS,
                ui_label="Public Data Handler",
                ui_icon="public",
            ),
        ]

        # UI FEATURE TRAITS - UI elements and features
        ui_feature_traits = [
            Trait(
                name="ui.admin",
                description="Access to admin interface",
                category=TraitCategory.UI_FEATURE,
                ui_label="Admin UI",
                ui_icon="admin_panel_settings",
                requires=["admin"],
            ),
            Trait(
                name="ui.config",
                description="Access to configuration interface",
                category=TraitCategory.UI_FEATURE,
                ui_label="Configuration UI",
                ui_icon="tune",
                requires=["config_manager"],
            ),
            Trait(
                name="ui.plugins",
                description="Access to plugin management interface",
                category=TraitCategory.UI_FEATURE,
                ui_label="Plugin Management UI",
                ui_icon="extension",
                requires=["plugin_manager"],
            ),
            Trait(
                name="ui.audit",
                description="Access to audit log interface",
                category=TraitCategory.UI_FEATURE,
                ui_label="Audit UI",
                ui_icon="description",
                requires=["audit_viewer"],
            ),
            Trait(
                name="ui.users",
                description="Access to user management interface",
                category=TraitCategory.UI_FEATURE,
                ui_label="User Management UI",
                ui_icon="people",
                requires=["user_manager"],
            ),
            Trait(
                name="ui.monitoring",
                description="Access to monitoring and diagnostics",
                category=TraitCategory.UI_FEATURE,
                ui_label="Monitoring UI",
                ui_icon="monitor",
                requires=["system_monitor"],
            ),
            Trait(
                name="ui.terminal",
                description="Access to system terminal",
                category=TraitCategory.UI_FEATURE,
                ui_label="Terminal Access",
                ui_icon="terminal",
                requires=["admin", "developer"],
            ),
        ]

        # PLUGIN TYPE TRAITS - Plugin categories
        plugin_type_traits = [
            Trait(
                name="communication_plugin",
                description="Handles communication (email, SMS, etc.)",
                category=TraitCategory.PLUGIN_TYPE,
                ui_label="Communication Plugin",
                ui_icon="message",
            ),
            Trait(
                name="storage_plugin",
                description="Handles data storage and retrieval",
                category=TraitCategory.PLUGIN_TYPE,
                ui_label="Storage Plugin",
                ui_icon="storage",
            ),
            Trait(
                name="identity_plugin",
                description="Handles user identity and authentication",
                category=TraitCategory.PLUGIN_TYPE,
                ui_label="Identity Plugin",
                ui_icon="person",
            ),
            Trait(
                name="integration_plugin",
                description="Integrates with external services",
                category=TraitCategory.PLUGIN_TYPE,
                ui_label="Integration Plugin",
                ui_icon="integration_instructions",
            ),
            Trait(
                name="workflow_plugin",
                description="Handles business workflows",
                category=TraitCategory.PLUGIN_TYPE,
                ui_label="Workflow Plugin",
                ui_icon="workflow",
            ),
        ]

        # SECURITY TRAITS - Security-related capabilities
        security_traits = [
            Trait(
                name="audit_required",
                description="All actions must be audited",
                category=TraitCategory.SECURITY,
                ui_label="Audit Required",
                ui_icon="audit",
            ),
            Trait(
                name="encryption_required",
                description="Data must be encrypted",
                category=TraitCategory.SECURITY,
                ui_label="Encryption Required",
                ui_icon="lock",
            ),
            Trait(
                name="external_service",
                description="Connects to external services",
                category=TraitCategory.SECURITY,
                ui_label="External Service",
                ui_icon="cloud",
            ),
            Trait(
                name="network_isolated",
                description="Requires network isolation",
                category=TraitCategory.SECURITY,
                ui_label="Network Isolated",
                ui_icon="network_check",
            ),
        ]

        # COMPLIANCE TRAITS - Compliance requirements
        compliance_traits = [
            Trait(
                name="hipaa_compliant",
                description="HIPAA compliance required",
                category=TraitCategory.COMPLIANCE,
                ui_label="HIPAA Compliant",
                ui_icon="health_and_safety",
                requires=["handles_phi", "audit_required", "encryption_required"],
            ),
            Trait(
                name="gdpr_compliant",
                description="GDPR compliance required",
                category=TraitCategory.COMPLIANCE,
                ui_label="GDPR Compliant",
                ui_icon="gavel",
                requires=["handles_pii", "audit_required"],
            ),
            Trait(
                name="soc2_compliant",
                description="SOC2 compliance required",
                category=TraitCategory.COMPLIANCE,
                ui_label="SOC2 Compliant",
                ui_icon="security",
                requires=["audit_required", "encryption_required"],
            ),
        ]

        # SYSTEM TRAITS - System-level traits
        system_traits = [
            Trait(
                name="system_core",
                description="Core system component",
                category=TraitCategory.SYSTEM,
                ui_label="Core System",
                ui_icon="settings",
            ),
            Trait(
                name="system_plugin",
                description="Plugin component",
                category=TraitCategory.SYSTEM,
                ui_label="Plugin",
                ui_icon="extension",
            ),
        ]

        # LEGACY TRAITS - For backward compatibility
        legacy_traits = [
            Trait(
                name="phi_handler",
                description="Legacy alias for handles_phi",
                category=TraitCategory.DATA_ACCESS,
                ui_label="PHI Handler (Legacy)",
                ui_icon="health_and_safety",
                is_legacy=True,
                aliases=["handles_phi"],
            ),
            Trait(
                name="pii_processor",
                description="Legacy alias for handles_pii",
                category=TraitCategory.DATA_ACCESS,
                ui_label="PII Processor (Legacy)",
                ui_icon="person",
                is_legacy=True,
                aliases=["handles_pii"],
            ),
        ]

        # Register all traits
        all_traits = (
            role_traits
            + capability_traits
            + data_access_traits
            + ui_feature_traits
            + plugin_type_traits
            + security_traits
            + compliance_traits
            + system_traits
            + legacy_traits
        )

        for trait in all_traits:
            self.register_trait(trait)

        # Build UI mapping
        self._build_ui_mapping()

    def register_trait(self, trait: Trait) -> None:
        """Register a new trait."""
        self._traits[trait.name] = trait
        self._categories[trait.category].add(trait.name)

        # Register aliases
        for alias in trait.aliases:
            self._traits[alias] = trait

    def get_trait(self, name: str) -> Optional[Trait]:
        """Get a trait by name."""
        return self._traits.get(name)

    def get_traits_by_category(self, category: TraitCategory) -> List[Trait]:
        """Get all traits in a category."""
        return [
            self._traits[name]
            for name in self._categories[category]
            if name in self._traits
        ]

    def get_ui_trait(self, backend_trait: str) -> Optional[str]:
        """Get UI trait name for backend trait."""
        return self._ui_mapping.get(backend_trait)

    def _build_ui_mapping(self) -> None:
        """Build mapping from backend traits to UI traits."""
        # Map backend traits to UI trait names
        ui_mappings = {
            "admin": "role.admin",
            "viewer": "role.viewer",
            "developer": "role.developer",
            "operator": "role.operator",
            "config_manager": "capability.config_manager",
            "plugin_manager": "capability.plugin_manager",
            "user_manager": "capability.user_manager",
            "audit_viewer": "capability.audit_viewer",
            "system_monitor": "capability.system_monitor",
            "handles_phi": "data_access.phi",
            "handles_pii": "data_access.pii",
            "handles_confidential": "data_access.confidential",
            "handles_public": "data_access.public",
            "ui.admin": "ui.admin",
            "ui.config": "ui.config",
            "ui.plugins": "ui.plugins",
            "ui.audit": "ui.audit",
            "ui.users": "ui.users",
            "ui.monitoring": "ui.monitoring",
            "ui.terminal": "ui.terminal",
        }

        self._ui_mapping.update(ui_mappings)

    def validate_trait_combination(self, traits: List[str]) -> Tuple[bool, List[str]]:
        """Validate a combination of traits for conflicts and requirements."""
        errors: List[str] = []
        trait_set = set(traits)

        # Check each trait
        for trait_name in traits:
            trait = self.get_trait(trait_name)
            if not trait:
                errors.append(f"Unknown trait: {trait_name}")
                continue

            # Check if trait is legacy
            if trait.is_legacy:
                logger.warning(
                    f"Using legacy trait: {trait_name}, consider using: {trait.aliases}"
                )

            # Check required traits
            for required in trait.requires:
                if required not in trait_set:
                    errors.append(f"Trait '{trait_name}' requires '{required}'")

            # Check conflicting traits
            for conflict in trait.conflicts:
                if conflict in trait_set:
                    errors.append(f"Trait '{trait_name}' conflicts with '{conflict}'")

        return len(errors) == 0, errors

    def get_compatible_traits(self, base_traits: List[str]) -> List[str]:
        """Get all traits compatible with the given base traits."""
        compatible = set(base_traits)

        # Add required traits
        for trait_name in base_traits:
            trait = self.get_trait(trait_name)
            if trait:
                compatible.update(trait.requires)

        # Remove conflicting traits
        for trait_name in list(compatible):
            trait = self.get_trait(trait_name)
            if trait:
                compatible -= set(trait.conflicts)

        return list(compatible)

    def get_trait_hierarchy(self) -> Dict[str, List[str]]:
        """Get trait hierarchy showing dependencies."""
        hierarchy = {}

        for trait_name, trait in self._traits.items():
            if trait.requires:
                hierarchy[trait_name] = trait.requires

        return hierarchy


class TraitValidator:
    """Advanced trait validator with comprehensive checks."""

    def __init__(self, registry: TraitRegistry) -> None:
        self.registry = registry

    def validate_user_traits(
        self, traits: List[str], user_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, List[str]]:
        """Validate traits for a user context."""
        errors = []

        # Basic validation
        is_valid, basic_errors = self.registry.validate_trait_combination(traits)
        errors.extend(basic_errors)

        if not is_valid:
            return False, errors

        # Context-specific validation
        if user_context is not None:
            # Check for sensitive traits
            sensitive_traits = []
            for t in traits:
                trait = self.registry.get_trait(t)
                if trait and trait.is_sensitive:
                    sensitive_traits.append(t)
            if sensitive_traits and not user_context.get("admin_approved", False):
                errors.append(
                    f"Sensitive traits require admin approval: {sensitive_traits}"
                )

        return len(errors) == 0, errors

    def validate_plugin_traits(
        self, traits: List[str], plugin_context: Optional[Dict[str, Any]] = None
    ) -> Tuple[bool, List[str]]:
        """Validate traits for a plugin context."""
        errors = []

        # Basic validation
        is_valid, basic_errors = self.registry.validate_trait_combination(traits)
        errors.extend(basic_errors)

        if not is_valid:
            return False, errors

        # Plugin-specific validation
        if plugin_context is not None:
            plugin_type = plugin_context.get("type")
            if plugin_type:
                # Check if plugin has appropriate type trait
                type_traits: List[str] = []
                for t in traits:
                    trait = self.registry.get_trait(t)
                    if trait and trait.category == TraitCategory.PLUGIN_TYPE:
                        type_traits.append(t)
                if not type_traits:
                    errors.append(
                        "Plugin must have a type trait (communication_plugin, storage_plugin, etc.)"
                    )

        return len(errors) == 0, errors

    def get_required_traits_for_data_classification(
        self, classification: str
    ) -> List[str]:
        """Get required traits for handling specific data classification."""
        classification = classification.lower()

        if classification == "phi":
            return ["handles_phi", "audit_required", "encryption_required"]
        elif classification == "pii":
            return ["handles_pii", "audit_required"]
        elif classification == "confidential":
            return ["handles_confidential"]
        elif classification == "public":
            return ["handles_public"]
        else:
            return []

    def can_access_data(self, user_traits: List[str], data_classification: str) -> bool:
        """Check if user can access data with given classification."""
        required = self.get_required_traits_for_data_classification(data_classification)
        return all(trait in user_traits for trait in required) or "admin" in user_traits


# Global instances
registry = TraitRegistry()
trait_validator = TraitValidator(registry)
