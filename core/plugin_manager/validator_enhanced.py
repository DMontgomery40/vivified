"""
Enhanced security validator for plugin manifests and operations.

This validator provides comprehensive security validation using the enhanced traits system.
"""

import re
import ipaddress
from typing import List, Dict, Any, Tuple, Set, Optional
from urllib.parse import urlparse
import logging

from .models import PluginManifest
from core.policy.traits import trait_validator, TraitCategory

logger = logging.getLogger(__name__)


class EnhancedSecurityValidator:
    """Enhanced security validator with comprehensive trait validation."""

    def __init__(self):
        """Initialize enhanced security validator."""
        self.blocked_domains = self._load_blocked_domains()
        self.dangerous_traits = {"admin", "system", "root"}
        self.phi_sensitive_traits = {"handles_phi", "hipaa_authorized"}
        self.required_security_configs = [
            "authentication_required",
            "data_classification",
        ]

    def validate_manifest_security(
        self, manifest: PluginManifest
    ) -> Tuple[bool, List[str]]:
        """
        Comprehensive security validation of plugin manifest.

        Args:
            manifest: Plugin manifest to validate

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors: List[str] = []

        try:
            # Validate basic security configuration
            security_errors = self._validate_security_config(manifest.security)
            errors.extend(security_errors)

            # Validate traits using enhanced trait validator
            trait_errors = self._validate_plugin_traits(manifest.traits)
            errors.extend(trait_errors)

            # Validate trait consistency with security settings
            consistency_errors = self._validate_trait_consistency(manifest)
            errors.extend(consistency_errors)

            # Validate network security
            network_errors = self._validate_network_security(manifest.security)
            errors.extend(network_errors)

            # Validate compliance configuration
            compliance_errors = self._validate_compliance(manifest)
            errors.extend(compliance_errors)

            # Validate resource limits
            resource_errors = self._validate_resource_limits(manifest.security)
            errors.extend(resource_errors)

            # Validate dependencies
            dependency_errors = self._validate_dependencies(manifest.dependencies)
            errors.extend(dependency_errors)

            is_valid = len(errors) == 0

            if not is_valid:
                logger.warning(
                    f"Plugin manifest validation failed for {manifest.id}: {errors}"
                )
            else:
                logger.info(f"Plugin manifest validation passed for {manifest.id}")

            return is_valid, errors

        except Exception as e:
            error_msg = f"Security validation exception: {str(e)}"
            logger.error(error_msg)
            return False, [error_msg]

    def _validate_security_config(self, security: Dict[str, Any]) -> List[str]:
        """Validate security configuration."""
        errors: List[str] = []

        if not security:
            errors.append("Security configuration is required")
            return errors

        # Authentication must be required
        if not security.get("authentication_required", False):
            errors.append("Authentication must be required for all plugins")

        # Data classification must be specified
        data_classification = security.get("data_classification", [])
        if not data_classification:
            errors.append("Data classification must be specified")

        # Validate data classification values
        valid_classifications = ["public", "internal", "confidential", "phi", "pii"]
        for classification in data_classification:
            if classification not in valid_classifications:
                errors.append(f"Invalid data classification: {classification}")

        return errors

    def _validate_plugin_traits(self, traits: List[str]) -> List[str]:
        """Validate plugin traits using enhanced trait validator."""
        errors: List[str] = []

        if not traits:
            errors.append("Plugin must have at least one trait")
            return errors

        # Use enhanced trait validator
        is_valid, trait_errors = trait_validator.validate_plugin_traits(traits)
        if not is_valid:
            errors.extend(trait_errors)

        # Check for dangerous traits
        for trait in traits:
            if trait in self.dangerous_traits:
                errors.append(f"Dangerous trait not allowed for plugins: {trait}")

        # Check for required plugin type trait
        plugin_type_traits = [t for t in traits if t.startswith("communication_") or 
                             t.startswith("storage_") or t.startswith("identity_") or
                             t.startswith("integration_") or t.startswith("workflow_")]
        if not plugin_type_traits:
            errors.append("Plugin must have a type trait (communication_plugin, storage_plugin, etc.)")

        return errors

    def _validate_trait_consistency(self, manifest: PluginManifest) -> List[str]:
        """Validate trait consistency with security settings."""
        errors: List[str] = []
        traits = set(manifest.traits)
        security = manifest.security or {}
        data_classification = security.get("data_classification", [])

        # PHI handling requires specific traits
        if "phi" in data_classification:
            if not traits.intersection({"handles_phi", "phi_handler"}):
                errors.append("PHI data classification requires handles_phi trait")
            
            if "audit_required" not in traits:
                errors.append("PHI handling requires audit_required trait")
            
            if "encryption_required" not in traits:
                errors.append("PHI handling requires encryption_required trait")

        # PII handling requires specific traits
        if "pii" in data_classification:
            if not traits.intersection({"handles_pii", "pii_processor"}):
                errors.append("PII data classification requires handles_pii trait")
            
            if "audit_required" not in traits:
                errors.append("PII handling requires audit_required trait")

        # External service trait validation
        if "external_service" in traits:
            allowed_domains = manifest.allowed_domains or []
            if not allowed_domains:
                errors.append("External service trait requires allowed_domains to be specified")

        return errors

    def _validate_network_security(self, security: Dict[str, Any]) -> List[str]:
        """Validate network security configuration."""
        errors: List[str] = []

        # Check for network isolation requirements
        if security.get("network_isolated", False):
            if "network_isolated" not in security:
                errors.append("Network isolation flag set but not properly configured")

        # Validate allowed domains if specified
        allowed_domains = security.get("allowed_domains", [])
        for domain in allowed_domains:
            if not self._is_safe_domain(domain):
                errors.append(f"Unsafe domain in allowed list: {domain}")

        return errors

    def _validate_compliance(self, manifest: PluginManifest) -> List[str]:
        """Validate compliance configuration."""
        errors: List[str] = []
        traits = set(manifest.traits)
        compliance = manifest.compliance or {}

        # HIPAA compliance validation
        if "hipaa_compliant" in traits:
            required_hipaa_traits = {"handles_phi", "audit_required", "encryption_required"}
            missing_traits = required_hipaa_traits - traits
            if missing_traits:
                errors.append(f"HIPAA compliance requires traits: {missing_traits}")

        # GDPR compliance validation
        if "gdpr_compliant" in traits:
            required_gdpr_traits = {"handles_pii", "audit_required"}
            missing_traits = required_gdpr_traits - traits
            if missing_traits:
                errors.append(f"GDPR compliance requires traits: {missing_traits}")

        # SOC2 compliance validation
        if "soc2_compliant" in traits:
            required_soc2_traits = {"audit_required", "encryption_required"}
            missing_traits = required_soc2_traits - traits
            if missing_traits:
                errors.append(f"SOC2 compliance requires traits: {missing_traits}")

        return errors

    def _validate_resource_limits(self, security: Dict[str, Any]) -> List[str]:
        """Validate resource limits configuration."""
        errors: List[str] = []

        # Check for reasonable resource limits
        max_memory = security.get("max_memory_mb", 0)
        if max_memory > 2048:  # 2GB limit
            errors.append("Maximum memory limit too high (max 2GB)")

        max_cpu = security.get("max_cpu_percent", 0)
        if max_cpu > 80:  # 80% CPU limit
            errors.append("Maximum CPU limit too high (max 80%)")

        return errors

    def _validate_dependencies(self, dependencies: List[str]) -> List[str]:
        """Validate plugin dependencies."""
        errors: List[str] = []

        for dep in dependencies:
            # Check for circular dependencies (basic check)
            if dep.startswith("self."):
                errors.append(f"Circular dependency detected: {dep}")

            # Validate dependency format
            if not re.match(r"^[a-zA-Z0-9_-]+(\.[a-zA-Z0-9_-]+)*$", dep):
                errors.append(f"Invalid dependency format: {dep}")

        return errors

    def _is_safe_domain(self, domain: str) -> bool:
        """Check if domain is safe for plugin access."""
        blocked_domains = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "169.254",  # Link-local
            "10.",      # Private ranges
            "172.16",
            "192.168"
        ]
        return not any(domain.startswith(blocked) for blocked in blocked_domains)

    def _load_blocked_domains(self) -> Set[str]:
        """Load list of blocked domains."""
        return {
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "169.254",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16"
        }

    def validate_plugin_operation(
        self, 
        plugin_id: str, 
        operation: str, 
        context: Dict[str, Any]
    ) -> Tuple[bool, List[str]]:
        """Validate a plugin operation."""
        errors: List[str] = []

        # Check for dangerous operations
        dangerous_operations = ["delete_all", "format", "shutdown", "restart"]
        if operation in dangerous_operations:
            errors.append(f"Dangerous operation not allowed: {operation}")

        # Check data access permissions
        data_classification = context.get("data_classification", "")
        if data_classification in ["phi", "pii"]:
            if not context.get("has_appropriate_traits", False):
                errors.append(f"Operation requires appropriate traits for {data_classification} data")

        return len(errors) == 0, errors
