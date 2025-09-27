"""Security validator for plugin manifests and operations."""

import re
import ipaddress
from typing import List, Dict, Any, Tuple, Set, Optional
from urllib.parse import urlparse
import logging

from .models import PluginManifest, PluginSecurity
from core.policy.traits import trait_validator

logger = logging.getLogger(__name__)


class SecurityValidator:
    """Validates plugin security configurations and operations."""

    def __init__(self):
        """Initialize security validator."""
        self.blocked_domains = self._load_blocked_domains()
        self.dangerous_traits = {"admin", "system", "root"}
        self.phi_sensitive_traits = {"handles_phi", "hipaa_authorized"}
        self.required_security_configs = [
            "authentication_required",
            "network_isolation",
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
        errors = []

        try:
            # Validate basic security configuration
            security_errors = self._validate_security_config(manifest.security)
            errors.extend(security_errors)

            # Validate traits
            trait_errors = self._validate_traits(manifest.traits)
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
            resource_errors = self._validate_resource_limits(manifest.resources)
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

    def _validate_security_config(self, security: PluginSecurity) -> List[str]:
        """Validate security configuration."""
        errors = []

        # Authentication must be required
        if not security.authentication_required:
            errors.append("Authentication must be required for all plugins")

        # Network isolation should be enabled by default
        if not security.network_isolation:
            logger.warning("Network isolation is disabled - ensure this is intentional")

        # Check data classification
        if not security.data_classification:
            # This is optional but recommended
            pass

        # Validate resource limits if specified
        if security.resource_limits:
            if "memory_mb" in security.resource_limits:
                memory = security.resource_limits["memory_mb"]
                if memory > 4096:  # 4GB limit
                    errors.append("Memory limit exceeds maximum allowed (4GB)")

            if "cpu_cores" in security.resource_limits:
                cpu = security.resource_limits["cpu_cores"]
                if cpu > 4:  # 4 core limit
                    errors.append("CPU limit exceeds maximum allowed (4 cores)")

        return errors

    def _validate_traits(self, traits: List[str]) -> List[str]:
        """Validate plugin traits."""
        errors = []

        # Check for dangerous traits
        dangerous_found = self.dangerous_traits.intersection(set(traits))
        if dangerous_found:
            errors.append(f"Dangerous traits not allowed: {list(dangerous_found)}")

        # Validate trait combinations
        is_valid, trait_errors = trait_validator.validate_trait_combination(traits)
        if not is_valid:
            errors.extend(trait_errors)

        # Check for unknown traits
        for trait in traits:
            if not trait_validator.registry.get_trait(trait):
                errors.append(f"Unknown trait: {trait}")

        return errors

    def _validate_trait_consistency(self, manifest: PluginManifest) -> List[str]:
        """Validate consistency between traits and security configuration."""
        errors = []

        traits = set(manifest.traits)
        security = manifest.security

        # PHI handling requirements
        if "handles_phi" in traits:
            if "phi" not in security.data_classification:
                errors.append(
                    "Plugin with handles_phi trait must declare 'phi' in data_classification"
                )

            if manifest.compliance.audit_level not in ["detailed", "comprehensive"]:
                errors.append(
                    "PHI handling plugins require detailed or comprehensive audit level"
                )

            if not manifest.compliance.encryption_required:
                errors.append("PHI handling plugins must require encryption")

        # PII handling requirements
        if "handles_pii" in traits:
            if "pii" not in security.data_classification:
                errors.append(
                    "Plugin with handles_pii trait must declare 'pii' in data_classification"
                )

        # External service requirements
        if "external_service" in traits:
            if not security.allowed_domains:
                errors.append("External service plugins must specify allowed domains")

        return errors

    def _validate_network_security(self, security: PluginSecurity) -> List[str]:
        """Validate network security configuration."""
        errors = []

        for domain in security.allowed_domains:
            # Check against blocked domains
            if self._is_blocked_domain(domain):
                errors.append(f"Domain '{domain}' is blocked for security reasons")

            # Check for suspicious patterns
            if self._is_suspicious_domain(domain):
                errors.append(f"Domain '{domain}' appears suspicious")

            # Validate domain format (already done in model, but double-check)
            if not self._is_valid_domain(domain):
                errors.append(f"Invalid domain format: {domain}")

        return errors

    def _validate_compliance(self, manifest: PluginManifest) -> List[str]:
        """Validate compliance configuration."""
        errors = []

        compliance = manifest.compliance

        # HIPAA controls validation
        if "handles_phi" in manifest.traits:
            if not compliance.hipaa_controls:
                errors.append("PHI handling plugins must specify HIPAA controls")

            # Validate HIPAA control format
            valid_control_pattern = re.compile(r"^\d{3}\.\d{3}\([a-z]\)(\(\d+\))?$")
            for control in compliance.hipaa_controls:
                if not valid_control_pattern.match(control):
                    errors.append(f"Invalid HIPAA control format: {control}")

        # Data retention validation
        if compliance.data_retention_days < 2555:  # 7 years for HIPAA
            if "handles_phi" in manifest.traits:
                errors.append(
                    "PHI handling plugins must retain data for at least 7 years (2555 days)"
                )

        return errors

    def _validate_resource_limits(self, resources: Dict[str, Any]) -> List[str]:
        """Validate resource limit specifications."""
        errors = []

        if not resources:
            # Resource limits are optional but recommended
            return errors

        # Memory limits
        if "memory_limit" in resources:
            try:
                memory = int(resources["memory_limit"])
                if memory < 64:  # Minimum 64MB
                    errors.append("Memory limit too low (minimum 64MB)")
                elif memory > 8192:  # Maximum 8GB
                    errors.append("Memory limit too high (maximum 8GB)")
            except (ValueError, TypeError):
                errors.append("Invalid memory limit format")

        # CPU limits
        if "cpu_limit" in resources:
            try:
                cpu = float(resources["cpu_limit"])
                if cpu < 0.1:  # Minimum 0.1 core
                    errors.append("CPU limit too low (minimum 0.1 core)")
                elif cpu > 8.0:  # Maximum 8 cores
                    errors.append("CPU limit too high (maximum 8 cores)")
            except (ValueError, TypeError):
                errors.append("Invalid CPU limit format")

        return errors

    def _validate_dependencies(self, dependencies: List[str]) -> List[str]:
        """Validate plugin dependencies."""
        errors = []

        for dependency in dependencies:
            # Check for circular dependencies (would need registry access)
            # For now, just validate format
            if not re.match(r"^[a-z0-9-]+$", dependency):
                errors.append(f"Invalid dependency format: {dependency}")

        return errors

    def _is_blocked_domain(self, domain: str) -> bool:
        """Check if domain is in blocked list."""
        return domain.lower() in self.blocked_domains

    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check for suspicious domain patterns."""
        suspicious_patterns = [
            r".*\.onion$",  # Tor domains
            r".*\.bit$",  # Namecoin domains
            r".*localhost.*",  # Localhost variants
            r".*127\.0\.0\.1.*",  # Loopback
            r".*192\.168\..*",  # Private networks
            r".*10\..*",  # Private networks
            r".*172\.1[6-9]\..*",  # Private networks
            r".*172\.2[0-9]\..*",  # Private networks
            r".*172\.3[0-1]\..*",  # Private networks
        ]

        for pattern in suspicious_patterns:
            if re.match(pattern, domain, re.IGNORECASE):
                return True

        return False

    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format."""
        # Basic domain validation
        domain_pattern = re.compile(
            r"^[a-zA-Z0-9]"
            r"([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
            r"(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$"
        )

        if not domain_pattern.match(domain):
            return False

        # Additional checks
        if len(domain) > 253:  # Maximum domain length
            return False

        if domain.startswith("-") or domain.endswith("-"):
            return False

        if ".." in domain:  # No consecutive dots
            return False

        return True

    def _load_blocked_domains(self) -> Set[str]:
        """Load blocked domains list."""
        # In production, this could be loaded from a file or database
        return {
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "example.com",
            "test.com",
            "malware.com",
            "phishing.com",
            # Add more blocked domains as needed
        }

    def validate_plugin_operation(
        self,
        plugin_id: str,
        operation: str,
        target: Optional[str] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, str]:
        """
        Validate a plugin operation at runtime.

        Args:
            plugin_id: ID of plugin performing operation
            operation: Type of operation (read, write, delete, etc.)
            target: Target resource or service
            data: Data being processed

        Returns:
            Tuple of (is_allowed, reason)
        """
        try:
            # Check if operation is allowed for this plugin type
            # This would integrate with the policy engine

            # For now, basic validation
            if operation in ["delete", "admin"]:
                return False, f"Operation '{operation}' not allowed for plugins"

            if target and self._is_sensitive_target(target):
                return False, f"Access to sensitive target '{target}' not allowed"

            if data and self._contains_malicious_content(data):
                return False, "Malicious content detected in data"

            return True, "Operation allowed"

        except Exception as e:
            logger.error(f"Error validating plugin operation: {e}")
            return False, "Validation error occurred"

    def _is_sensitive_target(self, target: str) -> bool:
        """Check if target is sensitive."""
        sensitive_patterns = [
            r"/etc/.*",
            r"/root/.*",
            r"/home/.*/.ssh/.*",
            r".*password.*",
            r".*secret.*",
            r".*key.*",
        ]

        for pattern in sensitive_patterns:
            if re.match(pattern, target, re.IGNORECASE):
                return True

        return False

    def _contains_malicious_content(self, data: Dict[str, Any]) -> bool:
        """Basic check for malicious content."""
        # Convert data to string for pattern matching
        data_str = str(data).lower()

        malicious_patterns = [
            r"<script.*?>.*?</script>",  # Script tags
            r"javascript:",  # JavaScript URLs
            r"eval\s*\(",  # Eval calls
            r"exec\s*\(",  # Exec calls
            r"\.\./\.\.",  # Directory traversal
            r"rm\s+-rf",  # Dangerous commands
            r"DROP\s+TABLE",  # SQL injection
        ]

        for pattern in malicious_patterns:
            if re.search(pattern, data_str, re.IGNORECASE | re.DOTALL):
                return True

        return False
