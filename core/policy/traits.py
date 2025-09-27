"""
Trait registry and validator used by plugin validation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List


@dataclass
class Trait:
    name: str
    description: str = ""


class TraitRegistry:
    def __init__(self) -> None:
        self._traits: Dict[str, Trait] = {}
        self._load_defaults()

    def _load_defaults(self) -> None:
        defaults = [
            Trait("admin", "Full system administration"),
            Trait("handles_phi", "Can process Protected Health Information"),
            Trait("handles_pii", "Can process Personally Identifiable Information"),
            Trait("external_service", "Connects to external services"),
            Trait("audit_required", "All actions must be audited"),
            Trait("config_manager", "Can modify system configuration"),
            Trait("plugin_manager", "Can manage plugins"),
            Trait("viewer", "Read-only access"),
            Trait("phi_handler", "Legacy alias for PHI access"),
            Trait("pii_processor", "Legacy alias for PII access"),
        ]
        for t in defaults:
            self._traits[t.name] = t

    def get_trait(self, name: str) -> Optional[Trait]:
        return self._traits.get(name)


class TraitValidator:
    def __init__(self, registry: TraitRegistry) -> None:
        self.registry = registry

    def validate_trait_combination(self, traits: List[str]) -> Tuple[bool, List[str]]:
        errors: List[str] = []
        s = set(traits)
        # Example conflicting traits (none for now)
        # if "admin" in s and "external_guest" in s:
        #     errors.append("admin and external_guest cannot be combined")
        # Ensure unknown traits flagged
        for t in traits:
            if not self.registry.get_trait(t):
                errors.append(f"Unknown trait: {t}")
        return len(errors) == 0, errors


registry = TraitRegistry()
trait_validator = TraitValidator(registry)

