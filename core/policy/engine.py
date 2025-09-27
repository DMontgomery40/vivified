"""
Minimal trait-based policy engine for Phase 2.

This provides just enough structure to unblock storage and admin flows.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
import json

logger = logging.getLogger(__name__)


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass
class PolicyRequest:
    user_id: Optional[str]
    resource_type: str
    resource_id: str
    action: str
    traits: List[str]
    context: Dict[str, Any]


@dataclass
class PolicyResult:
    decision: PolicyDecision
    reason: str


class PolicyEngine:
    def __init__(self) -> None:
        self._cache: Dict[str, PolicyResult] = {}

    async def evaluate_request(self, request: PolicyRequest) -> PolicyResult:
        """Evaluate a policy request using simple defaults.

        Rules:
        - Default deny if sensitive classification is present and no traits.
        - PHI access requires one of: phi_handler, handles_phi, admin.
        - PII access requires one of: pii_processor, handles_pii, admin.
        - Otherwise allow.
        """
        ctx = request.context or {}
        classification = (ctx.get("data_classification") or "").lower()
        traits = set(request.traits or [])

        # Admin override
        if "admin" in traits:
            return PolicyResult(PolicyDecision.ALLOW, "admin_privilege")

        if classification == "phi":
            if traits.intersection({"phi_handler", "handles_phi"}):
                return PolicyResult(PolicyDecision.ALLOW, "phi_trait_present")
            return PolicyResult(PolicyDecision.DENY, "phi_trait_missing")

        if classification == "pii":
            if traits.intersection({"pii_processor", "handles_pii"}):
                return PolicyResult(PolicyDecision.ALLOW, "pii_trait_present")
            return PolicyResult(PolicyDecision.DENY, "pii_trait_missing")

        # Default allow for non-sensitive
        return PolicyResult(PolicyDecision.ALLOW, "default_allow")

    def audit(self, source: str, target: str, data_traits: List[str], decision: str, reason: str) -> None:
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

