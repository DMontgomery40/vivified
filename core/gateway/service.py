"""
Gateway service for external API access and proxy functionality.
"""

import logging
from typing import Dict, List, Optional, Any
from datetime import datetime

from .models import (
    ProxyRequest,
    ProxyResponse,
    DomainAllowlist,
    ProxyStats,
    ProxyMethod,
)
from .proxy import ProxyHandler
from ..audit.service import AuditService, AuditLevel
from ..policy.engine import PolicyEngine, PolicyRequest, PolicyDecision

logger = logging.getLogger(__name__)


class GatewayService:
    """Service for external API access with security and rate limiting."""

    def __init__(
        self,
        audit_service: AuditService,
        policy_engine: PolicyEngine,
        config_service: Optional[Any] = None,
    ):
        self.audit_service = audit_service
        self.policy_engine = policy_engine
        self.proxy_handler = ProxyHandler(audit_service)
        # Map of domain -> DomainAllowlist
        self.domain_allowlists: Dict[str, DomainAllowlist] = {}
        self.stats = ProxyStats()
        self._running = False
        self._config_service = config_service

    async def start(self):
        """Start the gateway service."""
        if self._running:
            return

        await self.proxy_handler.start()
        self._running = True
        logger.info("Gateway service started")

    async def stop(self):
        """Stop the gateway service."""
        if not self._running:
            return

        await self.proxy_handler.stop()
        self._running = False
        logger.info("Gateway service stopped")

    async def add_domain_allowlist(
        self,
        plugin_id: str,
        domain: str,
        allowed_methods: List[str],
        allowed_paths: Optional[List[str]] = None,
        max_requests_per_minute: int = 60,
    ) -> str:
        """Add a domain to the allowlist for a plugin."""
        try:
            # Check if plugin can add domains
            if not await self._can_manage_allowlist(plugin_id):
                raise PermissionError(
                    f"Plugin {plugin_id} not authorized to manage allowlists"
                )

            allowlist_entry = DomainAllowlist(
                plugin_id=plugin_id,
                domain=domain,
                allowed_methods=allowed_methods,
                allowed_paths=allowed_paths or [],
                max_requests_per_minute=max_requests_per_minute,
            )

            self.domain_allowlists[domain] = allowlist_entry

            await self.audit_service.log_event(
                event_type="domain_allowlist_added",
                category="gateway",
                action="add_domain",
                result="success",
                description=f"Domain {domain} added to allowlist for plugin {plugin_id}",
                plugin_id=plugin_id,
                level=AuditLevel.STANDARD,
                details={
                    "domain": domain,
                    "allowed_methods": allowed_methods,
                    "allowed_paths": allowed_paths,
                    "max_requests_per_minute": max_requests_per_minute,
                },
            )

            return allowlist_entry.id

        except Exception as e:
            logger.error(f"Failed to add domain allowlist: {e}")
            await self.audit_service.log_event(
                event_type="domain_allowlist_add_failed",
                category="gateway",
                action="add_domain",
                result="failed",
                description=f"Failed to add domain {domain} to allowlist: {str(e)}",
                plugin_id=plugin_id,
                level=AuditLevel.STANDARD,
                details={"error": str(e)},
            )
            raise

    async def remove_domain_allowlist(self, domain: str, plugin_id: str) -> bool:
        """Remove a domain from the allowlist."""
        try:
            if domain not in self.domain_allowlists:
                return False

            allowlist_entry = self.domain_allowlists[domain]

            # Check if plugin owns this allowlist entry
            if allowlist_entry.plugin_id != plugin_id:
                raise PermissionError(
                    f"Plugin {plugin_id} not authorized to remove domain {domain}"
                )

            del self.domain_allowlists[domain]

            await self.audit_service.log_event(
                event_type="domain_allowlist_removed",
                category="gateway",
                action="remove_domain",
                result="success",
                description=f"Domain {domain} removed from allowlist",
                plugin_id=plugin_id,
                level=AuditLevel.STANDARD,
                details={"domain": domain},
            )

            return True

        except Exception as e:
            logger.error(f"Failed to remove domain allowlist: {e}")
            await self.audit_service.log_event(
                event_type="domain_allowlist_remove_failed",
                category="gateway",
                action="remove_domain",
                result="failed",
                description=f"Failed to remove domain {domain}: {str(e)}",
                plugin_id=plugin_id,
                level=AuditLevel.STANDARD,
                details={"error": str(e)},
            )
            raise

    async def proxy_request(
        self,
        plugin_id: str,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        body: Optional[bytes] = None,
        timeout: int = 30,
    ) -> ProxyResponse:
        """Proxy a request to an external API."""
        try:
            # Lazy-hydrate allowlist from ConfigService if available
            await self._ensure_allowlist_loaded(plugin_id)

            # Check if plugin can make proxy requests
            if not await self._can_proxy_request(plugin_id):
                raise PermissionError(
                    f"Plugin {plugin_id} not authorized to make proxy requests"
                )

            # Create proxy request
            request = ProxyRequest(
                plugin_id=plugin_id,
                method=method,
                url=url,
                headers=headers or {},
                body=body,
                timeout=timeout,
            )

            # Handle the request
            response = await self.proxy_handler.handle_request(
                request, self.domain_allowlists
            )

            # Update stats
            self._update_stats(response)

            return response

        except Exception as e:
            logger.error(f"Proxy request failed: {e}")
            await self.audit_service.log_event(
                event_type="proxy_request_failed",
                category="gateway",
                action="proxy_request",
                result="failed",
                description=f"Proxy request failed: {str(e)}",
                plugin_id=plugin_id,
                level=AuditLevel.STANDARD,
                details={"error": str(e)},
            )
            raise

    async def get_allowlist(
        self, plugin_id: Optional[str] = None
    ) -> List[DomainAllowlist]:
        """Get domain allowlist entries."""
        if plugin_id:
            return [
                entry
                for entry in self.domain_allowlists.values()
                if entry.plugin_id == plugin_id
            ]
        return list(self.domain_allowlists.values())

    async def get_stats(self) -> ProxyStats:
        """Get gateway statistics."""
        return self.stats

    async def preload_allowlists(self, plugin_ids: Optional[List[str]] = None) -> int:
        """Preload allowlists for plugins from ConfigService. Returns count loaded.

        If plugin_ids is None, attempts to load for all known plugins referenced
        in existing allowlists (idempotent) and returns number of domains loaded.
        """
        if self._config_service is None:
            return 0
        total_before = len(self.domain_allowlists)
        try:
            if plugin_ids is None:
                # Try to infer plugins from current state (no-op if empty)
                plugin_ids = list(
                    {e.plugin_id for e in self.domain_allowlists.values()}
                )
        except Exception:
            plugin_ids = []

        for pid in plugin_ids or []:
            try:
                await self._ensure_allowlist_loaded(pid)
            except Exception:  # noqa: BLE001
                logger.exception("allowlist preload failed for %s", pid)
        return len(self.domain_allowlists) - total_before

    async def _ensure_allowlist_loaded(self, plugin_id: str) -> None:
        """(Re)load allowlist for a plugin from ConfigService.

        Config structure is expected at key `gateway.allowlist.{plugin_id}`:
          { "example.com": { "allowed_methods": ["GET", "POST"], "allowed_paths": ["/v1/"] } }
        """
        if self._config_service is None:
            return
        key = f"gateway.allowlist.{plugin_id}"
        try:
            data = await self._config_service.get(key)
        except Exception:
            data = None
        if not isinstance(data, dict):
            return
        # Remove existing entries for this plugin
        for domain in list(self.domain_allowlists.keys()):
            try:
                if self.domain_allowlists[domain].plugin_id == plugin_id:  # type: ignore[attr-defined]
                    self.domain_allowlists.pop(domain, None)
            except Exception:
                # If structure differs, be conservative and leave it
                pass

        # Normalize and materialize DomainAllowlist entries
        for domain, rules in data.items():
            if not isinstance(rules, dict):
                continue
            raw_methods = rules.get("allowed_methods") or []
            raw_paths = rules.get("allowed_paths") or []
            # Coerce methods to ProxyMethod enums where possible
            methods: List[ProxyMethod] = []
            for m in raw_methods:
                try:
                    methods.append(ProxyMethod(str(m).upper()))
                except Exception:
                    # Ignore unknown method values
                    continue
            allow = DomainAllowlist(
                plugin_id=plugin_id,
                domain=str(domain),
                allowed_methods=methods,
                allowed_paths=[str(p) for p in raw_paths],
            )
            self.domain_allowlists[str(domain)] = allow

    async def get_active_requests(self) -> Dict[str, ProxyRequest]:
        """Get currently active requests."""
        return await self.proxy_handler.get_active_requests()

    async def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get rate limit status."""
        return await self.proxy_handler.get_rate_limit_status()

    def _is_safe_domain(self, domain: str) -> bool:
        """Check if domain is safe for proxy access."""
        blocked_domains = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "169.254",  # Link-local
            "10.",  # Private ranges
            "172.16",
            "192.168",
        ]
        return not any(domain.startswith(blocked) for blocked in blocked_domains)

    async def _can_manage_allowlist(self, plugin_id: str) -> bool:
        """Check if plugin can manage allowlists."""
        request = PolicyRequest(
            user_id=plugin_id,
            resource_type="gateway",
            resource_id="allowlist",
            action="manage_allowlist",
            traits=[],
            context={},
        )
        result = await self.policy_engine.evaluate_request(request)
        try:
            await self.audit_service.log_event(
                event_type="policy_decision",
                category="policy",
                action="manage_allowlist",
                result=result.decision.value,
                description=result.reason,
                resource_type="gateway",
                resource_id="allowlist",
                plugin_id=plugin_id,
                details={"sanitize_fields": result.sanitize_fields},
            )
        except Exception:  # noqa: BLE001
            logger.debug("policy audit emit failed", exc_info=True)
        return result.decision == PolicyDecision.ALLOW

    async def _can_proxy_request(self, plugin_id: str) -> bool:
        """Check if plugin can make proxy requests."""
        request = PolicyRequest(
            user_id=plugin_id,
            resource_type="gateway",
            resource_id="proxy",
            action="proxy_request",
            traits=[],
            context={},
        )
        result = await self.policy_engine.evaluate_request(request)
        try:
            await self.audit_service.log_event(
                event_type="policy_decision",
                category="policy",
                action="proxy_request",
                result=result.decision.value,
                description=result.reason,
                resource_type="gateway",
                resource_id="proxy",
                plugin_id=plugin_id,
                details={"sanitize_fields": result.sanitize_fields},
            )
        except Exception:  # noqa: BLE001
            logger.debug("policy audit emit failed", exc_info=True)
        return result.decision == PolicyDecision.ALLOW

    def _update_stats(self, response: ProxyResponse):
        """Update gateway statistics."""
        self.stats.total_requests += 1

        if response.success:
            self.stats.successful_requests += 1
        else:
            if response.status_code == 403:
                self.stats.blocked_requests += 1
            else:
                self.stats.failed_requests += 1

        # Update average response time
        if self.stats.total_requests > 0:
            total_time = (
                self.stats.average_response_time_ms * (self.stats.total_requests - 1)
                + response.response_time_ms
            ) / self.stats.total_requests
            self.stats.average_response_time_ms = total_time

        self.stats.last_updated = datetime.utcnow()
