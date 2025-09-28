"""
Proxy handler for external API requests.
"""

import logging
from typing import Dict, Optional, Any
from datetime import datetime, timedelta
import httpx
import time

from .models import ProxyRequest, ProxyResponse, RateLimit
from ..audit.service import AuditService, AuditLevel

logger = logging.getLogger(__name__)


class ProxyHandler:
    """Handles external API proxy requests with security and rate limiting."""

    def __init__(self, audit_service: AuditService):
        self.audit_service = audit_service
        self.rate_limits: Dict[str, RateLimit] = {}
        self.active_requests: Dict[str, ProxyRequest] = {}
        self._http_client: Optional[httpx.AsyncClient] = None

    async def start(self):
        """Start the proxy handler."""
        self._http_client = httpx.AsyncClient(
            timeout=httpx.Timeout(30.0),
            limits=httpx.Limits(max_keepalive_connections=20, max_connections=100),
        )
        logger.info("Proxy handler started")

    async def stop(self):
        """Stop the proxy handler."""
        if self._http_client:
            await self._http_client.aclose()
            self._http_client = None
        logger.info("Proxy handler stopped")

    async def handle_request(
        self, request: ProxyRequest, domain_allowlist: Dict[str, Any]
    ) -> ProxyResponse:
        """Handle a proxy request."""
        start_time = time.time()

        try:
            # Check if request is allowed
            if not await self._is_request_allowed(request, domain_allowlist):
                await self._audit_request(request, "blocked", "Domain not in allowlist")
                return ProxyResponse(
                    request_id=request.id,
                    status_code=403,
                    success=False,
                    error_message="Domain not in allowlist",
                    response_time_ms=int((time.time() - start_time) * 1000),
                )

            # Check rate limits
            if not await self._check_rate_limit(request):
                await self._audit_request(request, "blocked", "Rate limit exceeded")
                return ProxyResponse(
                    request_id=request.id,
                    status_code=429,
                    success=False,
                    error_message="Rate limit exceeded",
                    response_time_ms=int((time.time() - start_time) * 1000),
                )

            # Track active request
            self.active_requests[request.id] = request

            # Make the actual HTTP request
            response = await self._make_http_request(request)

            response_time_ms = int((time.time() - start_time) * 1000)

            # Create response
            proxy_response = ProxyResponse(
                request_id=request.id,
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.content,
                response_time_ms=response_time_ms,
                success=200 <= response.status_code < 400,
                error_message=(
                    None
                    if response.status_code < 400
                    else f"HTTP {response.status_code}"
                ),
            )

            # Audit successful request
            await self._audit_request(
                request,
                "completed" if proxy_response.success else "failed",
                f"Status: {response.status_code}",
            )

            return proxy_response

        except Exception as e:
            logger.error(f"Proxy request failed: {e}")
            response_time_ms = int((time.time() - start_time) * 1000)

            await self._audit_request(request, "failed", str(e))

            return ProxyResponse(
                request_id=request.id,
                status_code=500,
                success=False,
                error_message=str(e),
                response_time_ms=response_time_ms,
            )

        finally:
            # Clean up active request
            self.active_requests.pop(request.id, None)

    async def _is_request_allowed(
        self, request: ProxyRequest, domain_allowlist: Dict[str, Any]
    ) -> bool:
        """Check if request is allowed based on domain allowlist."""
        domain = str(request.url.host)

        # Check if domain is in allowlist
        if domain not in domain_allowlist:
            return False

        allowlist_entry = domain_allowlist[domain]

        # Check if method is allowed
        if request.method not in allowlist_entry.get("allowed_methods", []):
            return False

        # Check if path is allowed
        allowed_paths = allowlist_entry.get("allowed_paths", [])
        if allowed_paths and not any(
            request.url.path.startswith(path) for path in allowed_paths
        ):
            return False

        return True

    async def _check_rate_limit(self, request: ProxyRequest) -> bool:
        """Check if request is within rate limits."""
        domain = str(request.url.host)
        plugin_id = request.plugin_id

        # Create rate limit key
        rate_key = f"{plugin_id}:{domain}"

        # Get or create rate limit entry
        if rate_key not in self.rate_limits:
            self.rate_limits[rate_key] = RateLimit(
                plugin_id=plugin_id,
                domain=domain,
                requests_per_minute=60,  # Default limit
                burst_limit=100,
            )

        rate_limit = self.rate_limits[rate_key]
        now = datetime.utcnow()

        # Reset window if needed
        if now - rate_limit.window_start > timedelta(minutes=1):
            rate_limit.window_start = now
            rate_limit.current_requests = 0

        # Check if within limits
        if rate_limit.current_requests >= rate_limit.requests_per_minute:
            return False

        # Increment counter
        rate_limit.current_requests += 1
        return True

    async def _make_http_request(self, request: ProxyRequest) -> httpx.Response:
        """Make the actual HTTP request."""
        if not self._http_client:
            raise RuntimeError("HTTP client not initialized")

        # Prepare headers
        headers = dict(request.headers)

        # Make request
        response = await self._http_client.request(
            method=request.method,
            url=str(request.url),
            headers=headers,
            content=request.body,
            timeout=request.timeout,
        )

        return response

    async def _audit_request(self, request: ProxyRequest, status: str, details: str):
        """Audit proxy request."""
        await self.audit_service.log_event(
            event_type="proxy_request",
            category="gateway",
            action="proxy_request",
            result=status,
            description=f"Proxy request to {request.url}",
            plugin_id=request.plugin_id,
            level=AuditLevel.STANDARD,
            details={
                "url": str(request.url),
                "method": request.method,
                "status": status,
                "details": details,
            },
        )

    async def get_active_requests(self) -> Dict[str, ProxyRequest]:
        """Get currently active requests."""
        return self.active_requests.copy()

    async def get_rate_limit_status(self) -> Dict[str, Any]:
        """Get current rate limit status."""
        return {
            rate_key: {
                "plugin_id": rate_limit.plugin_id,
                "domain": rate_limit.domain,
                "current_requests": rate_limit.current_requests,
                "requests_per_minute": rate_limit.requests_per_minute,
                "window_start": rate_limit.window_start.isoformat(),
            }
            for rate_key, rate_limit in self.rate_limits.items()
        }
