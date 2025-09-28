"""
Gateway service for external API access and proxy functionality.

This module provides:
- External API proxy with domain allowlists
- Request/response transformation
- Security validation and filtering
- Rate limiting and monitoring
"""

from .service import GatewayService
from .models import ProxyRequest, ProxyResponse, DomainAllowlist
from .proxy import ProxyHandler

__all__ = [
    "GatewayService",
    "ProxyRequest",
    "ProxyResponse",
    "DomainAllowlist",
    "ProxyHandler",
]
