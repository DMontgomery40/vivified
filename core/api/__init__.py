"""
Admin API endpoints for Vivified platform management.

Provides secure, role-based access to:
- User management
- Plugin management
- Configuration management
- Audit log queries
- System health metrics
"""

from .admin import admin_router
from .auth import auth_router
from .models import ConfigSetRequest, UserCreateRequest  # re-export
from .dependencies import get_current_user, require_auth  # re-export

__all__ = [
    "admin_router",
    "auth_router",
    "ConfigSetRequest",
    "UserCreateRequest",
    "get_current_user",
    "require_auth",
]
