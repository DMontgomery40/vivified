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
from .models import *
from .dependencies import *

__all__ = ["admin_router"]
