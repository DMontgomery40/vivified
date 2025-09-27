from __future__ import annotations

from fastapi import Depends
from typing import List, Optional, Callable

from core.identity.auth import get_current_user, require_auth as _require_auth


def require_auth(required_traits: Optional[List[str]] = None) -> Callable:
    """Expose require_auth for route dependencies."""

    return _require_auth(required_traits)


__all__ = ["get_current_user", "require_auth"]

