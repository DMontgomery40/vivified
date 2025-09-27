from __future__ import annotations

from typing import Any, Optional, Dict, List
from pydantic import BaseModel, Field


class ConfigSetRequest(BaseModel):
    key: str = Field(..., max_length=255)
    value: Any
    is_sensitive: bool = False
    reason: Optional[str] = None


class UserCreateRequest(BaseModel):
    username: str
    email: str
    traits: List[str] = Field(default_factory=list)
    password: str
