from __future__ import annotations

from typing import Dict
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from core.database import get_session
from core.identity.service import IdentityService
from core.identity.auth import get_current_user, get_auth_manager


auth_router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str
    password: str


@auth_router.post("/login")
async def login(payload: LoginRequest, session=Depends(get_session)):
    svc = IdentityService(session, get_auth_manager())
    result = await svc.authenticate(payload.username, payload.password)
    if not result:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return result


@auth_router.get("/me")
async def me(user: Dict = Depends(get_current_user)):
    return {"id": user.get("id"), "traits": user.get("traits", [])}

