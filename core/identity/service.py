from __future__ import annotations

from typing import Optional, Dict, List, Tuple
from datetime import datetime
import asyncio

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from .models import User, Role, UserRole, Base
from ..identity.auth import AuthManager

try:  # Optional dependency in test env
    import bcrypt as _bcrypt  # type: ignore
except Exception:  # pragma: no cover - fallback for local tests
    import hashlib, os

    class _FallbackBcrypt:
        @staticmethod
        def gensalt():
            return os.urandom(16)

        @staticmethod
        def hashpw(pw: bytes, salt: bytes) -> bytes:
            h = hashlib.pbkdf2_hmac('sha256', pw, salt, 100_000)
            return b"salted$" + salt + b"$" + h

        @staticmethod
        def checkpw(pw: bytes, hashed: bytes) -> bool:
            try:
                _, salt, h = hashed.split(b"$", 2)
                hv = hashlib.pbkdf2_hmac('sha256', pw, salt, 100_000)
                return hv == h
            except Exception:
                return False

    _bcrypt = _FallbackBcrypt()


DEFAULT_ROLES = [
    ("admin", ["admin", "audit_viewer", "config_manager", "plugin_manager", "viewer"]),
    ("operator", ["plugin_manager", "audit_viewer", "viewer"]),
    ("viewer", ["viewer"]),
    ("phi_handler", ["handles_phi", "audit_required", "viewer"]),
    ("pii_handler", ["handles_pii", "audit_required", "viewer"]),
]


class IdentityService:
    def __init__(self, db: AsyncSession, auth: AuthManager):
        self.db = db
        self.auth = auth

    async def init_schema(self, engine) -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def ensure_default_roles(self) -> None:
        for name, traits in DEFAULT_ROLES:
            role = await self.db.scalar(select(Role).where(Role.name == name))
            if not role:
                role = Role(name=name, description=name, traits=traits)
                self.db.add(role)
        await self.db.commit()

    async def ensure_admin_user(self, username: str, password: str, email: str = "admin@local") -> None:
        user = await self.db.scalar(select(User).where(User.username == username))
        if user:
            return
        pw_hash = _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("latin1")
        user = User(username=username, email=email, password_hash=pw_hash)
        self.db.add(user)
        await self.db.flush()
        admin_role = await self.db.scalar(select(Role).where(Role.name == "admin"))
        if admin_role:
            self.db.add(UserRole(user_id=user.id, role_id=admin_role.id))
        await self.db.commit()

    async def authenticate(self, username: str, password: str) -> Optional[Dict]:
        user = await self.db.scalar(select(User).where(User.username == username))
        if not user or not user.is_active:
            return None
        if not _bcrypt.checkpw(password.encode("utf-8"), user.password_hash.encode("latin1")):
            return None
        traits = await self.get_user_traits(user.id)
        token = self.auth.generate_user_token(user.id, traits)
        return {"token": token, "user": {"id": user.id, "username": user.username, "traits": traits}}

    async def get_user_traits(self, user_id: str) -> List[str]:
        user = await self.db.get(User, user_id)
        if not user:
            return []
        traits: List[str] = []
        await self.db.refresh(user)
        # Eager load roles
        for role in user.roles:
            for t in role.traits or []:
                if t not in traits:
                    traits.append(t)
        return traits

    async def list_users(self, page: int = 1, page_size: int = 20) -> Dict:
        offset = (page - 1) * page_size
        result = await self.db.execute(select(User).offset(offset).limit(page_size))
        users = result.scalars().all()
        items = []
        for u in users:
            await self.db.refresh(u)
            role_names = [r.name for r in (u.roles or [])]
            items.append({
                "id": u.id,
                "username": u.username,
                "email": u.email,
                "is_active": u.is_active,
                "roles": role_names,
            })
        # Count
        total = (await self.db.execute(select(User))).scalars().unique().count()
        return {"users": items, "page": page, "page_size": page_size, "total": total}

    async def create_user(self, username: str, email: str, password: str, roles: List[str]) -> Tuple[bool, Optional[str]]:
        existing = await self.db.scalar(select(User).where((User.username == username) | (User.email == email)))
        if existing:
            return False, "user_exists"
        pw_hash = _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("latin1")
        user = User(username=username, email=email, password_hash=pw_hash)
        self.db.add(user)
        await self.db.flush()
        for rname in roles:
            role = await self.db.scalar(select(Role).where(Role.name == rname))
            if role:
                self.db.add(UserRole(user_id=user.id, role_id=role.id))
        await self.db.commit()
        return True, user.id

    async def list_roles(self) -> List[Dict]:
        result = await self.db.execute(select(Role))
        roles = result.scalars().all()
        return [{"id": r.id, "name": r.name, "description": r.description, "traits": r.traits or []} for r in roles]

    async def set_user_roles(self, user_id: str, role_names: List[str]) -> bool:
        user = await self.db.get(User, user_id)
        if not user:
            return False
        # Clear existing
        await self.db.execute(
            UserRole.__table__.delete().where(UserRole.user_id == user_id)
        )
        # Assign new
        for rn in role_names:
            role = await self.db.scalar(select(Role).where(Role.name == rn))
            if role:
                self.db.add(UserRole(user_id=user_id, role_id=role.id))
        await self.db.commit()
        return True
