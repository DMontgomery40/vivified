from __future__ import annotations

from typing import Optional, Dict, List, Tuple
from datetime import datetime, timedelta
import logging

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from .models import User, Role, UserRole, Base, APIKey, AuthAudit
from ..identity.auth import AuthManager

from typing import Any as _Any

try:  # Optional dependency in test env
    import bcrypt as _bcrypt_mod  # type: ignore
except Exception:  # pragma: no cover - fallback for local tests
    import hashlib
    import os

    class _FallbackBcrypt:
        @staticmethod
        def gensalt():
            return os.urandom(16)

        @staticmethod
        def hashpw(pw: bytes, salt: bytes) -> bytes:
            h = hashlib.pbkdf2_hmac("sha256", pw, salt, 100_000)
            return b"salted$" + salt + b"$" + h

        @staticmethod
        def checkpw(pw: bytes, hashed: bytes) -> bool:
            try:
                _, salt, h = hashed.split(b"$", 2)
                hv = hashlib.pbkdf2_hmac("sha256", pw, salt, 100_000)
                return hv == h
            except Exception:
                return False

    _bcrypt: _Any = _FallbackBcrypt()
else:
    _bcrypt = _bcrypt_mod  # type: ignore[assignment]


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
        self.logger = logging.getLogger(__name__)
        self.max_failed_attempts = 5
        self.lockout_duration = timedelta(minutes=30)

    async def init_schema(self, engine) -> None:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def ensure_default_roles(self) -> None:
        for name, traits in DEFAULT_ROLES:
            role = await self.db.scalar(select(Role).where(Role.name == name))
            if not role:
                role = Role(name=name, description=name, traits=traits)  # type: ignore[call-arg]
                self.db.add(role)
        await self.db.commit()

    async def ensure_admin_user(
        self, username: str, password: str, email: str = "admin@local"
    ) -> None:
        user = await self.db.scalar(select(User).where(User.username == username))
        if user:
            return
        pw_hash = _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode(
            "latin1"
        )
        user = User(username=username, email=email, password_hash=pw_hash)  # type: ignore[call-arg]
        self.db.add(user)
        await self.db.flush()
        admin_role = await self.db.scalar(select(Role).where(Role.name == "admin"))
        if admin_role:
            self.db.add(UserRole(user_id=user.id, role_id=admin_role.id))  # type: ignore[call-arg]
        await self.db.commit()

    async def authenticate(
        self,
        username: str,
        password: str,
        mfa_token: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> Optional[Dict]:
        """Authenticate user with optional MFA and account lockout protection."""
        user = await self.db.scalar(select(User).where(User.username == username))
        if not user or not user.is_active:
            await self._audit_log(
                None,
                "failed_login",
                False,
                {"username": username, "reason": "user_not_found"},
                ip_address,
            )
            return None

        # Check if account is locked
        if user.locked_until and user.locked_until > datetime.utcnow():
            await self._audit_log(
                user.id, "failed_login", False, {"reason": "account_locked"}, ip_address
            )
            return None

        # Verify password
        if not _bcrypt.checkpw(
            password.encode("utf-8"), user.password_hash.encode("latin1")
        ):
            await self._handle_failed_login(
                user.id, user.failed_login_attempts, ip_address
            )
            return None

        # Verify MFA if enabled
        if user.mfa_enabled:
            if not mfa_token or not self._verify_mfa(user.mfa_secret, mfa_token):
                await self._audit_log(
                    user.id,
                    "failed_login",
                    False,
                    {"reason": "invalid_mfa"},
                    ip_address,
                )
                return None

        # Generate JWT token
        traits = await self.get_user_traits(user.id)
        token = self.auth.generate_user_token(user.id, traits)

        # Update login info and reset failed attempts
        await self.db.execute(
            update(User)
            .where(User.id == user.id)
            .values(
                last_login=datetime.utcnow(), failed_login_attempts=0, locked_until=None
            )
        )
        await self.db.commit()

        # Audit successful login
        await self._audit_log(
            user.id, "login", True, {"ip_address": ip_address}, ip_address
        )

        return {
            "token": token,
            "user": {"id": user.id, "username": user.username, "traits": traits},
            "mfa_required": user.mfa_enabled,
        }

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
            items.append(
                {
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "is_active": u.is_active,
                    "roles": role_names,
                }
            )
        # Count
        total = len((await self.db.execute(select(User))).scalars().unique().all())
        return {"users": items, "page": page, "page_size": page_size, "total": total}

    async def create_user(
        self, username: str, email: str, password: str, roles: List[str]
    ) -> Tuple[bool, Optional[str]]:
        existing = await self.db.scalar(
            select(User).where((User.username == username) | (User.email == email))
        )
        if existing:
            return False, "user_exists"

        pw_hash = _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode(
            "latin1"
        )

        # Setup MFA for sensitive roles
        mfa_secret = None
        if self._requires_mfa(roles):
            try:
                import pyotp

                mfa_secret = pyotp.random_base32()
            except Exception:
                self.logger.warning(
                    f"Failed to generate MFA secret for user {username}"
                )

        user = User(  # type: ignore[call-arg]
            username=username,
            email=email,
            password_hash=pw_hash,
            mfa_secret=mfa_secret,
            mfa_enabled=bool(mfa_secret),
        )
        self.db.add(user)
        await self.db.flush()

        for rname in roles:
            role = await self.db.scalar(select(Role).where(Role.name == rname))
            if role:
                self.db.add(UserRole(user_id=user.id, role_id=role.id))  # type: ignore[call-arg]

        await self.db.commit()

        # Audit user creation
        await self._audit_log(
            user.id, "user_created", True, {"username": username, "roles": roles}, None
        )

        return True, user.id

    async def list_roles(self) -> List[Dict]:
        result = await self.db.execute(select(Role))
        roles = result.scalars().all()
        return [
            {
                "id": r.id,
                "name": r.name,
                "description": r.description,
                "traits": r.traits or [],
            }
            for r in roles
        ]

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
                self.db.add(UserRole(user_id=user_id, role_id=role.id))  # type: ignore[call-arg]
        await self.db.commit()
        return True

    def _verify_mfa(self, secret: str, token: str) -> bool:
        """Verify TOTP MFA token."""
        try:
            import pyotp

            totp = pyotp.TOTP(secret)
            return totp.verify(token, valid_window=1)
        except Exception:
            return False

    def _requires_mfa(self, roles: List[str]) -> bool:
        """Check if roles require MFA."""
        mfa_required_roles = ["admin", "phi_handler"]
        return any(role in mfa_required_roles for role in roles)

    async def _handle_failed_login(
        self, user_id: str, current_attempts: int, ip_address: Optional[str] = None
    ):
        """Handle failed login attempt with account lockout."""
        new_attempts = current_attempts + 1

        if new_attempts >= self.max_failed_attempts:
            locked_until = datetime.utcnow() + self.lockout_duration
            await self.db.execute(
                update(User)
                .where(User.id == user_id)
                .values(failed_login_attempts=new_attempts, locked_until=locked_until)
            )
            await self._audit_log(
                user_id, "account_locked", True, {"attempts": new_attempts}, ip_address
            )
        else:
            await self.db.execute(
                update(User)
                .where(User.id == user_id)
                .values(failed_login_attempts=new_attempts)
            )

        await self.db.commit()
        await self._audit_log(
            user_id, "failed_login", False, {"attempt": new_attempts}, ip_address
        )

    async def _audit_log(
        self,
        user_id: Optional[str],
        event_type: str,
        success: bool,
        details: Dict,
        ip_address: Optional[str] = None,
    ):
        """Log authentication events for audit trail."""
        audit_entry = AuthAudit(  # type: ignore[call-arg]
            user_id=user_id,
            event_type=event_type,
            ip_address=ip_address,
            success=success,
            details=details,
        )
        self.db.add(audit_entry)
        await self.db.commit()

        self.logger.info(
            f"Auth event: {event_type}",
            extra={
                "trace_id": user_id or "unknown",
                "event_type": event_type,
                "success": success,
                "ip_address": ip_address,
            },
        )

    async def setup_mfa(self, user_id: str) -> Dict:
        """Setup MFA for a user."""
        try:
            import pyotp

            secret = pyotp.random_base32()
            qr_code_url = pyotp.totp.TOTP(secret).provisioning_uri(
                name=user_id, issuer_name="Vivified Platform"
            )

            # Store secret (not enabled yet)
            await self.db.execute(
                update(User).where(User.id == user_id).values(mfa_secret=secret)
            )
            await self.db.commit()

            return {
                "secret": secret,
                "qr_code_url": qr_code_url,
                "backup_codes": [],  # Could implement backup codes
            }
        except Exception as e:
            self.logger.error(f"Failed to setup MFA for user {user_id}: {e}")
            raise

    async def enable_mfa(self, user_id: str, mfa_token: str) -> bool:
        """Enable MFA for a user after verifying the token."""
        user = await self.db.get(User, user_id)
        if not user or not user.mfa_secret:
            return False

        if not self._verify_mfa(user.mfa_secret, mfa_token):
            return False

        await self.db.execute(
            update(User).where(User.id == user_id).values(mfa_enabled=True)
        )
        await self.db.commit()

        await self._audit_log(user_id, "mfa_enabled", True, {}, None)
        return True

    async def create_api_key(
        self,
        name: str,
        owner_id: Optional[str] = None,
        plugin_id: Optional[str] = None,
        scopes: List[str] | None = None,
    ) -> str:
        """Create an API key for service-to-service authentication."""
        import secrets
        import hashlib

        # Generate a secure random key
        key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(key.encode()).hexdigest()

        api_key = APIKey(  # type: ignore[call-arg]
            key_hash=key_hash,
            name=name,
            owner_id=owner_id,
            plugin_id=plugin_id,
            scopes=scopes or [],
        )
        self.db.add(api_key)
        await self.db.commit()

        await self._audit_log(
            owner_id,
            "api_key_created",
            True,
            {"name": name, "plugin_id": plugin_id},
            None,
        )

        return key  # Return the plain key only once
