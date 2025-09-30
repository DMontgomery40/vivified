"""
Database utilities: async SQLAlchemy engine and session factory.
"""

from __future__ import annotations

import os
from typing import AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    AsyncEngine,
    create_async_engine,
    async_sessionmaker,
)


_engine: Optional[AsyncEngine] = None
_session_maker: Optional[async_sessionmaker[AsyncSession]] = None


def _default_db_url() -> str:
    """Default database URL when DATABASE_URL is not set.

    - Tests: remain on in-memory SQLite unless TEST_DB_URL overrides (fast, hermetic).
    - Dev/Prod: prefer Postgres for PHI/PII and performance by default.
    """
    # Keep tests hermetic by default
    if os.getenv("PYTEST_CURRENT_TEST"):
        return os.getenv("TEST_DB_URL", "sqlite+aiosqlite:///:memory:")
    # Prefer Postgres by default for any non-test run
    return os.getenv(
        "DEV_POSTGRES_URL",
        "postgresql+asyncpg://vivified:changeme@localhost:5432/vivified",
    )


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        url = os.getenv("DATABASE_URL", _default_db_url())
        # Disallow SQLite for non-test, non-dev runs to avoid PHI/PII risk and concurrency limits
        if not os.getenv("PYTEST_CURRENT_TEST"):
            if url.strip().lower().startswith("sqlite"):
                if os.getenv("DEV_MODE", "false").lower() not in {"1", "true", "yes"}:
                    raise RuntimeError(
                        "SQLite is not allowed for core data outside DEV_MODE. Set DATABASE_URL to a "
                        "PostgreSQL DSN (e.g., postgresql+asyncpg://user:pass@host:5432/db).",
                    )
        _engine = create_async_engine(url, future=True, echo=False)
    return _engine


def _get_session_maker() -> async_sessionmaker[AsyncSession]:
    global _session_maker
    if _session_maker is None:
        _session_maker = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _session_maker


def async_session_factory() -> AsyncSession:
    """Factory that returns a new AsyncSession when called.

    Kept as a callable to match existing usage patterns:
    - `async with async_session_factory() as session:`
    - passed into services that expect a callable returning an AsyncSession.
    """
    return _get_session_maker()()


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session
