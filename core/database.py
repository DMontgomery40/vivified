"""
Database utilities: async SQLAlchemy engine and session factory.
"""

from __future__ import annotations

import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    create_async_engine,
    async_sessionmaker,
)


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


def get_engine():
    url = os.getenv("DATABASE_URL", _default_db_url())
    # Disallow SQLite for non-test, non-dev runs to avoid PHI/PII risk and concurrency limits
    if not os.getenv("PYTEST_CURRENT_TEST"):
        if url.strip().lower().startswith("sqlite"):
            if os.getenv("DEV_MODE", "false").lower() not in {"1", "true", "yes"}:
                raise RuntimeError(
                    "SQLite is not allowed for core data outside DEV_MODE. Set DATABASE_URL to a "
                    "PostgreSQL DSN (e.g., postgresql+asyncpg://user:pass@host:5432/db)."
                )
    return create_async_engine(url, future=True, echo=False)


# Use SQLAlchemy 2.0 async_sessionmaker for accurate typing with mypy
async_session_factory = async_sessionmaker(get_engine(), expire_on_commit=False)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session
