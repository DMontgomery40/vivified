"""
Database utilities: async SQLAlchemy engine and session factory.
"""

from __future__ import annotations

import os
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker


def _default_db_url() -> str:
    # Use in-memory SQLite for local/dev if no DATABASE_URL is set.
    return os.getenv("TEST_DB_URL", "sqlite+aiosqlite:///:memory:")


def get_engine():
    url = os.getenv("DATABASE_URL", _default_db_url())
    return create_async_engine(url, future=True, echo=False)


async_session_factory = sessionmaker(
    bind=get_engine(), class_=AsyncSession, expire_on_commit=False
)


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        yield session

