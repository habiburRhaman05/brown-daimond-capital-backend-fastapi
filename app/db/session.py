from collections.abc import AsyncIterator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine

from app.config import get_settings

_engine: AsyncEngine | None = None
_factory: async_sessionmaker[AsyncSession] | None = None


def db_configured() -> bool:
    return bool(get_settings().DATABASE_URL.strip())


def get_engine() -> AsyncEngine:
    global _engine
    if _engine is None:
        url = get_settings().async_database_url
        if not url:
            raise RuntimeError("DATABASE_URL is not set")
        # statement_cache_size=0 keeps this working behind Supabase's transaction-mode pooler too.
        _engine = create_async_engine(
            url, pool_size=5, max_overflow=5, pool_pre_ping=True, pool_recycle=1800,
            connect_args={"statement_cache_size": 0},
        )
    return _engine


def get_factory() -> async_sessionmaker[AsyncSession]:
    global _factory
    if _factory is None:
        _factory = async_sessionmaker(get_engine(), expire_on_commit=False)
    return _factory


async def get_db() -> AsyncIterator[AsyncSession]:
    """One transaction per request: commits when the handler returns, rolls back on any error."""
    async with get_factory()() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            await session.rollback()
            raise


async def close_db() -> None:
    global _engine, _factory
    if _engine is not None:
        await _engine.dispose()
    _engine = None
    _factory = None
