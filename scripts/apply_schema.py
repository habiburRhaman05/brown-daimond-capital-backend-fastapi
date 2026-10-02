"""Apply db/001_schema.sql to DATABASE_URL (from .env). WARNING: drops and recreates every table.

    python scripts/apply_schema.py --yes
"""
import asyncio
import pathlib
import sys

import asyncpg

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.config import get_settings  # noqa: E402


async def main() -> None:
    if "--yes" not in sys.argv:
        sys.exit("This deletes all data in the portal tables. Re-run with --yes to continue.")
    url = get_settings().async_database_url.replace("postgresql+asyncpg://", "postgresql://", 1)
    conn = await asyncpg.connect(url, statement_cache_size=0)
    try:
        await conn.execute((ROOT / "db" / "001_schema.sql").read_text(encoding="utf-8"))
        tables = await conn.fetch("select tablename, rowsecurity from pg_tables where schemaname='public' order by 1")
        for t in tables:
            print(f"{t['tablename']:<22} rls={'on' if t['rowsecurity'] else 'OFF'}")
    finally:
        await conn.close()


asyncio.run(main())
