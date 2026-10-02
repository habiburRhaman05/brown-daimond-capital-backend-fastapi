"""Create (or reset the password of) an admin account.

    python scripts/create_admin.py you@example.com "a strong password" "Your Name"
"""
import asyncio
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sqlalchemy import select  # noqa: E402

from app.db.models import Profile  # noqa: E402
from app.db.session import close_db, get_factory  # noqa: E402
from app.security import hash_password, now, password_ok  # noqa: E402


async def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    email, password = sys.argv[1].strip().lower(), sys.argv[2]
    name = sys.argv[3] if len(sys.argv) > 3 else "Administrator"
    if not password_ok(password):
        sys.exit("Password must be 8 to 72 bytes.")
    async with get_factory()() as db:
        user = (await db.execute(select(Profile).where(Profile.email == email))).scalar_one_or_none()
        if user is None:
            user = Profile(email=email, full_name=name)
            db.add(user)
        user.role, user.is_active, user.email_verified_at = "admin", True, user.email_verified_at or now()
        user.password_hash = await hash_password(password)
        await db.commit()
        print(f"admin ready: {email}")
    await close_db()


asyncio.run(main())
