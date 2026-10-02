import uuid
from datetime import datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import AuthToken, Profile
from app.security import create_access_token, expiry, hash_token, new_opaque_token, now

# Two tabs (the app and the portal page) can refresh with the same token at nearly the
# same moment. A refresh token that was just used keeps working for this long.
REFRESH_REUSE_GRACE = timedelta(seconds=30)


def user_json(user: Profile) -> dict:
    return {"id": str(user.id), "email": user.email, "role": user.role}


async def issue_session(db: AsyncSession, user: Profile, *, with_user: bool = True) -> dict:
    s = get_settings()
    access, exp = create_access_token(user.id, user.email, user.role)
    refresh = new_opaque_token()
    db.add(AuthToken(user_id=user.id, kind="refresh", token_hash=hash_token(refresh),
                     expires_at=expiry(days=s.REFRESH_TOKEN_TTL_DAYS)))
    session = {"access_token": access, "refresh_token": refresh, "expires_at": exp, "expires_in": s.ACCESS_TOKEN_TTL_SECONDS}
    if with_user:
        session["user"] = user_json(user)
    return session


async def rotate_refresh(db: AsyncSession, raw: str) -> tuple[Profile, dict] | None:
    row = (await db.execute(select(AuthToken).where(AuthToken.token_hash == hash_token(raw), AuthToken.kind == "refresh"))).scalar_one_or_none()
    if row is None or row.expires_at <= now():
        return None
    if row.used_at is not None and now() - row.used_at > REFRESH_REUSE_GRACE:
        return None
    user = await db.get(Profile, row.user_id)
    if user is None or not user.is_active or user.email_verified_at is None:
        return None
    if row.used_at is None:
        row.used_at = now()
    return user, await issue_session(db, user, with_user=False)


async def revoke_sessions(db: AsyncSession, user_id: uuid.UUID) -> None:
    await db.execute(delete(AuthToken).where(AuthToken.user_id == user_id, AuthToken.kind == "refresh"))


async def purge_expired(db: AsyncSession) -> None:
    await db.execute(delete(AuthToken).where(AuthToken.expires_at < now() - timedelta(days=1)))


async def create_link_token(db: AsyncSession, user_id: uuid.UUID, kind: str, expires_at: datetime) -> str:
    """A one-time emailed token. Older unused tokens of the same kind stop working."""
    await db.execute(update(AuthToken).where(AuthToken.user_id == user_id, AuthToken.kind == kind,
                                             AuthToken.used_at.is_(None)).values(used_at=now()))
    raw = new_opaque_token()
    db.add(AuthToken(user_id=user_id, kind=kind, token_hash=hash_token(raw), expires_at=expires_at))
    return raw


async def find_link_token(db: AsyncSession, raw: str, kinds: tuple[str, ...]) -> AuthToken | None:
    if not raw:
        return None
    return (await db.execute(select(AuthToken).where(AuthToken.token_hash == hash_token(raw), AuthToken.kind.in_(kinds)))).scalar_one_or_none()


def verify_link(raw: str) -> str:
    return f"{get_settings().PUBLIC_API_URL.rstrip('/')}/api/auth/verify-email?token={raw}"


def redeem_link(raw: str) -> str:
    return f"{get_settings().PUBLIC_API_URL.rstrip('/')}/api/auth/redeem?token={raw}"
