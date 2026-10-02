import re
import uuid
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog, Profile
from app.db.session import get_db
from app.errors import ApiError
from app.security import TokenError, decode_access_token

# scope="function": commit (or roll back) before the response goes out, so a client that
# fires its next request the moment it gets a 200 always sees what it just wrote.
DB = Annotated[AsyncSession, Depends(get_db, scope="function")]

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


def normalize_email(email: object) -> str:
    return email.strip().lower() if isinstance(email, str) else ""


def bearer_token(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    return h[7:].strip() if h.lower().startswith("bearer ") else None


async def current_user(request: Request, db: DB) -> Profile:
    token = bearer_token(request)
    if not token:
        raise ApiError(401, "NOT_SIGNED_IN")
    try:
        claims = decode_access_token(token)
        user_id = uuid.UUID(claims["sub"])
    except (TokenError, ValueError) as exc:
        raise ApiError(401, "SESSION_EXPIRED") from exc
    profile = await db.get(Profile, user_id)
    if profile is None or not profile.is_active:
        raise ApiError(401, "SESSION_EXPIRED")
    if profile.email_verified_at is None:
        raise ApiError(403, "EMAIL_NOT_VERIFIED")
    return profile


CurrentUser = Annotated[Profile, Depends(current_user)]


async def admin_user(user: CurrentUser) -> Profile:
    if user.role != "admin":
        raise ApiError(403, "FORBIDDEN")
    return user


AdminUser = Annotated[Profile, Depends(admin_user)]


async def read_json(request: Request) -> dict:
    """The request body as a JSON object, or a 400. Routes that accept free-form portal
    payloads use this instead of a fixed model so no key the page sends is dropped."""
    try:
        data = await request.json()
    except Exception as exc:
        raise ApiError(400, "Invalid payload") from exc
    if not isinstance(data, dict):
        raise ApiError(400, "Invalid payload")
    return data


async def audit(db: AsyncSession, actor_id: uuid.UUID | None, action: str,
                client_id: uuid.UUID | None = None, meta: dict | None = None) -> None:
    db.add(AuditLog(actor_id=actor_id, action=action, client_id=client_id, meta=meta or {}))


async def profile_by_email(db: AsyncSession, email: str) -> Profile | None:
    return (await db.execute(select(Profile).where(Profile.email == email))).scalar_one_or_none()
