import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app import mailer
from app.config import get_settings
from app.db.models import Invite, Profile
from app.errors import ApiError
from app.security import expiry
from app.services import tokens


def registered(profile: Profile | None) -> bool:
    """True once the person has chosen a password (an invite that was never accepted does not count)."""
    return profile is not None and profile.password_hash is not None


async def open_invite(db: AsyncSession, email: str) -> Invite | None:
    return (await db.execute(
        select(Invite).where(Invite.email == email, Invite.status == "sent").order_by(Invite.created_at.desc()).limit(1)
    )).scalar_one_or_none()


async def _open_invite(db: AsyncSession, email: str, invited_by: uuid.UUID, existing: Profile | None, full_name: str = "") -> tuple[Invite, str]:
    """Create (or reuse) the not-yet-active account and a one-time link. Same expiry and
    tied-to-email rules whether the link is emailed or copied by an admin."""
    user = existing
    if user is None:
        user = Profile(email=email, full_name=full_name[:120], password_hash=None, role="client")
        db.add(user)
        await db.flush()
    invite = Invite(email=email, invited_by=invited_by, status="sent")
    db.add(invite)
    raw = await tokens.create_link_token(db, user.id, "invite", expiry(days=get_settings().INVITE_TTL_DAYS))
    await db.flush()
    return invite, raw


async def send_invite(db: AsyncSession, email: str, invited_by: uuid.UUID, existing: Profile | None, full_name: str = "") -> Invite:
    """Create (or reuse) the not-yet-active account, an invite row and a one-time link, and email it.
    Raises 502 INVITE_EMAIL_FAILED if the message could not be handed to GHL; the caller's
    transaction then rolls everything back."""
    invite, raw = await _open_invite(db, email, invited_by, existing, full_name)
    if not await mailer.send_invite_email(email, tokens.redeem_link(raw)):
        raise ApiError(502, "INVITE_EMAIL_FAILED")
    return invite


async def create_invite_link(db: AsyncSession, email: str, invited_by: uuid.UUID, existing: Profile | None, full_name: str = "") -> tuple[Invite, str]:
    """Same as send_invite but returns the link instead of emailing it, for an admin to paste
    into their own message."""
    invite, raw = await _open_invite(db, email, invited_by, existing, full_name)
    return invite, tokens.redeem_link(raw)
