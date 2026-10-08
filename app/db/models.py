import uuid
from datetime import date, datetime

from sqlalchemy import BigInteger, Boolean, Date, DateTime, ForeignKey, Integer, Text, func, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


_uuid = lambda: mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)  # noqa: E731
_now = lambda: mapped_column(DateTime(timezone=True), server_default=func.now())  # noqa: E731


class Profile(Base):
    __tablename__ = "profiles"

    id: Mapped[uuid.UUID] = _uuid()
    email: Mapped[str] = mapped_column(Text, unique=True)
    full_name: Mapped[str] = mapped_column(Text, default="")
    password_hash: Mapped[str | None] = mapped_column(Text)
    role: Mapped[str] = mapped_column(Text, default="client")
    avatar_url: Mapped[str | None] = mapped_column(Text)
    phone: Mapped[str | None] = mapped_column(Text)
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()


class ClientNumber(Base):
    """Our team's own reference number(s) for a client. The client never sees or sets these."""

    __tablename__ = "client_numbers"

    id: Mapped[uuid.UUID] = _uuid()
    client_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    number: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()


class AuthToken(Base):
    __tablename__ = "auth_tokens"

    id: Mapped[uuid.UUID] = _uuid()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    kind: Mapped[str] = mapped_column(Text)
    token_hash: Mapped[str] = mapped_column(Text, unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()


class ClientDetail(Base):
    __tablename__ = "client_details"

    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"), primary_key=True)

    legal_first_name: Mapped[str | None] = mapped_column(Text)
    legal_last_name: Mapped[str | None] = mapped_column(Text)
    date_of_birth: Mapped[date | None] = mapped_column(Date)
    personal_email: Mapped[str | None] = mapped_column(Text)
    personal_phone: Mapped[str | None] = mapped_column(Text)
    preferred_contact: Mapped[str | None] = mapped_column(Text)
    contact_time: Mapped[list] = mapped_column(JSONB, default=list)
    mailing_street: Mapped[str | None] = mapped_column(Text)
    mailing_city: Mapped[str | None] = mapped_column(Text)
    mailing_state: Mapped[str | None] = mapped_column(Text)
    mailing_zip: Mapped[str | None] = mapped_column(Text)

    team_members: Mapped[list] = mapped_column(JSONB, default=list)

    business_name: Mapped[str | None] = mapped_column(Text)
    backup_name_1: Mapped[str | None] = mapped_column(Text)
    backup_name_2: Mapped[str | None] = mapped_column(Text)
    business_theme: Mapped[str | None] = mapped_column(Text)
    purpose_text: Mapped[str | None] = mapped_column(Text)
    naics_code: Mapped[str | None] = mapped_column(Text)
    sic_code: Mapped[str | None] = mapped_column(Text)

    domain_name: Mapped[str | None] = mapped_column(Text)
    tagline: Mapped[str | None] = mapped_column(Text)
    cta_text: Mapped[str | None] = mapped_column(Text)

    raw_fields: Mapped[dict] = mapped_column(JSONB, default=dict)

    completed_on: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    locked_on: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    changes_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    site_preview_url: Mapped[str | None] = mapped_column(Text)
    site_deployed_on: Mapped[date | None] = mapped_column(Date)
    site_url: Mapped[str | None] = mapped_column(Text)
    client_number: Mapped[str | None] = mapped_column(Text)

    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()


class SiteConfig(Base):
    __tablename__ = "site_configs"

    client_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"), primary_key=True)
    config_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    config_raw: Mapped[str | None] = mapped_column(Text)
    version: Mapped[int] = mapped_column(Integer, default=1)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("profiles.id"))
    updated_at: Mapped[datetime] = _now()


class SiteConfigHistory(Base):
    __tablename__ = "site_config_history"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    client_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    version: Mapped[int] = mapped_column(Integer)
    config_data: Mapped[dict] = mapped_column(JSONB)
    config_raw: Mapped[str | None] = mapped_column(Text)
    changed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("profiles.id"))
    changed_at: Mapped[datetime] = _now()


class ChangeRequest(Base):
    __tablename__ = "change_requests"

    id: Mapped[uuid.UUID] = _uuid()
    client_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    part: Mapped[str] = mapped_column(Text)
    text: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="pending")
    admin_note: Mapped[str | None] = mapped_column(Text)
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("profiles.id"))
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()
    updated_at: Mapped[datetime] = _now()


class Invite(Base):
    __tablename__ = "invites"

    id: Mapped[uuid.UUID] = _uuid()
    email: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="sent")
    invited_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("profiles.id"))
    created_at: Mapped[datetime] = _now()
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class SignupRequest(Base):
    __tablename__ = "signup_requests"

    id: Mapped[uuid.UUID] = _uuid()
    email: Mapped[str] = mapped_column(Text)
    full_name: Mapped[str | None] = mapped_column(Text)
    company: Mapped[str | None] = mapped_column(Text)
    phone: Mapped[str | None] = mapped_column(Text)
    message: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="pending")
    admin_note: Mapped[str | None] = mapped_column(Text)
    decided_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("profiles.id"))
    decided_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = _now()


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("profiles.id", ondelete="SET NULL"))
    action: Mapped[str] = mapped_column(Text)
    client_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("profiles.id", ondelete="CASCADE"))
    meta: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = _now()
