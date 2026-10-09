import uuid

from fastapi import APIRouter, BackgroundTasks, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy import update
from sqlalchemy.exc import IntegrityError

from app import mailer
from app.config import get_settings
from app.db.models import AuthToken, Invite, Profile
from app.deps import DB, EMAIL_RE, CurrentUser, audit, bearer_token, normalize_email, profile_by_email, read_json
from app.errors import ApiError
from app.limiter import limiter
from app.security import TokenError, decode_access_token, expiry, hash_password, now, password_ok, verify_password
from app.services import tokens
from botocore.exceptions import ClientError as S3Error

from app.services.storage import ALLOWED_TYPES, MAX_SIZE, is_configured as storage_configured, upload_avatar

router = APIRouter(prefix="/api/auth", tags=["auth"])

_NO_STORE = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}


def _frontend(path: str) -> str:
    return get_settings().FRONTEND_URL.rstrip("/") + path


async def _queue_verify_email(db, background: BackgroundTasks, user: Profile) -> None:
    s = get_settings()
    raw = await tokens.create_link_token(db, user.id, "verify_email", expiry(hours=s.VERIFY_EMAIL_TTL_HOURS))
    background.add_task(mailer.send_verify_email, user.email, user.full_name, tokens.verify_link(raw))


@router.post("/signup", status_code=201)
@limiter.limit("10/15 minutes")
async def signup(request: Request, db: DB, background: BackgroundTasks):
    body = await read_json(request)
    email = normalize_email(body.get("email"))
    name = body.get("fullName").strip()[:120] if isinstance(body.get("fullName"), str) else ""
    password = body.get("password")
    if not EMAIL_RE.match(email):
        raise ApiError(400, "INVALID_EMAIL")
    if not name:
        raise ApiError(400, "NAME_REQUIRED")
    if not password_ok(password):
        raise ApiError(400, "WEAK_PASSWORD")

    # Hash before looking the address up, so a new and an existing address take the same time.
    password_hash = await hash_password(password)
    existing = await profile_by_email(db, email)
    if existing is not None:
        if existing.email_verified_at is None and existing.is_active:
            await _queue_verify_email(db, background, existing)
        return {"ok": True}

    user = Profile(email=email, full_name=name, password_hash=password_hash, role="client")
    db.add(user)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return {"ok": True}
    await audit(db, user.id, "client.signup", user.id, {"email": email, "via": "self"})
    await _queue_verify_email(db, background, user)
    return {"ok": True}


@router.post("/resend-verification")
@limiter.limit("10/15 minutes")
async def resend_verification(request: Request, db: DB, background: BackgroundTasks):
    body = await read_json(request)
    email = normalize_email(body.get("email"))
    if EMAIL_RE.match(email):
        user = await profile_by_email(db, email)
        if user is not None and user.is_active and user.email_verified_at is None:
            await _queue_verify_email(db, background, user)
    return {"ok": True}


@router.get("/verify-email")
@limiter.limit("60/15 minutes")
async def verify_email(request: Request, db: DB, token: str = ""):
    """Lands on /email-verified. Only the click that actually performs the verification
    (the first one) gets a one-time session in the redirect fragment, same mechanism as
    /redeem. A mail scanner may open the link before the person does, or the person may
    open a forwarded/stale copy afterwards; either way that replay gets no session at all,
    just the "already verified" state, so the link can never become a reusable backdoor."""
    row = await tokens.find_link_token(db, token, ("verify_email",))
    user = await db.get(Profile, row.user_id) if row is not None else None
    if user is None or not user.is_active or (row.expires_at <= now() and user.email_verified_at is None):
        return RedirectResponse(_frontend("/email-verified?status=expired"), status_code=302, headers=_NO_STORE)
    if user.email_verified_at is None:
        user.email_verified_at = now()
        row.used_at = now()
        await audit(db, user.id, "email.verified", user.id)
        session = await tokens.issue_session(db, user, with_user=False)
        fragment = (f"access_token={session['access_token']}&refresh_token={session['refresh_token']}"
                    f"&expires_in={session['expires_in']}&type=verify")
        return RedirectResponse(_frontend("/email-verified#" + fragment), status_code=302, headers=_NO_STORE)
    return RedirectResponse(_frontend("/email-verified?status=already"), status_code=302, headers=_NO_STORE)


@router.post("/login")
@limiter.limit("20/15 minutes")
async def login(request: Request, db: DB):
    body = await read_json(request)
    email, password = body.get("email"), body.get("password")
    if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
        raise ApiError(400, "Email and password are required")

    user = await profile_by_email(db, normalize_email(email))
    ok = await verify_password(password, user.password_hash if user else None)
    if user is None or not ok or not user.is_active:
        raise ApiError(401, "INVALID_CREDENTIALS")
    if user.email_verified_at is None:
        raise ApiError(403, "EMAIL_NOT_VERIFIED")

    user.last_login_at = now()
    await tokens.purge_expired(db)
    return await tokens.issue_session(db, user)


@router.post("/refresh")
@limiter.limit("120/15 minutes")
async def refresh(request: Request, db: DB):
    body = await read_json(request)
    raw = body.get("refresh_token")
    if not isinstance(raw, str) or not raw:
        raise ApiError(400, "refresh_token required")
    result = await tokens.rotate_refresh(db, raw)
    if result is None:
        raise ApiError(401, "REFRESH_FAILED")
    return result[1]


@router.post("/logout")
async def logout(request: Request, db: DB):
    raw = bearer_token(request)
    if raw:
        try:
            await tokens.revoke_sessions(db, uuid.UUID(decode_access_token(raw)["sub"]))
        except (TokenError, ValueError):
            pass
    return {"ok": True}


@router.post("/forgot-password")
@limiter.limit("10/15 minutes")
async def forgot_password(request: Request, db: DB, background: BackgroundTasks):
    body = await read_json(request)
    email = normalize_email(body.get("email"))
    # Same answer whether or not the address has an account.
    if EMAIL_RE.match(email):
        user = await profile_by_email(db, email)
        if user is not None and user.is_active and user.email_verified_at is not None:
            raw = await tokens.create_link_token(db, user.id, "reset_password", expiry(minutes=get_settings().RESET_PASSWORD_TTL_MINUTES))
            background.add_task(mailer.send_reset_email, user.email, user.full_name, tokens.redeem_link(raw))
    return {"ok": True}


@router.get("/redeem")
@limiter.limit("60/15 minutes")
async def redeem(request: Request, db: DB, token: str = ""):
    """Landing point for invite and password-reset emails: turns the one-time link into a
    session and hands it to the app's /set-password page. The link stays valid until a
    password is actually set, so a mail scanner opening it first does not burn it."""
    row = await tokens.find_link_token(db, token, ("invite", "reset_password"))
    user = await db.get(Profile, row.user_id) if row is not None else None
    if user is None or not user.is_active or row.used_at is not None or row.expires_at <= now():
        return RedirectResponse(_frontend("/set-password"), status_code=302, headers=_NO_STORE)
    if user.email_verified_at is None:
        user.email_verified_at = now()
    session = await tokens.issue_session(db, user, with_user=False)
    fragment = (f"access_token={session['access_token']}&refresh_token={session['refresh_token']}"
                f"&expires_in={session['expires_in']}&type={'invite' if row.kind == 'invite' else 'recovery'}")
    return RedirectResponse(_frontend("/set-password#" + fragment), status_code=302, headers=_NO_STORE)


@router.post("/set-password")
@limiter.limit("20/15 minutes")
async def set_password(request: Request, user: CurrentUser, db: DB):
    body = await read_json(request)
    password = body.get("password")
    if not password_ok(password):
        raise ApiError(400, "WEAK_PASSWORD")
    user.password_hash = await hash_password(password)
    user.updated_at = now()
    await db.execute(update(AuthToken).where(AuthToken.user_id == user.id, AuthToken.kind.in_(("invite", "reset_password")),
                                             AuthToken.used_at.is_(None)).values(used_at=now()))
    await db.execute(update(Invite).where(Invite.email == user.email, Invite.status == "sent").values(status="accepted", accepted_at=now()))
    await audit(db, user.id, "password.set", user.id)
    return {"ok": True, "email": user.email}


@router.post("/change-password")
@limiter.limit("10/15 minutes")
async def change_password(request: Request, user: CurrentUser, db: DB):
    """A signed-in user (admin or client) changes their own password. Every other session is
    signed out; the caller gets a fresh session back so this browser stays signed in."""
    body = await read_json(request)
    current, new = body.get("currentPassword"), body.get("newPassword")
    if not isinstance(current, str) or not await verify_password(current, user.password_hash):
        raise ApiError(400, "WRONG_PASSWORD")
    if not password_ok(new):
        raise ApiError(400, "WEAK_PASSWORD")
    if new == current:
        raise ApiError(400, "SAME_PASSWORD")
    user.password_hash = await hash_password(new)
    user.updated_at = now()
    await tokens.revoke_sessions(db, user.id)
    await audit(db, user.id, "password.changed", user.id if user.role == "client" else None)
    return {"ok": True, "session": await tokens.issue_session(db, user)}


@router.get("/me")
async def me(user: CurrentUser):
    return {"user": tokens.user_json(user)}


@router.put("/profile")
async def update_profile(request: Request, user: CurrentUser, db: DB):
    body = await read_json(request)
    changed = False
    name = body.get("fullName")
    if isinstance(name, str):
        user.full_name = name.strip()[:120]
        changed = True
    phone = body.get("phone")
    if isinstance(phone, str):
        user.phone = phone.strip()[:30] or None
        changed = True
    if changed:
        user.updated_at = now()
        await audit(db, user.id, "profile.updated", user.id if user.role == "client" else None)
    return {"user": tokens.user_json(user)}


@router.post("/avatar")
@limiter.limit("20/15 minutes")
async def upload_avatar_endpoint(request: Request, user: CurrentUser, db: DB, file: UploadFile):
    if not storage_configured():
        raise ApiError(503, "STORAGE_NOT_CONFIGURED", "Avatar upload is not available. Configure Supabase storage first.")
    if file.content_type not in ALLOWED_TYPES:
        raise ApiError(400, "INVALID_FILE_TYPE", f"Allowed types: {', '.join(sorted(ALLOWED_TYPES))}")
    data = await file.read()
    if len(data) > MAX_SIZE:
        raise ApiError(400, "FILE_TOO_LARGE", "Maximum file size is 2 MB.")
    try:
        url = await upload_avatar(user.id, data, file.content_type)
    except S3Error as exc:
        raise ApiError(502, "UPLOAD_FAILED", f"Storage error: {exc}")
    user.avatar_url = url
    user.updated_at = now()
    await audit(db, user.id, "avatar.uploaded", user.id if user.role == "client" else None)
    return {"user": tokens.user_json(user)}


@router.delete("/avatar")
async def remove_avatar(user: CurrentUser, db: DB):
    user.avatar_url = None
    user.updated_at = now()
    return {"user": tokens.user_json(user)}
