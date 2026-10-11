import uuid

import structlog
from botocore.exceptions import ClientError as S3Error
from fastapi import APIRouter, BackgroundTasks, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
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
from app.services.storage import ALLOWED_TYPES, MAX_SIZE, delete_avatar, detect_image_type, is_configured as storage_configured, upload_avatar

router = APIRouter(prefix="/api/auth", tags=["auth"])
log = structlog.get_logger()

_NO_STORE = {"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"}
COOKIE_PATH = "/api/auth"  # the refresh cookie is only ever sent to the auth endpoints


def _set_refresh_cookie(response, raw: str) -> None:
    s = get_settings()
    response.set_cookie(s.REFRESH_COOKIE_NAME, raw, max_age=s.REFRESH_TOKEN_TTL_DAYS * 86400,
                        httponly=True, secure=s.is_production, samesite="lax", path=COOKIE_PATH)


def _clear_refresh_cookie(response) -> None:
    s = get_settings()
    response.delete_cookie(s.REFRESH_COOKIE_NAME, path=COOKIE_PATH, httponly=True, secure=s.is_production, samesite="lax")


def session_response(session: dict, **extra) -> JSONResponse:
    """JSON for the browser app plus the refresh token as an HttpOnly cookie. The refresh token is
    never part of the body, so scripts running on the page (including injected ones) cannot read it."""
    resp = JSONResponse({**{k: v for k, v in session.items() if k != "refresh_token"}, **extra})
    _set_refresh_cookie(resp, session["refresh_token"])
    return resp


def _check_origin(request: Request) -> None:
    """Defence in depth on top of SameSite=Lax: a browser POST that names a foreign origin is refused.
    Requests with no Origin header (curl, server-to-server) carry no browser cookie jar, so they pass."""
    origin = request.headers.get("origin")
    if origin and not get_settings().origin_allowed(origin):
        raise ApiError(403, "BAD_ORIGIN")


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

    existing = await profile_by_email(db, email)
    if existing is not None:
        if existing.email_verified_at is None and existing.is_active:
            # They may have lost the first email. Returned (not raised) so the new token is committed
            # and the background email still runs; an exception would roll back and skip both.
            await _queue_verify_email(db, background, existing)
            return JSONResponse({"error": "EMAIL_NOT_VERIFIED"}, status_code=409)
        raise ApiError(409, "EMAIL_EXISTS")

    password_hash = await hash_password(password)
    user = Profile(email=email, full_name=name, password_hash=password_hash, role="client")
    db.add(user)
    try:
        await db.flush()
    except IntegrityError as exc:  # someone registered this address a moment ago
        await db.rollback()
        raise ApiError(409, "EMAIL_EXISTS") from exc
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
    (the first one) gets a one-time sign-in grant in the redirect fragment, same mechanism as
    /redeem; the app trades it for a session at /exchange. A mail scanner may open the link before the person does, or the person may
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
        grant = await _new_grant(db, user)
        return RedirectResponse(_frontend(f"/email-verified#grant={grant}&type=verify"), status_code=302, headers=_NO_STORE)
    return RedirectResponse(_frontend("/email-verified?status=already"), status_code=302, headers=_NO_STORE)


@router.post("/login")
@limiter.limit("20/15 minutes")
async def login(request: Request, db: DB):
    body = await read_json(request)
    email, password = body.get("email"), body.get("password")
    if not isinstance(email, str) or not isinstance(password, str) or not email or not password:
        raise ApiError(400, "Email and password are required")

    user = await profile_by_email(db, normalize_email(email))
    if user is None:
        raise ApiError(404, "ACCOUNT_NOT_FOUND")
    if not user.is_active:
        raise ApiError(403, "ACCOUNT_DISABLED")
    if not await verify_password(password, user.password_hash):
        raise ApiError(401, "INVALID_CREDENTIALS")
    if user.email_verified_at is None:
        raise ApiError(403, "EMAIL_NOT_VERIFIED")

    user.last_login_at = now()
    await tokens.purge_expired(db)
    return session_response(await tokens.issue_session(db, user))


@router.post("/refresh")
@limiter.limit("120/15 minutes")
async def refresh(request: Request, db: DB):
    """Trade the refresh cookie for a new access token (and a rotated cookie). The refresh token is
    read only from the HttpOnly cookie, never from the request body."""
    _check_origin(request)
    raw = request.cookies.get(get_settings().REFRESH_COOKIE_NAME)
    result = await tokens.rotate_refresh(db, raw) if raw else None
    if result is None:
        failed = JSONResponse({"error": "REFRESH_FAILED"}, status_code=401)
        if raw:
            _clear_refresh_cookie(failed)  # a dead cookie should not be retried on every page load
        return failed
    user, session = result
    return session_response(session, user=tokens.user_json(user))


async def _new_grant(db, user: Profile) -> str:
    return await tokens.create_link_token(db, user.id, "session_grant", expiry(minutes=get_settings().GRANT_TTL_MINUTES))


@router.post("/exchange")
@limiter.limit("30/15 minutes")
async def exchange(request: Request, db: DB):
    """Trade the one-time grant from an emailed link (verify / invite / reset) for a real session.
    The grant is short-lived and single-use, so the address bar never holds a lasting credential."""
    _check_origin(request)
    body = await read_json(request)
    raw = body.get("grant")
    row = await tokens.find_link_token(db, raw if isinstance(raw, str) else "", ("session_grant",))
    user = await db.get(Profile, row.user_id) if row is not None else None
    if user is None or not user.is_active or user.email_verified_at is None or row.used_at is not None or row.expires_at <= now():
        raise ApiError(401, "GRANT_INVALID")
    # Claim the grant atomically: of several simultaneous requests carrying the same grant, only one wins.
    claimed = await db.execute(update(AuthToken).where(AuthToken.id == row.id, AuthToken.used_at.is_(None)).values(used_at=now()))
    if claimed.rowcount != 1:
        raise ApiError(401, "GRANT_INVALID")
    return session_response(await tokens.issue_session(db, user))


@router.post("/logout")
async def logout(request: Request, db: DB):
    """Ends the user's sessions and clears the cookie. The user is identified by the access token
    if it is still valid, otherwise by the refresh cookie, so an expired access token cannot stop a sign-out."""
    _check_origin(request)
    user_id = None
    raw = bearer_token(request)
    if raw:
        try:
            user_id = uuid.UUID(decode_access_token(raw)["sub"])
        except (TokenError, ValueError, KeyError):
            pass
    cookie = request.cookies.get(get_settings().REFRESH_COOKIE_NAME)
    if user_id is None and cookie:
        row = await tokens.find_link_token(db, cookie, ("refresh",))
        user_id = row.user_id if row is not None else None
    if user_id is not None:
        await tokens.revoke_sessions(db, user_id)
    resp = JSONResponse({"ok": True})
    _clear_refresh_cookie(resp)
    return resp


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
    sign-in grant and hands it to the app's /set-password page (which trades it at /exchange). The link stays valid until a
    password is actually set, so a mail scanner opening it first does not burn it."""
    row = await tokens.find_link_token(db, token, ("invite", "reset_password"))
    user = await db.get(Profile, row.user_id) if row is not None else None
    if user is None or not user.is_active or row.used_at is not None or row.expires_at <= now():
        return RedirectResponse(_frontend("/set-password"), status_code=302, headers=_NO_STORE)
    if user.email_verified_at is None:
        user.email_verified_at = now()
    grant = await _new_grant(db, user)
    kind = "invite" if row.kind == "invite" else "recovery"
    return RedirectResponse(_frontend(f"/set-password#grant={grant}&type={kind}"), status_code=302, headers=_NO_STORE)


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
    session = await tokens.issue_session(db, user)
    resp = JSONResponse({"ok": True, "session": {k: v for k, v in session.items() if k != "refresh_token"}})
    _set_refresh_cookie(resp, session["refresh_token"])
    return resp


@router.get("/me")
async def me(user: CurrentUser):
    return {"user": tokens.user_json(user)}


@router.put("/profile")
async def update_profile(request: Request, user: CurrentUser, db: DB):
    body = await read_json(request)
    changed = False
    name = body.get("fullName")
    if isinstance(name, str):
        if not name.strip():
            raise ApiError(400, "NAME_REQUIRED")
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
        raise ApiError(503, "STORAGE_NOT_CONFIGURED")
    if file.content_type not in ALLOWED_TYPES:
        raise ApiError(400, "INVALID_FILE_TYPE")
    data = await file.read(MAX_SIZE + 1)  # never buffer more than one byte over the limit
    if len(data) > MAX_SIZE:
        raise ApiError(400, "FILE_TOO_LARGE")
    if detect_image_type(data) != file.content_type:
        raise ApiError(400, "INVALID_FILE_TYPE")
    try:
        key = await upload_avatar(user.id, data, file.content_type)
    except S3Error as exc:
        log.error("avatar_upload_failed", user_id=str(user.id), error=repr(exc))
        raise ApiError(502, "UPLOAD_FAILED") from exc
    user.avatar_url = key
    user.updated_at = now()
    await audit(db, user.id, "avatar.uploaded", user.id if user.role == "client" else None)
    return {"user": tokens.user_json(user)}


@router.delete("/avatar")
async def remove_avatar(user: CurrentUser, db: DB):
    if storage_configured():
        await delete_avatar(user.id)
    user.avatar_url = None
    user.updated_at = now()
    return {"user": tokens.user_json(user)}
