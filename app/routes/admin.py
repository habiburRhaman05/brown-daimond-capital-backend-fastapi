import uuid
from datetime import date, timedelta

from fastapi import APIRouter, Request
from sqlalchemy import select

from app.db.models import AuditLog, ChangeRequest, Invite, Profile, SignupRequest
from app.deps import DB, AdminUser, EMAIL_RE, audit, normalize_email, profile_by_email, read_json
from app.errors import ApiError
from app.routes.portal import _check_payload, write_answers
from app.security import now
from app.services import portal as svc
from app.services.invites import open_invite, registered, send_invite

router = APIRouter(prefix="/api/admin", tags=["admin"])

STATUS_FILTER = ("pending", "resolved")
SIGNUP_FILTER = ("pending", "approved", "rejected")


def _uuid(value: str, code: str) -> uuid.UUID:
    try:
        return uuid.UUID(value)
    except ValueError as exc:
        raise ApiError(404, code) from exc


async def _client_or_404(db, client_id: str) -> Profile:
    profile = await db.get(Profile, _uuid(client_id, "CLIENT_NOT_FOUND"))
    if profile is None or profile.role != "client":
        raise ApiError(404, "CLIENT_NOT_FOUND")
    return profile


def _note(body: dict) -> str:
    n = body.get("note")
    return n.strip()[:1000] if isinstance(n, str) else ""


async def _optional_json(request: Request) -> dict:
    try:
        data = await request.json()
    except Exception:
        return {}
    return data if isinstance(data, dict) else {}


async def _reopen_client_portal_for_change_request(db, admin: Profile, request: ChangeRequest, *, hours: int = 24) -> None:
    """Allow the client back into the portal once an admin resolves a change request."""
    profile = await db.get(Profile, request.client_id)
    if profile is None or profile.role != "client":
        return
    data = await svc.load_client(db, profile, create=True)
    if not svc.is_locked(data.cd):
        return
    until = now() + timedelta(hours=hours)
    data.cd.locked_on = None
    data.cd.changes_until = until
    data.cd.updated_at = now()
    await audit(db, admin.id, "request.resolved_reopen", request.client_id, {"requestId": str(request.id), "hours": hours, "changesUntil": svc.iso(until)})


# ── clients ────────────────────────────────────────────────────────────
@router.get("/clients")
async def list_clients(_: AdminUser, db: DB):
    profiles = list((await db.execute(select(Profile).where(Profile.role == "client").order_by(Profile.created_at.desc()))).scalars())
    return {"clients": [svc.summarize(d) for d in await svc.load_many(db, profiles)]}


@router.get("/clients/{client_id}")
async def client_detail(client_id: str, _: AdminUser, db: DB):
    profile = await _client_or_404(db, client_id)
    data = await svc.load_client(db, profile)
    sel = data.sel
    audit_rows = (await db.execute(select(AuditLog).where(AuditLog.client_id == profile.id).order_by(AuditLog.created_at.desc()).limit(100))).scalars()
    return {
        "summary": svc.summarize(data),
        "fields": data.fields,
        "sel": sel,
        "design": svc.design(sel),
        "status": data.status,
        "site": data.site,
        "requests": [svc.public_request(r, with_client=True) for r in sorted(data.requests, key=lambda r: r.created_at, reverse=True)],
        "audit": [{"id": a.id, "actor_id": str(a.actor_id) if a.actor_id else None, "action": a.action,
                   "client_id": str(a.client_id) if a.client_id else None, "meta": a.meta, "created_at": svc.iso(a.created_at)}
                   for a in audit_rows],
    }


@router.get("/clients/{client_id}/prefill")
async def client_prefill(client_id: str, _: AdminUser, db: DB):
    """Same shape as /api/portal/prefill, so the portal page can show a client read-only."""
    profile = await _client_or_404(db, client_id)
    data = await svc.load_client(db, profile)
    return {**data.prefill(), "client": {"id": str(profile.id), "email": profile.email, "name": svc.display_name(profile, data.fields)}}


@router.put("/clients/{client_id}/details")
async def edit_details(client_id: str, request: Request, admin: AdminUser, db: DB):
    """Admin edits ignore the lock but are still stripped of status and system fields."""
    profile = await _client_or_404(db, client_id)
    body = await read_json(request)
    _check_payload(body)
    data = await svc.load_client(db, profile, create=True)
    raw = (await request.body()).decode("utf-8", "replace")
    await write_answers(db, data, body, raw, admin.id)
    fields, _sel = svc.strip_forbidden(body)
    await audit(db, admin.id, "admin.edit_details", profile.id, {"fields": list(fields.keys()), "designChanged": bool(body.get("sel"))})
    return {"ok": True}


@router.put("/clients/{client_id}/site")
async def set_site_info(client_id: str, request: Request, admin: AdminUser, db: DB):
    """Recorded by our team once the website is built; shown on the client's dashboard."""
    profile = await _client_or_404(db, client_id)
    body = await read_json(request)
    data = await svc.load_client(db, profile, create=True)
    cd = data.cd
    if "previewUrl" in body:
        cd.site_preview_url = str(body["previewUrl"] or "")[:500] or None
    if "url" in body:
        cd.site_url = str(body["url"] or "")[:500] or None
    if "clientNumber" in body:
        cd.client_number = str(body["clientNumber"] or "")[:60] or None
    if "deployedOn" in body:
        try:
            cd.site_deployed_on = date.fromisoformat(str(body["deployedOn"])[:10]) if body["deployedOn"] else None
        except ValueError as exc:
            raise ApiError(400, "Invalid payload") from exc
    cd.updated_at = now()
    await audit(db, admin.id, "admin.site_info", profile.id)
    return {"ok": True, "site": svc.site_of(cd)}


@router.post("/clients/{client_id}/reopen")
async def reopen_portal(client_id: str, request: Request, admin: AdminUser, db: DB):
    profile = await _client_or_404(db, client_id)
    body = await _optional_json(request)
    try:
        hours = min(max(int(body.get("hours") or 24), 1), 168)
    except (TypeError, ValueError):
        hours = 24
    data = await svc.load_client(db, profile, create=True)
    if not svc.is_locked(data.cd):
        raise ApiError(409, "NOT_LOCKED")
    until = now() + timedelta(hours=hours)
    data.cd.locked_on = None
    data.cd.changes_until = until
    data.cd.updated_at = now()
    await audit(db, admin.id, "admin.reopen", profile.id, {"hours": hours, "changesUntil": svc.iso(until)})
    return {"ok": True, "changesUntil": svc.iso(until)}


@router.post("/clients/{client_id}/lock")
async def lock_portal(client_id: str, admin: AdminUser, db: DB):
    profile = await _client_or_404(db, client_id)
    data = await svc.load_client(db, profile, create=True)
    if svc.is_locked(data.cd):
        raise ApiError(409, "ALREADY_LOCKED")
    stamp = now()
    data.cd.locked_on = stamp
    data.cd.changes_until = None
    data.cd.updated_at = stamp
    await audit(db, admin.id, "admin.lock", profile.id)
    return {"ok": True, "lockedOn": svc.iso(stamp)}


# ── change requests: pending <-> resolved, switchable both ways ────────────────
@router.get("/change-requests")
async def list_requests(_: AdminUser, db: DB, status: str = ""):
    q = select(ChangeRequest, Profile.email).join(Profile, Profile.id == ChangeRequest.client_id).order_by(ChangeRequest.created_at.desc()).limit(500)
    if status in STATUS_FILTER:
        q = q.where(ChangeRequest.status == status)
    rows = (await db.execute(q)).all()
    return {"requests": [{**svc.public_request(r, with_client=True), "clientEmail": email} for r, email in rows]}


async def _set_request_status(db, admin: Profile, request_id: str, request: Request, status: str) -> dict:
    cr = await db.get(ChangeRequest, _uuid(request_id, "REQUEST_NOT_FOUND"))
    if cr is None:
        raise ApiError(404, "REQUEST_NOT_FOUND")
    body = await _optional_json(request)
    note = _note(body)
    if cr.status != status:
        cr.status = status
        cr.resolved_by = admin.id if status == "resolved" else None
        cr.resolved_at = now() if status == "resolved" else None
        cr.updated_at = now()
        await audit(db, admin.id, f"request.{ 'resolved' if status == 'resolved' else 'reopened' }", cr.client_id,
                    {"requestId": str(cr.id), "part": cr.part})
    if "note" in body:
        cr.admin_note = note or None
        cr.updated_at = now()
    if status == "resolved":
        await _reopen_client_portal_for_change_request(db, admin, cr)
    return {"ok": True, "request": svc.public_request(cr, with_client=True)}


@router.post("/change-requests/{request_id}/resolve")
async def resolve_request(request_id: str, request: Request, admin: AdminUser, db: DB):
    return await _set_request_status(db, admin, request_id, request, "resolved")


@router.post("/change-requests/{request_id}/reopen")
async def reopen_request(request_id: str, request: Request, admin: AdminUser, db: DB):
    return await _set_request_status(db, admin, request_id, request, "pending")


# ── invites ────────────────────────────────────────────────────────────
def _invite_json(i: Invite) -> dict:
    return {"id": str(i.id), "email": i.email, "status": i.status, "created_at": svc.iso(i.created_at),
            "accepted_at": svc.iso(i.accepted_at) or None}


@router.get("/invites")
async def list_invites(_: AdminUser, db: DB):
    rows = (await db.execute(select(Invite).order_by(Invite.created_at.desc()).limit(200))).scalars()
    return {"invites": [_invite_json(i) for i in rows]}


@router.post("/invites", status_code=201)
async def create_invite(request: Request, admin: AdminUser, db: DB):
    body = await read_json(request)
    email = normalize_email(body.get("email"))
    if not EMAIL_RE.match(email):
        raise ApiError(400, "INVALID_EMAIL")
    existing = await profile_by_email(db, email)
    if registered(existing):
        raise ApiError(409, "ALREADY_REGISTERED")
    if await open_invite(db, email) is not None:
        raise ApiError(409, "INVITE_PENDING")
    invite = await send_invite(db, email, admin.id, existing)
    await audit(db, admin.id, "invite.sent", None, {"email": email})
    await db.refresh(invite)
    return {"ok": True, "invite": _invite_json(invite)}


@router.delete("/invites/{invite_id}")
async def revoke_invite(invite_id: str, admin: AdminUser, db: DB):
    invite = await db.get(Invite, _uuid(invite_id, "INVITE_NOT_FOUND"))
    if invite is None:
        raise ApiError(404, "INVITE_NOT_FOUND")
    if invite.status != "sent":
        raise ApiError(409, "INVITE_NOT_OPEN")
    invite.status = "revoked"
    # Drop the never-used account so the emailed link stops working.
    user = await profile_by_email(db, invite.email)
    if user is not None and not registered(user) and user.last_login_at is None:
        await db.delete(user)
    await audit(db, admin.id, "invite.revoked", None, {"email": invite.email})
    return {"ok": True}


# ── signup requests (the public "request access" form) ─────────────────────────
def _signup_json(r: SignupRequest) -> dict:
    return {"id": str(r.id), "email": r.email, "fullName": r.full_name or "", "company": r.company or "",
            "phone": r.phone or "", "message": r.message or "", "status": r.status, "adminNote": r.admin_note or "",
            "createdAt": svc.iso(r.created_at), "decidedAt": svc.iso(r.decided_at) or None}


@router.get("/signup-requests")
async def list_signup_requests(_: AdminUser, db: DB, status: str = ""):
    q = select(SignupRequest).order_by(SignupRequest.created_at.desc()).limit(200)
    if status in SIGNUP_FILTER:
        q = q.where(SignupRequest.status == status)
    return {"requests": [_signup_json(r) for r in (await db.execute(q)).scalars()]}


async def _pending_signup(db, request_id: str) -> SignupRequest:
    sr = await db.get(SignupRequest, _uuid(request_id, "REQUEST_NOT_FOUND"))
    if sr is None:
        raise ApiError(404, "REQUEST_NOT_FOUND")
    if sr.status != "pending":
        raise ApiError(409, "ALREADY_DECIDED")
    return sr


@router.post("/signup-requests/{request_id}/approve")
async def approve_signup(request_id: str, request: Request, admin: AdminUser, db: DB):
    """Approve = send the person an invite email; they choose a password from the link."""
    sr = await _pending_signup(db, request_id)
    body = await _optional_json(request)
    email = normalize_email(sr.email)
    existing = await profile_by_email(db, email)
    sr.status, sr.decided_by, sr.decided_at, sr.admin_note = "approved", admin.id, now(), _note(body) or None

    if registered(existing):
        sr.admin_note = "Already registered"
        await db.commit()
        raise ApiError(409, "ALREADY_REGISTERED")
    if await open_invite(db, email) is None:
        await send_invite(db, email, admin.id, existing, sr.full_name or "")
    await audit(db, admin.id, "signup.approved", None, {"email": email, "requestId": str(sr.id)})
    return {"ok": True, "request": _signup_json(sr)}


@router.post("/signup-requests/{request_id}/reject")
async def reject_signup(request_id: str, request: Request, admin: AdminUser, db: DB):
    sr = await _pending_signup(db, request_id)
    body = await _optional_json(request)
    sr.status, sr.decided_by, sr.decided_at, sr.admin_note = "rejected", admin.id, now(), _note(body) or None
    await audit(db, admin.id, "signup.rejected", None, {"email": sr.email, "requestId": str(sr.id)})
    return {"ok": True, "request": _signup_json(sr)}
