"""The signed-in client's own data: what the portal page reads and writes, plus the dashboard views."""
from fastapi import APIRouter, BackgroundTasks, Request

from app import mailer
from app.db.models import ChangeRequest
from app.deps import DB, CurrentUser, audit, read_json
from app.errors import ApiError
from app.limiter import limiter
from app.security import now
from app.services import portal as svc

portal_router = APIRouter(prefix="/api/portal", tags=["portal"])
client_router = APIRouter(prefix="/api/client", tags=["client"])

PARTS = ("website", "team", "you", "business")


def _check_payload(body: dict) -> None:
    for key in ("fields", "sel"):
        if key in body and body[key] is not None and not isinstance(body[key], dict):
            raise ApiError(400, "Invalid payload")


async def write_answers(db, data: svc.ClientData, body: dict, raw: str, actor) -> bool:
    """Apply a save payload. Returns True if anything changed."""
    fields, sel = svc.strip_forbidden(body)
    before = data.fields
    svc.apply_fields(data.cd, fields)
    changed = data.fields != before
    if await svc.save_site_config(db, data.profile.id, sel, raw, actor):
        changed = True
    if changed:
        data.cd.updated_at = now()
    return changed


# ── portal page ────────────────────────────────────────────────────────────────
@portal_router.get("/prefill")
async def prefill(user: CurrentUser, db: DB):
    return (await svc.load_client(db, user)).prefill()


@portal_router.post("/save")
@limiter.limit("30/minute")
async def save(request: Request, user: CurrentUser, db: DB):
    body = await read_json(request)
    _check_payload(body)
    data = await svc.load_client(db, user, create=True)
    if svc.is_locked(data.cd):
        raise ApiError(423, "LOCKED", message="Portal is locked")
    changed = await write_answers(db, data, body, (await request.body()).decode("utf-8", "replace"), user.id)
    return {"ok": True} if changed else {"ok": True, "unchanged": True}


@portal_router.post("/submit")
@limiter.limit("30/minute")
async def submit(request: Request, user: CurrentUser, db: DB, background: BackgroundTasks):
    body = await read_json(request)
    _check_payload(body)
    data = await svc.load_client(db, user, create=True)
    if svc.is_locked(data.cd):
        raise ApiError(423, "LOCKED", message="Portal is already locked")
    await write_answers(db, data, body, (await request.body()).decode("utf-8", "replace"), user.id)

    # The server sets the timestamps; whatever the client sent is discarded.
    stamp = now()
    data.cd.completed_on = stamp
    data.cd.locked_on = stamp
    data.cd.changes_until = None
    data.cd.updated_at = stamp
    await audit(db, user.id, "portal.submit", user.id)
    background.add_task(mailer.notify_portal_submitted, user.email)
    return {"ok": True, "completedOn": svc.iso(stamp), "lockedOn": svc.iso(stamp)}


@portal_router.post("/change-request")
@limiter.limit("30/minute")
async def change_request(request: Request, user: CurrentUser, db: DB, background: BackgroundTasks):
    body = await read_json(request)
    part, text = body.get("part"), body.get("text")
    if body.get("type") != "change_request":
        raise ApiError(400, "Invalid type")
    if part not in PARTS:
        raise ApiError(400, "Invalid part")
    if not isinstance(text, str) or not text.strip() or len(text) > 2000:
        raise ApiError(400, "Text is required (max 2000 chars)")

    row = ChangeRequest(client_id=user.id, part=part, text=text.strip(), status="pending")
    db.add(row)
    await db.flush()
    await db.refresh(row)
    await audit(db, user.id, "request.created", user.id, {"requestId": str(row.id), "part": part})
    background.add_task(mailer.notify_change_request, user.email, part, row.text)
    return {"ok": True, "request": {"id": str(row.id), "part": part, "text": row.text, "status": row.status, "at": svc.iso(row.created_at)}}


# ── client dashboard (read-only) ───────────────────────────────────────────────
@client_router.get("/overview")
async def overview(user: CurrentUser, db: DB):
    data = await svc.load_client(db, user, create=True)
    return {
        "profile": {"id": str(user.id), "email": user.email, "role": user.role, "createdAt": svc.iso(user.created_at)},
        "summary": svc.summarize(data),
        "design": svc.design(data.sel),
    }


@client_router.get("/details")
async def details(user: CurrentUser, db: DB):
    data = await svc.load_client(db, user)
    sel = data.sel
    return {"fields": data.fields, "sel": sel, "status": data.status, "site": data.site, "design": svc.design(sel)}


@client_router.get("/change-requests")
async def my_requests(user: CurrentUser, db: DB):
    data = await svc.load_client(db, user)
    ordered = sorted(data.requests, key=lambda r: r.created_at, reverse=True)
    return {"requests": [svc.public_request(r) for r in ordered]}
