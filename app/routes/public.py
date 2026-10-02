from fastapi import APIRouter, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.db.models import SignupRequest
from app.deps import DB, EMAIL_RE, audit, normalize_email, profile_by_email, read_json
from app.errors import ApiError
from app.limiter import limiter

router = APIRouter(tags=["public"])


def _trim(value: object, limit: int) -> str:
    return value.strip()[:limit] if isinstance(value, str) else ""


@router.post("/api/signup-request", status_code=201)
@limiter.limit("10/hour")
async def signup_request(request: Request, db: DB):
    """Public "request access" form. Lands as a pending row for an admin to approve or reject."""
    body = await read_json(request)
    email = normalize_email(body.get("email"))
    full_name = _trim(body.get("fullName") or body.get("full_name"), 120)
    if not EMAIL_RE.match(email):
        raise ApiError(400, "INVALID_EMAIL")
    if not full_name:
        raise ApiError(400, "NAME_REQUIRED")

    # An address that already has an account or an open request gets the same friendly answer,
    # so this form cannot be used to find out who is registered.
    if await profile_by_email(db, email) is not None:
        return {"ok": True}
    open_request = (await db.execute(select(SignupRequest.id).where(SignupRequest.email == email, SignupRequest.status == "pending"))).first()
    if open_request:
        return {"ok": True}

    req = SignupRequest(email=email, full_name=full_name, company=_trim(body.get("company"), 160) or None,
                        phone=_trim(body.get("phone"), 40) or None, message=_trim(body.get("message"), 2000) or None)
    db.add(req)
    try:
        await db.flush()
    except IntegrityError:
        await db.rollback()
        return {"ok": True}
    await audit(db, None, "signup.requested", None, {"email": email, "requestId": str(req.id)})
    return {"ok": True}
