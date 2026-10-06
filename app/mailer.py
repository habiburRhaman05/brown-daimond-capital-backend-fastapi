"""Email goes through a GoHighLevel workflow: we POST one JSON payload per message to its
webhook and the workflow, branching on `type`, builds and sends the email. Nothing here speaks SMTP.

Every payload has: type, app, sent_at, to_email, to_name, login_url. Then, per type:

  verify_email    verify_url, expires_in_hours
  invite          invite_url, expires_in_days
  reset_password  reset_url, expires_in_minutes
  portal_submitted (to the admin)  client_email
  change_request   (to the admin)  client_email, part, text
"""
import httpx
import structlog

from app.config import get_settings
from app.security import now

log = structlog.get_logger()


async def post_to_ghl(payload: dict) -> bool:
    """POST one payload to the GHL webhook. Returns True when GHL accepted it. Never raises."""
    s = get_settings()
    kind = payload.get("type")
    if not s.GHL_WEBHOOK_URL:
        if s.is_production:
            log.error("email_not_sent_webhook_missing", kind=kind, to=payload.get("to_email"))
            return False
        log.warning("email_dev_only_not_sent", kind=kind, to=payload.get("to_email"),
                    link=payload.get("verify_url") or payload.get("invite_url") or payload.get("reset_url"))
        return True
    headers = {"Content-Type": "application/json"}
    if s.GHL_WEBHOOK_SECRET:
        headers["X-Webhook-Secret"] = s.GHL_WEBHOOK_SECRET
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(s.GHL_WEBHOOK_URL, json=payload, headers=headers)
        if resp.status_code >= 300:
            log.error("ghl_webhook_rejected", kind=kind, status=resp.status_code, body=resp.text[:200])
            return False
        log.info("email_sent", kind=kind, to=payload.get("to_email"))
        return True
    except httpx.HTTPError as exc:
        log.error("ghl_webhook_failed", kind=kind, error=repr(exc))
        return False


MAILING_ADDRESS = "Brown Diamond Capital, 3400 Cottage Way, Ste G2 #36795, Sacramento, CA 95825"


def _base(kind: str, to_email: str, to_name: str = "") -> dict:
    s = get_settings()
    return {
        "type": kind,
        "app": "bdcap-portal",
        "sent_at": now().isoformat(),
        "to_email": to_email,
        "to_name": to_name or "",
        "login_url": s.FRONTEND_URL.rstrip("/") + "/client/login",
        "mailing_address": MAILING_ADDRESS,
    }


async def send_verify_email(email: str, name: str, link: str) -> bool:
    s = get_settings()
    return await post_to_ghl({**_base("verify_email", email, name), "verify_url": link,
                              "expires_in_hours": s.VERIFY_EMAIL_TTL_HOURS})


async def send_invite_email(email: str, link: str) -> bool:
    s = get_settings()
    return await post_to_ghl({**_base("invite", email), "invite_url": link, "expires_in_days": s.INVITE_TTL_DAYS})


async def send_reset_email(email: str, name: str, link: str) -> bool:
    s = get_settings()
    return await post_to_ghl({**_base("reset_password", email, name), "reset_url": link,
                              "expires_in_minutes": s.RESET_PASSWORD_TTL_MINUTES})


async def notify_portal_submitted(client_email: str) -> bool:
    to = get_settings().ADMIN_NOTIFY_EMAIL
    return bool(to) and await post_to_ghl({**_base("portal_submitted", to), "client_email": client_email})


async def notify_change_request(client_email: str, part: str, text: str) -> bool:
    to = get_settings().ADMIN_NOTIFY_EMAIL
    return bool(to) and await post_to_ghl({**_base("change_request", to), "client_email": client_email, "part": part, "text": text})
