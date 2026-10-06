"""Everything about turning a client's stored answers into the shapes the portal page and the
dashboards expect ({fields, sel, status, site}), and back."""
import re
import uuid
from datetime import date, datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ChangeRequest, ClientDetail, ClientNumber, Profile, SiteConfig, SiteConfigHistory
from app.security import now

# ── field map: portal key -> client_details column ─────────────────────────────
TEXT_COLUMNS = {
    "legalFirstName": "legal_first_name",
    "legalLastName": "legal_last_name",
    "personalEmail": "personal_email",
    "personalPhone": "personal_phone",
    "mailingStreet": "mailing_street",
    "mailingCity": "mailing_city",
    "mailingState": "mailing_state",
    "mailingZip": "mailing_zip",
    "preferredContact": "preferred_contact",
    "bizNameInput": "business_name",
    "backupName1": "backup_name_1",
    "backupName2": "backup_name_2",
    "themeSelect": "business_theme",
    "purposeText": "purpose_text",
    "naicsField": "naics_code",
    "sicField": "sic_code",
    "domainInput": "domain_name",
    "taglineInput": "tagline",
    "ctaSel": "cta_text",
}
# Always present in a prefill, even when empty (the portal expects them).
ALWAYS_PRESENT = ("personalPhone", "mailingStreet", "mailingCity", "mailingState", "mailingZip")
CONTACT_TIMES = {"contactTimeMorning": "Morning", "contactTimeEvening": "Evening", "contactTimeNight": "Night"}
TEAM_KEYS = ("role", "name", "email", "phone", "relationship")
TEAM_RE = re.compile(r"^team_(role|name|email|phone|relationship)_([1-5])$")
MAX_TEAM_ROWS = 5

# Set by the server only. A client (or an admin editing details) can never write these.
FORBIDDEN_FIELDS = {
    "lockedOn", "changesUntil", "completedOn", "clientNumber",
    "sitePreviewUrl", "siteDeployedOn", "siteUrl", "contactFirstName", "contactLastName",
}
SERVER_SEL_KEYS = {"completedOn", "lockedOn", "changesUntil", "changeRequests"}

MAX_VALUE_LEN = 5000
MAX_EXTRA_KEYS = 200
MAX_KEY_LEN = 100


def iso(dt: datetime | None) -> str:
    """Same format as JavaScript's Date.toISOString(); '' when unset (what the page expects)."""
    if dt is None:
        return ""
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _s(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else ""
    return str(value)[:MAX_VALUE_LEN]


def _parse_date(value: object) -> date | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return date.fromisoformat(value.strip()[:10])
    except ValueError:
        return None


# ── lock state (mirrors the portal page) ───────────────────────────────────────
def is_locked(cd: ClientDetail | None, at: datetime | None = None) -> bool:
    """Locked unless a reopened window is currently open. An expired window counts as locked."""
    if cd is None:
        return False
    at = at or now()
    if cd.changes_until and cd.changes_until > at:
        return False
    if cd.locked_on:
        return True
    return bool(cd.changes_until)


def portal_state(cd: ClientDetail | None, has_data: bool, at: datetime | None = None) -> str:
    """not_started | in_progress | submitted | reopened"""
    at = at or now()
    if cd and cd.changes_until and cd.changes_until > at and not cd.locked_on:
        return "reopened"
    if is_locked(cd, at):
        return "submitted"
    return "in_progress" if has_data else "not_started"


def status_of(cd: ClientDetail | None) -> dict:
    return {
        "completedOn": iso(cd.completed_on) if cd else "",
        "lockedOn": iso(cd.locked_on) if cd else "",
        "changesUntil": iso(cd.changes_until) if cd else "",
    }


def site_of(cd: ClientDetail | None) -> dict:
    return {
        "previewUrl": (cd.site_preview_url or "") if cd else "",
        "deployedOn": cd.site_deployed_on.isoformat() if cd and cd.site_deployed_on else "",
        "url": (cd.site_url or "") if cd else "",
        "clientNumber": (cd.client_number or "") if cd else "",
    }


# ── stored answers -> portal fields ────────────────────────────────────────────
def fields_of(cd: ClientDetail | None, profile: Profile) -> dict:
    f: dict = {}
    if cd is not None:
        for k, v in (cd.raw_fields or {}).items():
            if k not in FORBIDDEN_FIELDS:
                f[k] = v
        for key, col in TEXT_COLUMNS.items():
            v = getattr(cd, col)
            if v is not None:
                f[key] = v
    for key in ALWAYS_PRESENT:
        f.setdefault(key, "")
    f["personalEmail"] = (cd.personal_email if cd and cd.personal_email else None) or profile.email
    f["dateOfBirth"] = cd.date_of_birth.isoformat() if cd and cd.date_of_birth else ""

    times = (cd.contact_time if cd else None) or []
    if times:
        for key, label in CONTACT_TIMES.items():
            f[key] = label in times

    members = (cd.team_members if cd else None) or []
    for i in range(1, MAX_TEAM_ROWS + 1):
        row = members[i - 1] if i <= len(members) and isinstance(members[i - 1], dict) else {}
        if i == 1 or any(row.get(k) for k in TEAM_KEYS):
            for k in TEAM_KEYS:
                if k == "relationship" and i == 1 and not row.get(k):
                    continue
                f[f"team_{k}_{i}"] = row.get(k, "") or ""
    return f


def mirror_of(requests: list[ChangeRequest]) -> list[dict]:
    """The Site Config copy of the change requests, oldest first (the order the page renders)."""
    out = []
    for r in sorted(requests, key=lambda r: r.created_at):
        item = {"id": str(r.id), "at": iso(r.created_at), "part": r.part, "text": r.text, "status": r.status}
        if r.admin_note:
            item["adminNote"] = r.admin_note
        out.append(item)
    return out


def sel_of(cfg: SiteConfig | None, cd: ClientDetail | None, requests: list[ChangeRequest]) -> dict:
    sel = dict(cfg.config_data) if cfg and isinstance(cfg.config_data, dict) else {}
    sel.update(status_of(cd))
    sel["changeRequests"] = mirror_of(requests)
    return sel


class ClientData:
    """One client's stored data, loaded together."""

    def __init__(self, profile: Profile, cd: ClientDetail | None, cfg: SiteConfig | None, requests: list[ChangeRequest],
                 numbers: list[ClientNumber] | None = None):
        self.profile = profile
        self.cd = cd
        self.cfg = cfg
        self.requests = requests
        self.numbers = numbers or []

    @property
    def fields(self) -> dict:
        return fields_of(self.cd, self.profile)

    @property
    def sel(self) -> dict:
        return sel_of(self.cfg, self.cd, self.requests)

    @property
    def status(self) -> dict:
        return status_of(self.cd)

    @property
    def site(self) -> dict:
        return site_of(self.cd)

    def prefill(self) -> dict:
        return {"fields": self.fields, "sel": self.sel, "status": self.status, "site": self.site}


async def load_client(db: AsyncSession, profile: Profile, *, create: bool = False) -> ClientData:
    cd = await db.get(ClientDetail, profile.id)
    if cd is None and create:
        cd = ClientDetail(user_id=profile.id, contact_time=[], team_members=[], raw_fields={})
        db.add(cd)
        await db.flush()
    cfg = await db.get(SiteConfig, profile.id)
    requests = list((await db.execute(
        select(ChangeRequest).where(ChangeRequest.client_id == profile.id).order_by(ChangeRequest.created_at.desc())
    )).scalars())
    numbers = list((await db.execute(
        select(ClientNumber).where(ClientNumber.client_id == profile.id).order_by(ClientNumber.created_at)
    )).scalars())
    return ClientData(profile, cd, cfg, requests, numbers)


async def load_many(db: AsyncSession, profiles: list[Profile]) -> list[ClientData]:
    """All clients for the admin list in five queries, not five per client."""
    ids = [p.id for p in profiles]
    if not ids:
        return []
    cds = {c.user_id: c for c in (await db.execute(select(ClientDetail).where(ClientDetail.user_id.in_(ids)))).scalars()}
    cfgs = {c.client_id: c for c in (await db.execute(select(SiteConfig).where(SiteConfig.client_id.in_(ids)))).scalars()}
    reqs: dict[uuid.UUID, list[ChangeRequest]] = {}
    for r in (await db.execute(select(ChangeRequest).where(ChangeRequest.client_id.in_(ids)))).scalars():
        reqs.setdefault(r.client_id, []).append(r)
    nums: dict[uuid.UUID, list[ClientNumber]] = {}
    for n in (await db.execute(select(ClientNumber).where(ClientNumber.client_id.in_(ids)).order_by(ClientNumber.created_at))).scalars():
        nums.setdefault(n.client_id, []).append(n)
    return [ClientData(p, cds.get(p.id), cfgs.get(p.id), reqs.get(p.id, []), nums.get(p.id, [])) for p in profiles]


async def pending_count(db: AsyncSession, client_id: uuid.UUID) -> int:
    return (await db.execute(
        select(func.count()).select_from(ChangeRequest).where(ChangeRequest.client_id == client_id, ChangeRequest.status == "pending")
    )).scalar_one()


# ── portal fields -> stored answers ────────────────────────────────────────────
def strip_forbidden(body: dict) -> tuple[dict, dict]:
    fields = body.get("fields") if isinstance(body.get("fields"), dict) else {}
    sel = body.get("sel") if isinstance(body.get("sel"), dict) else {}
    return (
        {k: v for k, v in fields.items() if k not in FORBIDDEN_FIELDS},
        {k: v for k, v in sel.items() if k not in SERVER_SEL_KEYS},
    )


def apply_fields(cd: ClientDetail, fields: dict) -> None:
    """Write the answers the page sent onto the typed columns; anything unmapped goes to raw_fields."""
    members = [dict(m) if isinstance(m, dict) else {} for m in (cd.team_members or [])]
    while len(members) < MAX_TEAM_ROWS:
        members.append({})
    times = list(cd.contact_time or [])
    raw = dict(cd.raw_fields or {})
    time_touched = False

    for key, value in fields.items():
        if not isinstance(key, str) or len(key) > MAX_KEY_LEN:
            continue
        if key in TEXT_COLUMNS:
            setattr(cd, TEXT_COLUMNS[key], _s(value))
        elif key == "dateOfBirth":
            cd.date_of_birth = _parse_date(value)
        elif key in CONTACT_TIMES:
            time_touched = True
            label = CONTACT_TIMES[key]
            if value is True or value == "true":
                if label not in times:
                    times.append(label)
            elif label in times:
                times.remove(label)
        elif (m := TEAM_RE.match(key)):
            members[int(m.group(2)) - 1][m.group(1)] = _s(value)
        elif isinstance(value, (str, int, float, bool)) or value is None:
            if key in raw or len(raw) < MAX_EXTRA_KEYS:
                raw[key] = value if isinstance(value, bool) else _s(value)

    while members and not any(members[-1].get(k) for k in TEAM_KEYS):
        members.pop()
    if time_touched:
        order = list(CONTACT_TIMES.values())
        cd.contact_time = [t for t in order if t in times]
    cd.team_members = members
    cd.raw_fields = raw


async def save_site_config(db: AsyncSession, client_id: uuid.UUID, incoming_sel: dict, raw_body: str,
                           actor_id: uuid.UUID | None) -> bool:
    """Store the design exactly as sent (only the server-owned keys are removed). Returns True if it changed."""
    cfg = await db.get(SiteConfig, client_id)
    if cfg is None:
        if not incoming_sel:
            return False
        db.add(SiteConfig(client_id=client_id, config_data=incoming_sel, config_raw=raw_body, version=1, updated_by=actor_id))
        return True
    merged = {**(cfg.config_data or {}), **incoming_sel}
    if merged == (cfg.config_data or {}):
        return False
    db.add(SiteConfigHistory(client_id=client_id, version=cfg.version, config_data=cfg.config_data,
                             config_raw=cfg.config_raw, changed_by=cfg.updated_by))
    cfg.config_data = merged
    cfg.config_raw = raw_body
    cfg.version = cfg.version + 1
    cfg.updated_by = actor_id
    cfg.updated_at = now()
    return True


# ── summaries for the dashboards ───────────────────────────────────────────────
INFO_KEYS = (
    "legalFirstName", "legalLastName", "dateOfBirth", "personalPhone",
    "mailingStreet", "mailingCity", "mailingState", "mailingZip", "preferredContact",
    "bizNameInput", "themeSelect", "purposeText",
)
SITE_KEYS = ("domainInput", "taglineInput", "ctaSel")

NAV_SETS = [
    ["Why We Exist", "Our Purpose", "What We Do", "How We Work"],
    ["Who We Serve", "Who It’s For", "Who We Work With", "Our Focus"],
    ["Contact", "Get in Touch", "Start a Conversation", "Reach Us"],
]
PALETTES = {
    "Forest": "#1F4A3A", "Navy": "#1B2A4A", "Charcoal": "#2B2B2B", "Oxblood": "#5C1F1F",
    "Umber": "#6B4A2F", "Aubergine": "#4A2140", "Slate": "#20303A", "Ironstone": "#4A4A4A",
    "Onyx": "#151515", "Teal": "#123A3E",
}
TEMPLATES = {"editorial": "Editorial", "split": "Split", "sidebar": "Sidebar", "centered": "Centered"}
FONT_PAIRS = {"Classic": "Lora + Inter", "Contemporary": "Space Grotesk + Manrope"}


def _filled(fields: dict, keys: tuple[str, ...]) -> int:
    return sum(1 for k in keys if str(fields.get(k) if fields.get(k) is not None else "").strip())


def progress(fields: dict, sel: dict) -> dict:
    return {
        "information": {"filled": _filled(fields, INFO_KEYS), "total": len(INFO_KEYS)},
        "website": {"filled": _filled(fields, SITE_KEYS) + (1 if sel.get("tpl") else 0), "total": len(SITE_KEYS) + 1},
    }


def _hero_label(v: str) -> str:
    if not v:
        return "Theme default"
    if v in ("none", "nohero"):
        return "No image"
    if v.startswith("fill:"):
        return "Solid colour (" + v[5:].replace("-", " ") + ")"
    return re.sub(r"-\d+$", "", v).replace("-", " ") + " photo"


def design(sel: dict) -> dict:
    heroes = sel.get("heroPg") if isinstance(sel.get("heroPg"), list) else []
    navs = [sel.get("nav0"), sel.get("nav1"), sel.get("nav2")]
    variant = sel.get("variant") if isinstance(sel.get("variant"), int) and not isinstance(sel.get("variant"), bool) else None

    def page_name(i: int, n: object) -> str:
        try:
            return NAV_SETS[i][int(n)]
        except (IndexError, TypeError, ValueError):
            return ""

    return {
        "template": sel.get("tpl") or "",
        "templateLabel": TEMPLATES.get(sel.get("tpl"), ""),
        "fonts": sel.get("fnt") or "",
        "fontPair": FONT_PAIRS.get(sel.get("fnt"), ""),
        "palette": sel.get("pal") or "",
        "paletteHex": PALETTES.get(sel.get("pal"), ""),
        "theme": sel.get("thm") or "",
        "variant": variant,
        "variantLabel": "" if variant is None else ("ABCD"[variant] if 0 <= variant < 4 else ""),
        "tier": sel.get("tier") or "",
        "pageNames": [page_name(i, n) for i, n in enumerate(navs)],
        "heroImages": heroes,
        "heroLabels": [_hero_label(h if isinstance(h, str) else "") for h in heroes],
        "tagline": sel.get("tagline") or "",
        "cta": sel.get("cta") or "",
        "entity": sel.get("entity") or "",
    }


def display_name(profile: Profile, fields: dict) -> str:
    legal = " ".join(x for x in (fields.get("legalFirstName"), fields.get("legalLastName")) if x).strip()
    return legal or (profile.full_name or "").strip() or profile.email


def summarize(data: ClientData, pending: int | None = None) -> dict:
    fields, sel = data.fields, data.sel
    p = progress(fields, sel)
    has_data = p["information"]["filled"] > 0 or p["website"]["filled"] > 0
    if pending is None:
        pending = sum(1 for r in data.requests if r.status == "pending")
    status = data.status
    return {
        "id": str(data.profile.id),
        "email": data.profile.email,
        "name": display_name(data.profile, fields),
        "businessName": fields.get("bizNameInput") or "",
        "theme": fields.get("themeSelect") or sel.get("thm") or "",
        "template": sel.get("tpl") or "",
        "palette": sel.get("pal") or "",
        "state": portal_state(data.cd, has_data),
        "completedOn": status["completedOn"],
        "lockedOn": status["lockedOn"],
        "changesUntil": status["changesUntil"],
        "pendingRequests": pending,
        "progress": p,
        "site": data.site,
        "createdAt": iso(data.profile.created_at),
        "clientNumbers": [n.number for n in data.numbers],
    }


def public_request(r: ChangeRequest, *, with_client: bool = False) -> dict:
    out = {
        "id": str(r.id), "part": r.part, "text": r.text, "status": r.status,
        "adminNote": r.admin_note or "", "createdAt": iso(r.created_at),
        "decidedAt": iso(r.resolved_at) or None,
    }
    if with_client:
        out["clientId"] = str(r.client_id)
    return out
