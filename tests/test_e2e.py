"""End-to-end checks of the whole API contract against the real database.
Emails are captured (see conftest.Outbox); test accounts are removed afterwards."""
import json

import pytest
from sqlalchemy import select

from app.db.models import SiteConfig
from app.db.session import get_factory
from tests.conftest import auth, unique_email

pytestmark = pytest.mark.asyncio(loop_scope="session")


# ── health ─────────────────────────────────────────────────────────────────────
async def test_health(api):
    r = await api.get("/api/health")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] and body["db"] == "up" and body["jwt_configured"]


# ── signup, verification, login ────────────────────────────────────────────────
async def test_signup_requires_verification_then_logs_in(api, outbox):
    email, pw = unique_email("flow"), "Password123!"
    r = await api.post("/api/auth/signup", json={"email": email, "password": pw, "fullName": "Flow Tester"})
    assert r.status_code == 201 and r.json() == {"ok": True}

    r = await api.post("/api/auth/login", json={"email": email, "password": pw})
    assert (r.status_code, r.json()["error"]) == (403, "EMAIL_NOT_VERIFIED")
    r = await api.post("/api/auth/login", json={"email": email, "password": "wrong-password"})
    assert (r.status_code, r.json()["error"]) == (401, "INVALID_CREDENTIALS")

    token = outbox.token_in(email, "verify_email")
    r = await api.get(f"/api/auth/verify-email?token={token}")
    assert r.status_code == 302 and r.headers["location"].endswith("/client/login?verified=1")
    r = await api.get(f"/api/auth/verify-email?token={token}")  # a mail scanner may open it twice
    assert r.headers["location"].endswith("/client/login?verified=1")
    r = await api.get("/api/auth/verify-email?token=nonsense")
    assert r.headers["location"].endswith("/client/login?verify=expired")

    r = await api.post("/api/auth/login", json={"email": email.upper(), "password": pw})
    assert r.status_code == 200
    s = r.json()
    assert s["user"]["email"] == email and s["user"]["role"] == "client"
    assert s["expires_in"] == 3600 and s["expires_at"] > 0

    me = await api.get("/api/auth/me", headers=auth(s))
    assert me.json()["user"]["id"] == s["user"]["id"]


async def test_signup_validation_and_no_enumeration(api, client_session):
    bad = [({"email": "nope", "password": "Password123!", "fullName": "x"}, "INVALID_EMAIL"),
           ({"email": unique_email("v"), "password": "short", "fullName": "x"}, "WEAK_PASSWORD"),
           ({"email": unique_email("v"), "password": "Password123!", "fullName": " "}, "NAME_REQUIRED")]
    for body, code in bad:
        r = await api.post("/api/auth/signup", json=body)
        assert (r.status_code, r.json()["error"]) == (400, code)
    # an address that already exists gets the identical answer
    r = await api.post("/api/auth/signup", json={"email": client_session["user"]["email"], "password": "Password123!", "fullName": "Dup"})
    assert (r.status_code, r.json()) == (201, {"ok": True})
    r = await api.post("/api/auth/login", json={"email": client_session["user"]["email"], "password": client_session["password"]})
    assert r.status_code == 200  # the duplicate signup did not change the password


async def test_refresh_rotates_and_rejects_garbage(api, client_session):
    r = await api.post("/api/auth/refresh", json={"refresh_token": client_session["refresh_token"]})
    assert r.status_code == 200
    new = r.json()
    assert new["access_token"] and new["refresh_token"] != client_session["refresh_token"] and "user" not in new
    assert (await api.get("/api/auth/me", headers=auth(new))).status_code == 200
    r = await api.post("/api/auth/refresh", json={"refresh_token": "garbage"})
    assert (r.status_code, r.json()["error"]) == (401, "REFRESH_FAILED")


async def test_auth_guards(api, client_session, admin):
    r = await api.get("/api/portal/prefill")
    assert (r.status_code, r.json()["error"]) == (401, "NOT_SIGNED_IN")
    r = await api.get("/api/portal/prefill", headers={"Authorization": "Bearer abc.def.ghi"})
    assert (r.status_code, r.json()["error"]) == (401, "SESSION_EXPIRED")
    tampered = client_session["access_token"][:-3] + "AAA"
    assert (await api.get("/api/auth/me", headers={"Authorization": "Bearer " + tampered})).status_code == 401
    for path in ("/api/admin/clients", "/api/admin/invites", "/api/admin/change-requests", "/api/admin/signup-requests"):
        r = await api.get(path, headers=auth(client_session))
        assert (r.status_code, r.json()["error"]) == (403, "FORBIDDEN"), path
        assert (await api.get(path, headers=auth(admin))).status_code == 200, path


async def test_forgot_and_reset_password(api, outbox):
    email, old = unique_email("reset"), "OldPassword1!"
    await api.post("/api/auth/signup", json={"email": email, "password": old, "fullName": "Reset Me"})
    await api.get(f"/api/auth/verify-email?token={outbox.token_in(email, 'verify_email')}")

    n = len(outbox.sent)
    for addr in (unique_email("ghost"), "not-an-email"):
        r = await api.post("/api/auth/forgot-password", json={"email": addr})
        assert r.json() == {"ok": True}
    assert len(outbox.sent) == n  # unknown addresses get the same answer and no email

    assert (await api.post("/api/auth/forgot-password", json={"email": email})).json() == {"ok": True}
    token = outbox.token_in(email, "reset_password")
    r = await api.get(f"/api/auth/redeem?token={token}")
    assert r.status_code == 302
    loc = r.headers["location"]
    assert "/set-password#access_token=" in loc and "refresh_token=" in loc
    access = loc.split("access_token=")[1].split("&")[0]

    h = {"Authorization": "Bearer " + access}
    assert (await api.post("/api/auth/set-password", json={"password": "short"}, headers=h)).json()["error"] == "WEAK_PASSWORD"
    r = await api.post("/api/auth/set-password", json={"password": "BrandNew123!"}, headers=h)
    assert r.json() == {"ok": True, "email": email}

    assert (await api.post("/api/auth/login", json={"email": email, "password": old})).status_code == 401
    assert (await api.post("/api/auth/login", json={"email": email, "password": "BrandNew123!"})).status_code == 200
    r = await api.get(f"/api/auth/redeem?token={token}")  # the link is spent once a password is set
    assert r.headers["location"].endswith("/set-password")


# ── portal data ────────────────────────────────────────────────────────────────
async def test_portal_save_prefill_roundtrip_and_raw_site_config(api, client_session):
    h = auth(client_session)
    first = (await api.get("/api/portal/prefill", headers=h)).json()
    assert first["fields"]["personalEmail"] == client_session["user"]["email"]  # prefilled from the account
    assert first["status"] == {"completedOn": "", "lockedOn": "", "changesUntil": ""}

    payload = {
        "fields": {
            "legalFirstName": "Ada", "legalLastName": "Lovelace", "dateOfBirth": "1990-12-10",
            "personalPhone": "(512) 555-0143", "mailingStreet": "1 Main St", "mailingCity": "Austin",
            "mailingState": "TX", "mailingZip": "78701", "preferredContact": "Zoom",
            "contactTimeMorning": True, "contactTimeEvening": False, "contactTimeNight": True,
            "team_role_1": "Agent", "team_name_1": "Grace", "team_email_1": "g@example.com", "team_phone_1": "555",
            "team_name_2": "Linus", "team_role_2": "Other", "team_relationship_2": "Mentor",
            "bizNameInput": "Ada & Co", "backupName1": "Ada Two", "themeSelect": "NIL Consulting",
            "purposeText": "Advisory.", "naicsField": "541611", "sicField": "8742",
            "domainInput": "adaco.com", "taglineInput": "Compute well.", "ctaSel": "Get in touch",
            "someFutureField": "kept",
            "lockedOn": "2020-01-01T00:00:00.000Z", "clientNumber": "HACK",   # must be ignored
        },
        "sel": {"tpl": "split", "pal": "Onyx", "fnt": "Classic", "thm": "NIL Consulting", "variant": 2,
                "nav0": 0, "nav1": 1, "nav2": 3, "heroPg": ["sport-hoop-39", "fill:accent-dark", "nohero"],
                "lockedOn": "2020-01-01T00:00:00.000Z", "changeRequests": [{"status": "approved"}]},
    }
    raw = json.dumps(payload, indent=1)  # odd whitespace on purpose
    r = await api.post("/api/portal/save", content=raw, headers={**h, "Content-Type": "application/json"})
    assert r.json() == {"ok": True}

    back = (await api.get("/api/portal/prefill", headers=h)).json()
    f = back["fields"]
    for k in ("legalFirstName", "dateOfBirth", "mailingCity", "preferredContact", "bizNameInput", "backupName1",
              "themeSelect", "purposeText", "naicsField", "sicField", "domainInput", "taglineInput", "ctaSel",
              "team_name_1", "team_email_1", "team_name_2", "team_relationship_2", "someFutureField"):
        assert f[k] == payload["fields"][k], k
    assert (f["contactTimeMorning"], f["contactTimeEvening"], f["contactTimeNight"]) == (True, False, True)
    assert back["status"]["lockedOn"] == "" and back["site"]["clientNumber"] == ""   # forbidden fields ignored
    for k in ("tpl", "pal", "variant", "nav2", "heroPg"):
        assert back["sel"][k] == payload["sel"][k], k
    assert back["sel"]["changeRequests"] == []                                       # server-owned

    async with get_factory()() as db:
        cfg = (await db.execute(select(SiteConfig).where(SiteConfig.client_id == client_session["user"]["id"]))).scalar_one()
        assert cfg.config_raw == raw and cfg.version == 1                            # byte-for-byte

    again = await api.post("/api/portal/save", json=payload, headers=h)
    assert again.json() == {"ok": True, "unchanged": True}

    overview = (await api.get("/api/client/overview", headers=h)).json()
    assert overview["summary"]["state"] == "in_progress" and overview["summary"]["businessName"] == "Ada & Co"
    assert overview["design"]["palette"] == "Onyx" and overview["design"]["paletteHex"] == "#151515"
    assert overview["design"]["templateLabel"] == "Split" and overview["design"]["variantLabel"] == "C"
    assert overview["design"]["pageNames"] == ["Why We Exist", "Who It’s For", "Reach Us"]
    details = (await api.get("/api/client/details", headers=h)).json()
    assert details["fields"]["legalLastName"] == "Lovelace" and details["design"]["template"] == "split"


async def test_submit_locks_then_change_requests_and_admin_flow(api, client_session, admin):
    h, ah = auth(client_session), auth(admin)
    cid = client_session["user"]["id"]

    r = await api.post("/api/portal/submit", json={"fields": {"taglineInput": "Final tagline"}, "sel": {"tpl": "editorial"}}, headers=h)
    body = r.json()
    assert r.status_code == 200 and body["ok"] and body["lockedOn"] == body["completedOn"]
    assert body["lockedOn"].endswith("Z")

    r = await api.post("/api/portal/save", json={"fields": {"taglineInput": "sneaky"}}, headers=h)
    assert (r.status_code, r.json()["error"]) == (423, "LOCKED")
    assert (await api.post("/api/portal/submit", json={}, headers=h)).status_code == 423
    assert (await api.get("/api/portal/prefill", headers=h)).json()["fields"]["taglineInput"] == "Final tagline"
    assert (await api.get("/api/client/overview", headers=h)).json()["summary"]["state"] == "submitted"

    # change requests
    for bad in ({"type": "x", "part": "website", "text": "hi"}, {"type": "change_request", "part": "nope", "text": "hi"},
                {"type": "change_request", "part": "team", "text": "  "}):
        assert (await api.post("/api/portal/change-request", json=bad, headers=h)).status_code == 400
    r = await api.post("/api/portal/change-request", json={"type": "change_request", "part": "team", "text": "Add my CPA"}, headers=h)
    req = r.json()["request"]
    assert req["status"] == "pending" and req["part"] == "team"

    mine = (await api.get("/api/client/change-requests", headers=h)).json()["requests"]
    assert [x["id"] for x in mine] == [req["id"]]
    pr = (await api.get("/api/portal/prefill", headers=h)).json()
    assert pr["sel"]["changeRequests"][0]["status"] == "pending"

    listed = (await api.get("/api/admin/change-requests?status=pending", headers=ah)).json()["requests"]
    mine_row = next(x for x in listed if x["id"] == req["id"])
    assert mine_row["clientEmail"] == client_session["user"]["email"] and mine_row["clientId"] == cid

    # pending <-> resolved, both directions
    r = await api.post(f"/api/admin/change-requests/{req['id']}/resolve", json={"note": "Done, thanks"}, headers=ah)
    assert r.json()["request"]["status"] == "resolved" and r.json()["request"]["decidedAt"]
    assert (await api.get("/api/client/change-requests", headers=h)).json()["requests"][0]["adminNote"] == "Done, thanks"
    assert (await api.get("/api/portal/prefill", headers=h)).json()["sel"]["changeRequests"][0]["status"] == "resolved"
    assert req["id"] not in [x["id"] for x in (await api.get("/api/admin/change-requests?status=pending", headers=ah)).json()["requests"]]
    r = await api.post(f"/api/admin/change-requests/{req['id']}/reopen", json={}, headers=ah)
    assert r.json()["request"]["status"] == "pending" and r.json()["request"]["decidedAt"] is None
    assert (await api.post("/api/admin/change-requests/not-a-uuid/resolve", json={}, headers=ah)).json()["error"] == "REQUEST_NOT_FOUND"

    # admin views
    clients = (await api.get("/api/admin/clients", headers=ah)).json()["clients"]
    row = next(c for c in clients if c["id"] == cid)
    assert row["state"] == "submitted" and row["pendingRequests"] == 1 and row["name"] == "Ada Lovelace"
    detail = (await api.get(f"/api/admin/clients/{cid}", headers=ah)).json()
    assert detail["summary"]["id"] == cid and detail["requests"][0]["clientId"] == cid
    actions = [a["action"] for a in detail["audit"]]
    assert "portal.submit" in actions and "request.created" in actions and "request.resolved" in actions
    pf = (await api.get(f"/api/admin/clients/{cid}/prefill", headers=ah)).json()
    assert pf["client"]["email"] == client_session["user"]["email"] and pf["fields"]["bizNameInput"] == "Ada & Co"

    # admin edit ignores the lock; reopen / lock
    r = await api.put(f"/api/admin/clients/{cid}/details", json={"fields": {"taglineInput": "Admin tagline", "lockedOn": ""}}, headers=ah)
    assert r.json() == {"ok": True}
    assert (await api.get(f"/api/admin/clients/{cid}/prefill", headers=ah)).json()["fields"]["taglineInput"] == "Admin tagline"
    assert (await api.post(f"/api/admin/clients/{cid}/lock", headers=ah)).json()["error"] == "ALREADY_LOCKED"
    r = await api.post(f"/api/admin/clients/{cid}/reopen", json={"hours": 2}, headers=ah)
    assert r.json()["ok"] and r.json()["changesUntil"].endswith("Z")
    assert (await api.get("/api/client/overview", headers=h)).json()["summary"]["state"] == "reopened"
    assert (await api.post("/api/portal/save", json={"fields": {"taglineInput": "Client edit"}}, headers=h)).json() == {"ok": True}
    assert (await api.post(f"/api/admin/clients/{cid}/reopen", json={}, headers=ah)).json()["error"] == "NOT_LOCKED"
    assert (await api.post(f"/api/admin/clients/{cid}/lock", headers=ah)).json()["ok"]
    assert (await api.post("/api/portal/save", json={"fields": {"taglineInput": "x"}}, headers=h)).status_code == 423

    site = {"previewUrl": "https://preview.example/ada", "deployedOn": "2026-10-01", "url": "https://adaco.com", "clientNumber": "BD-0042"}
    r = await api.put(f"/api/admin/clients/{cid}/site", json=site, headers=ah)
    assert r.json()["site"] == site
    assert (await api.get("/api/client/overview", headers=h)).json()["summary"]["site"] == site


# ── invites + access requests ──────────────────────────────────────────────────
async def test_invite_flow(api, admin, outbox):
    ah, email = auth(admin), unique_email("invitee")
    assert (await api.post("/api/admin/invites", json={"email": "nope"}, headers=ah)).json()["error"] == "INVALID_EMAIL"
    r = await api.post("/api/admin/invites", json={"email": email.upper()}, headers=ah)
    assert r.status_code == 201 and r.json()["invite"]["status"] == "sent"
    assert (await api.post("/api/admin/invites", json={"email": email}, headers=ah)).json()["error"] == "INVITE_PENDING"

    # no password yet, so nobody can sign in as them
    assert (await api.post("/api/auth/login", json={"email": email, "password": "Anything123!"})).status_code == 401

    r = await api.get(f"/api/auth/redeem?token={outbox.token_in(email, 'invite')}")
    access = r.headers["location"].split("access_token=")[1].split("&")[0]
    r = await api.post("/api/auth/set-password", json={"password": "InvitePass123!"}, headers={"Authorization": "Bearer " + access})
    assert r.json()["email"] == email
    assert (await api.post("/api/auth/login", json={"email": email, "password": "InvitePass123!"})).status_code == 200

    invites = (await api.get("/api/admin/invites", headers=ah)).json()["invites"]
    assert next(i for i in invites if i["email"] == email)["status"] == "accepted"
    assert (await api.post("/api/admin/invites", json={"email": email}, headers=ah)).json()["error"] == "ALREADY_REGISTERED"


async def test_revoke_invite_kills_the_link(api, admin, outbox):
    ah, email = auth(admin), unique_email("revoked")
    inv = (await api.post("/api/admin/invites", json={"email": email}, headers=ah)).json()["invite"]
    token = outbox.token_in(email, "invite")
    assert (await api.delete(f"/api/admin/invites/{inv['id']}", headers=ah)).json() == {"ok": True}
    assert (await api.delete(f"/api/admin/invites/{inv['id']}", headers=ah)).json()["error"] == "INVITE_NOT_OPEN"
    assert (await api.get(f"/api/auth/redeem?token={token}")).headers["location"].endswith("/set-password")
    # and the address can be invited again
    assert (await api.post("/api/admin/invites", json={"email": email}, headers=ah)).status_code == 201


async def test_invite_email_failure_rolls_back(api, admin, outbox, monkeypatch):
    from app import mailer

    async def failing(*a, **k):
        return False

    monkeypatch.setattr(mailer, "post_to_ghl", failing)
    email = unique_email("mailfail")
    r = await api.post("/api/admin/invites", json={"email": email}, headers=auth(admin))
    assert (r.status_code, r.json()["error"]) == (502, "INVITE_EMAIL_FAILED")
    assert not [i for i in (await api.get("/api/admin/invites", headers=auth(admin))).json()["invites"] if i["email"] == email]


async def test_access_request_approve_and_reject(api, admin, outbox):
    ah = auth(admin)
    yes, no = unique_email("approve"), unique_email("reject")
    for e, n in ((yes, "Yes Person"), (no, "No Person")):
        r = await api.post("/api/signup-request", json={"email": e, "fullName": n, "company": "Acme"})
        assert r.status_code == 201 and r.json() == {"ok": True}
    assert (await api.post("/api/signup-request", json={"email": yes, "fullName": "Again"})).json() == {"ok": True}  # silent duplicate
    assert (await api.post("/api/signup-request", json={"email": "bad", "fullName": "x"})).json()["error"] == "INVALID_EMAIL"
    assert (await api.post("/api/signup-request", json={"email": unique_email("n"), "fullName": ""})).json()["error"] == "NAME_REQUIRED"

    pending = (await api.get("/api/admin/signup-requests?status=pending", headers=ah)).json()["requests"]
    ids = {r["email"]: r for r in pending}
    assert len([r for r in pending if r["email"] == yes]) == 1
    assert ids[yes]["fullName"] == "Yes Person" and ids[yes]["company"] == "Acme"

    r = await api.post(f"/api/admin/signup-requests/{ids[yes]['id']}/approve", json={"note": "Welcome"}, headers=ah)
    assert r.json()["request"]["status"] == "approved"
    assert outbox.link_to(yes, "invite")
    assert (await api.post(f"/api/admin/signup-requests/{ids[yes]['id']}/approve", json={}, headers=ah)).json()["error"] == "ALREADY_DECIDED"

    r = await api.post(f"/api/admin/signup-requests/{ids[no]['id']}/reject", json={"note": "Not a fit"}, headers=ah)
    assert r.json()["request"]["status"] == "rejected" and r.json()["request"]["adminNote"] == "Not a fit"
    assert not [m for m in outbox.sent if m["to_email"] == no]
    assert (await api.post("/api/admin/signup-requests/nope/approve", json={}, headers=ah)).json()["error"] == "REQUEST_NOT_FOUND"


async def test_logout_ends_refresh_tokens(api):
    email, pw = unique_email("bye"), "ByePassword1!"
    from tests.conftest import Outbox  # noqa: F401
    from app.db.models import Profile
    from app.security import hash_password, now
    async with get_factory()() as db:
        db.add(Profile(email=email, full_name="Bye", email_verified_at=now(), password_hash=await hash_password(pw)))
        await db.commit()
    s = (await api.post("/api/auth/login", json={"email": email, "password": pw})).json()
    assert (await api.post("/api/auth/logout", headers=auth(s))).json() == {"ok": True}
    r = await api.post("/api/auth/refresh", json={"refresh_token": s["refresh_token"]})
    assert r.status_code == 401


async def test_each_email_type_sends_its_own_payload(api, admin, outbox):
    ah = auth(admin)
    common = {"type", "app", "sent_at", "to_email", "to_name", "login_url"}

    email = unique_email("payload")
    await api.post("/api/auth/signup", json={"email": email, "password": "Password123!", "fullName": "Pay Load"})
    v = next(m for m in reversed(outbox.sent) if m["to_email"] == email)
    assert v["type"] == "verify_email" and v["to_name"] == "Pay Load"
    assert set(v) - {"link"} == common | {"verify_url", "expires_in_hours"} and v["expires_in_hours"] == 24

    await api.get(f"/api/auth/verify-email?token={outbox.token_in(email, 'verify_email')}")
    await api.post("/api/auth/forgot-password", json={"email": email})
    r = next(m for m in reversed(outbox.sent) if m["to_email"] == email)
    assert r["type"] == "reset_password" and set(r) - {"link"} == common | {"reset_url", "expires_in_minutes"}
    assert r["reset_url"].startswith("http") and "/api/auth/redeem?token=" in r["reset_url"]

    inv = unique_email("payloadinv")
    await api.post("/api/admin/invites", json={"email": inv}, headers=ah)
    i = next(m for m in reversed(outbox.sent) if m["to_email"] == inv)
    assert i["type"] == "invite" and set(i) - {"link"} == common | {"invite_url", "expires_in_days"} and i["expires_in_days"] == 7


async def test_change_password_signs_out_other_sessions(api):
    from app.db.models import Profile
    from app.security import hash_password, now
    email, old, new = unique_email("chg"), "OldPassword1!", "NewPassword1!"
    async with get_factory()() as db:
        db.add(Profile(email=email, full_name="Chg", email_verified_at=now(), password_hash=await hash_password(old)))
        await db.commit()
    first = (await api.post("/api/auth/login", json={"email": email, "password": old})).json()
    other = (await api.post("/api/auth/login", json={"email": email, "password": old})).json()
    h = auth(first)

    for body, code in (({"currentPassword": "nope", "newPassword": new}, "WRONG_PASSWORD"),
                       ({"currentPassword": old, "newPassword": "short"}, "WEAK_PASSWORD"),
                       ({"currentPassword": old, "newPassword": old}, "SAME_PASSWORD")):
        r = await api.post("/api/auth/change-password", json=body, headers=h)
        assert (r.status_code, r.json()["error"]) == (400, code)
    assert (await api.post("/api/auth/change-password", json={"currentPassword": old, "newPassword": new})).status_code == 401

    r = await api.post("/api/auth/change-password", json={"currentPassword": old, "newPassword": new}, headers=h)
    fresh = r.json()["session"]
    assert r.json()["ok"] and fresh["user"]["email"] == email
    assert (await api.get("/api/auth/me", headers=auth(fresh))).status_code == 200
    assert (await api.post("/api/auth/refresh", json={"refresh_token": other["refresh_token"]})).status_code == 401
    assert (await api.post("/api/auth/login", json={"email": email, "password": old})).status_code == 401
    assert (await api.post("/api/auth/login", json={"email": email, "password": new})).status_code == 200


async def test_admin_can_reset_own_password_by_email(api, outbox):
    from app.db.models import Profile
    from app.security import hash_password, now
    email, old = unique_email("adminreset"), "AdminOld123!"
    async with get_factory()() as db:
        db.add(Profile(email=email, full_name="Admin Reset", role="admin", email_verified_at=now(), password_hash=await hash_password(old)))
        await db.commit()
    await api.post("/api/auth/forgot-password", json={"email": email})
    assert outbox.link_to(email, "reset_password")
    r = await api.get(f"/api/auth/redeem?token={outbox.token_in(email, 'reset_password')}")
    access = r.headers["location"].split("access_token=")[1].split("&")[0]
    r = await api.post("/api/auth/set-password", json={"password": "AdminNew123!"}, headers={"Authorization": "Bearer " + access})
    assert r.json()["email"] == email
    s = (await api.post("/api/auth/login", json={"email": email, "password": "AdminNew123!"})).json()
    assert s["user"]["role"] == "admin"
    assert (await api.get("/api/admin/clients", headers=auth(s))).status_code == 200
