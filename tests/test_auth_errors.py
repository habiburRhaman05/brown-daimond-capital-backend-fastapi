"""Signup / login error handling: explicit "already exists" and "not found" answers."""
import asyncio

import pytest
from sqlalchemy import select

from app.db.models import Profile
from app.db.session import get_factory
from app.security import hash_password, now
from tests.conftest import auth, unique_email

pytestmark = pytest.mark.asyncio(loop_scope="session")

PW = "Password123!"


async def make_profile(email, *, verified=True, active=True, password=PW, role="client"):
    async with get_factory()() as db:
        db.add(Profile(email=email, full_name="Existing", role=role, is_active=active,
                       email_verified_at=now() if verified else None,
                       password_hash=await hash_password(password) if password else None))
        await db.commit()


async def count(email):
    async with get_factory()() as db:
        return len((await db.execute(select(Profile).where(Profile.email == email))).scalars().all())


# ── signup ─────────────────────────────────────────────────────────────────────
async def test_signup_with_a_verified_existing_email_says_so(api, outbox):
    email = unique_email("dupv")
    await make_profile(email)
    n = len(outbox.sent)
    r = await api.post("/api/auth/signup", json={"email": email, "password": PW, "fullName": "Again"})
    assert (r.status_code, r.json()["error"]) == (409, "EMAIL_EXISTS")
    assert len(outbox.sent) == n  # no email is sent to a verified account
    assert await count(email) == 1


async def test_signup_is_case_and_whitespace_insensitive_for_duplicates(api):
    email = unique_email("dupcase")
    await make_profile(email)
    r = await api.post("/api/auth/signup", json={"email": "  " + email.upper() + " ", "password": PW, "fullName": "X"})
    assert (r.status_code, r.json()["error"]) == (409, "EMAIL_EXISTS")


async def test_signup_with_an_unverified_existing_email_resends_the_link(api, outbox):
    email = unique_email("dupu")
    await make_profile(email, verified=False)
    r = await api.post("/api/auth/signup", json={"email": email, "password": PW, "fullName": "Again"})
    assert (r.status_code, r.json()["error"]) == (409, "EMAIL_NOT_VERIFIED")
    token = outbox.token_in(email, "verify_email")  # a fresh verification email went out
    r = await api.get(f"/api/auth/verify-email?token={token}")  # ...and its link really works
    assert r.status_code == 302 and "/email-verified#" in r.headers["location"]
    assert (await api.post("/api/auth/login", json={"email": email, "password": PW})).status_code == 200


async def test_signup_with_a_disabled_account_does_not_resend_anything(api, outbox):
    email = unique_email("dupd")
    await make_profile(email, verified=False, active=False)
    n = len(outbox.sent)
    r = await api.post("/api/auth/signup", json={"email": email, "password": PW, "fullName": "Again"})
    assert (r.status_code, r.json()["error"]) == (409, "EMAIL_EXISTS")
    assert len(outbox.sent) == n


async def test_duplicate_signup_never_changes_the_existing_password(api):
    email = unique_email("duppw")
    await make_profile(email)
    await api.post("/api/auth/signup", json={"email": email, "password": "Different999!", "fullName": "Evil"})
    assert (await api.post("/api/auth/login", json={"email": email, "password": PW})).status_code == 200
    assert (await api.post("/api/auth/login", json={"email": email, "password": "Different999!"})).status_code == 401


async def test_simultaneous_signups_for_one_address_create_exactly_one_account(api):
    email = unique_email("race")
    body = {"email": email, "password": PW, "fullName": "Racer"}
    rs = await asyncio.gather(*[api.post("/api/auth/signup", json=body) for _ in range(3)])
    statuses = sorted(r.status_code for r in rs)
    assert statuses.count(201) == 1 and all(s in (201, 409) for s in statuses), statuses
    assert await count(email) == 1


# ── login ──────────────────────────────────────────────────────────────────────
async def test_login_with_an_unknown_email_says_not_found(api):
    r = await api.post("/api/auth/login", json={"email": unique_email("ghost"), "password": PW})
    assert (r.status_code, r.json()["error"]) == (404, "ACCOUNT_NOT_FOUND")


async def test_login_with_a_wrong_password_is_still_a_credentials_error(api):
    email = unique_email("badpw")
    await make_profile(email)
    r = await api.post("/api/auth/login", json={"email": email, "password": "Wrong-password1"})
    assert (r.status_code, r.json()["error"]) == (401, "INVALID_CREDENTIALS")


async def test_login_finds_the_account_regardless_of_email_case(api):
    email = unique_email("login-case")
    await make_profile(email)
    r = await api.post("/api/auth/login", json={"email": email.upper(), "password": PW})
    assert r.status_code == 200


async def test_login_with_a_disabled_account_says_so(api):
    email = unique_email("off")
    await make_profile(email, active=False)
    r = await api.post("/api/auth/login", json={"email": email, "password": PW})
    assert (r.status_code, r.json()["error"]) == (403, "ACCOUNT_DISABLED")


async def test_unverified_email_is_reported_only_after_the_password_is_right(api):
    email = unique_email("unv")
    await make_profile(email, verified=False)
    wrong = await api.post("/api/auth/login", json={"email": email, "password": "Wrong-password1"})
    assert (wrong.status_code, wrong.json()["error"]) == (401, "INVALID_CREDENTIALS")  # no hint without the password
    right = await api.post("/api/auth/login", json={"email": email, "password": PW})
    assert (right.status_code, right.json()["error"]) == (403, "EMAIL_NOT_VERIFIED")


async def test_invited_account_with_no_password_yet_cannot_sign_in(api):
    email = unique_email("nopw")
    await make_profile(email, password=None)
    r = await api.post("/api/auth/login", json={"email": email, "password": PW})
    assert (r.status_code, r.json()["error"]) == (401, "INVALID_CREDENTIALS")


@pytest.mark.parametrize("body", [{}, {"email": "a@b.co"}, {"password": PW}, {"email": "", "password": ""}, {"email": 1, "password": 2}])
async def test_login_requires_both_fields(api, body):
    r = await api.post("/api/auth/login", json=body)
    assert r.status_code == 400


async def test_forgot_password_still_does_not_reveal_whether_an_account_exists(api):
    r = await api.post("/api/auth/forgot-password", json={"email": unique_email("nobody")})
    assert (r.status_code, r.json()) == (200, {"ok": True})


# ── errors must reach the browser ──────────────────────────────────────────────
async def test_a_server_crash_is_a_json_500_with_cors_headers(api, fake_s3, monkeypatch):
    """Without CORS headers the browser reports a bare network failure and hides the status."""
    from app.routes import auth as auth_routes
    from tests.test_profile_avatar import PNG, new_user

    async def boom(*a, **k):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(auth_routes, "upload_avatar", boom)
    s = await new_user(api)
    origin = "http://localhost:5173"
    r = await api.post("/api/auth/avatar", files={"file": ("a.png", PNG, "image/png")}, headers={**auth(s), "Origin": origin})
    assert (r.status_code, r.json()["error"]) == (500, "SERVER_ERROR")
    assert r.headers.get("access-control-allow-origin") == origin
    assert "kaboom" not in r.text


async def test_health_reports_whether_storage_is_configured(api, fake_s3):
    body = (await api.get("/api/health")).json()
    assert body["storage_configured"] is True
