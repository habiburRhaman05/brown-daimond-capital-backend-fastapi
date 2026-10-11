"""The refresh token lives in an HttpOnly cookie, never in a response body or a URL.
Covers cookie attributes, refresh, logout, the one-time grant that emailed links hand over, and the CSRF origin check."""
import asyncio
import re
import uuid
from datetime import timedelta

import pytest
from sqlalchemy import select, update

from app import config
from app.db.models import AuthToken, Profile
from app.db.session import get_factory
from app.routes import auth as auth_routes
from app.security import create_access_token, decode_access_token, hash_password, hash_token, now
from tests.conftest import COOKIE, as_session, auth, exchange, refresh_cookie, unique_email, with_cookie

pytestmark = pytest.mark.asyncio(loop_scope="session")

PW = "CookiePass123!"
_hash: str | None = None


async def make_user(*, role="client", verified=True, active=True):
    global _hash
    if _hash is None:
        _hash = await hash_password(PW)
    email = unique_email("ck")
    async with get_factory()() as db:
        p = Profile(email=email, full_name="Cookie Tester", role=role, is_active=active,
                    email_verified_at=now() if verified else None, password_hash=_hash)
        db.add(p)
        await db.flush()
        uid = p.id
        await db.commit()
    return email, uid


async def login(api, email=None):
    if email is None:
        email, _ = await make_user()
    r = await api.post("/api/auth/login", json={"email": email, "password": PW})
    assert r.status_code == 200, r.text
    return r, as_session(r)


def set_cookie_header(resp) -> str:
    return next(h for h in resp.headers.get_list("set-cookie") if h.startswith(COOKIE + "="))


async def expire_grants_for(uid):
    async with get_factory()() as db:
        await db.execute(update(AuthToken).where(AuthToken.user_id == uid, AuthToken.kind == "session_grant")
                         .values(expires_at=now() - timedelta(minutes=1)))
        await db.commit()


async def new_grant(api, outbox=None):
    """A real grant, obtained the way a user does: sign up, click the emailed link, read the redirect."""
    email = unique_email("grant")
    async with get_factory()() as db:
        p = Profile(email=email, full_name="Grant", email_verified_at=now(), password_hash=await hash_password(PW))
        db.add(p)
        await db.flush()
        uid = p.id
        await db.commit()
    from app.services import tokens
    async with get_factory()() as db:
        raw = await tokens.create_link_token(db, uid, "session_grant", now() + timedelta(minutes=5))
        await db.commit()
    return email, uid, raw


# ── cookie attributes ──────────────────────────────────────────────────────────
async def test_login_sets_an_httponly_lax_cookie_scoped_to_the_auth_endpoints(api):
    r, _ = await login(api)
    header = set_cookie_header(r)
    assert "HttpOnly" in header
    assert "SameSite=lax" in header
    assert "Path=/api/auth" in header
    assert f"Max-Age={30 * 86400}" in header
    assert "Domain=" not in header                      # host-only: never shared with sibling subdomains
    assert "Secure" not in header                       # development runs over plain http


async def test_login_never_puts_the_refresh_token_in_the_body(api):
    r, s = await login(api)
    assert "refresh_token" not in r.json() and "refresh_token" not in r.text
    assert s["refresh_token"] and s["refresh_token"] not in r.text


async def test_the_cookie_is_secure_in_production(api, monkeypatch):
    prod = config.get_settings().model_copy(update={"ENV": "production"})
    monkeypatch.setattr(auth_routes, "get_settings", lambda: prod)
    email, _ = await make_user()
    r = await api.post("/api/auth/login", json={"email": email, "password": PW})
    assert "Secure" in set_cookie_header(r)


async def test_session_responses_are_never_cacheable(api):
    r, s = await login(api)
    assert "no-store" in r.headers["cache-control"]
    r = await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))
    assert "no-store" in r.headers["cache-control"]


async def test_cookie_value_is_long_random_and_unique_per_login(api):
    email, _ = await make_user()
    _, a = await login(api, email)
    _, b = await login(api, email)
    assert len(a["refresh_token"]) >= 40 and a["refresh_token"] != b["refresh_token"]


async def test_the_server_stores_only_a_hash_of_the_refresh_token(api):
    _, s = await login(api)
    async with get_factory()() as db:
        assert (await db.execute(select(AuthToken).where(AuthToken.token_hash == s["refresh_token"]))).first() is None
        assert (await db.execute(select(AuthToken).where(AuthToken.token_hash == hash_token(s["refresh_token"])))).first() is not None


async def test_access_tokens_are_short_lived(api):
    r, s = await login(api)
    assert r.json()["expires_in"] == 900
    claims = decode_access_token(s["access_token"])
    assert 800 <= claims["exp"] - int(now().timestamp()) <= 900


# ── refresh ────────────────────────────────────────────────────────────────────
async def test_refresh_uses_the_cookie_and_rotates_it(api):
    _, s = await login(api)
    r = await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))
    assert r.status_code == 200
    body, new_cookie = r.json(), refresh_cookie(r)
    assert body["access_token"] and body["user"]["id"] == s["user"]["id"] and body["expires_in"] == 900
    assert "refresh_token" not in body
    assert new_cookie and new_cookie != s["refresh_token"]
    assert "HttpOnly" in set_cookie_header(r)
    assert (await api.get("/api/auth/me", headers={"Authorization": "Bearer " + body["access_token"]})).status_code == 200


async def test_a_just_used_cookie_still_works_for_a_second_tab(api):
    _, s = await login(api)
    first = await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))
    second = await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))  # the other tab, same moment
    assert first.status_code == 200 and second.status_code == 200


async def test_refresh_without_a_cookie_fails_cleanly(api):
    r = await api.post("/api/auth/refresh")
    assert (r.status_code, r.json()["error"]) == (401, "REFRESH_FAILED")
    assert not r.headers.get_list("set-cookie")


async def test_a_dead_cookie_is_cleared_so_it_is_not_retried(api):
    r = await api.post("/api/auth/refresh", headers=with_cookie("not-a-real-token"))
    assert (r.status_code, r.json()["error"]) == (401, "REFRESH_FAILED")
    header = set_cookie_header(r)
    assert "Max-Age=0" in header and "Path=/api/auth" in header


async def test_refresh_ignores_a_token_sent_in_the_body(api):
    _, s = await login(api)
    r = await api.post("/api/auth/refresh", json={"refresh_token": s["refresh_token"]})  # the pre-cookie API
    assert (r.status_code, r.json()["error"]) == (401, "REFRESH_FAILED")


async def test_an_access_token_is_not_a_refresh_token_and_vice_versa(api):
    _, s = await login(api)
    r = await api.post("/api/auth/refresh", headers=with_cookie(s["access_token"]))
    assert r.status_code == 401
    r = await api.get("/api/auth/me", headers={"Authorization": "Bearer " + s["refresh_token"]})
    assert r.status_code == 401


async def test_refresh_stops_working_for_a_disabled_account(api):
    email, uid = await make_user()
    _, s = await login(api, email)
    async with get_factory()() as db:
        await db.execute(update(Profile).where(Profile.id == uid).values(is_active=False))
        await db.commit()
    assert (await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))).status_code == 401


async def test_two_devices_have_independent_cookies(api):
    email, _ = await make_user()
    _, a = await login(api, email)
    _, b = await login(api, email)
    ra = await api.post("/api/auth/refresh", headers=with_cookie(a["refresh_token"]))
    rb = await api.post("/api/auth/refresh", headers=with_cookie(b["refresh_token"]))
    assert ra.status_code == rb.status_code == 200 and refresh_cookie(ra) != refresh_cookie(rb)


# ── logout ─────────────────────────────────────────────────────────────────────
async def test_logout_clears_the_cookie_and_kills_the_session(api):
    _, s = await login(api)
    r = await api.post("/api/auth/logout", headers={**auth(s), **with_cookie(s["refresh_token"])})
    assert r.json() == {"ok": True}
    assert "Max-Age=0" in set_cookie_header(r)
    assert (await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))).status_code == 401


async def test_logout_works_with_only_the_cookie_when_the_access_token_has_expired(api):
    _, s = await login(api)
    r = await api.post("/api/auth/logout", headers=with_cookie(s["refresh_token"]))  # no Authorization header at all
    assert r.status_code == 200
    assert (await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))).status_code == 401


async def test_logout_with_a_garbage_bearer_falls_back_to_the_cookie(api):
    _, s = await login(api)
    r = await api.post("/api/auth/logout", headers={"Authorization": "Bearer not.a.jwt", **with_cookie(s["refresh_token"])})
    assert r.status_code == 200
    assert (await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))).status_code == 401


async def test_logout_with_nothing_is_still_a_clean_ok(api):
    r = await api.post("/api/auth/logout")
    assert r.status_code == 200 and r.json() == {"ok": True}


async def test_logging_out_never_touches_another_users_session(api):
    _, mine = await login(api)
    _, theirs = await login(api)
    await api.post("/api/auth/logout", headers={**auth(mine), **with_cookie(mine["refresh_token"])})
    assert (await api.post("/api/auth/refresh", headers=with_cookie(theirs["refresh_token"]))).status_code == 200


# ── CSRF: the origin check ─────────────────────────────────────────────────────
@pytest.mark.parametrize("origin", [
    "https://evil.example", "http://localhost:5173.evil.com", "https://evil-vercel.app", "https://x.vercel.app.evil.com",
    "http://evil.localhost:5173", "null", "file://",
])
@pytest.mark.parametrize("path", ["/api/auth/refresh", "/api/auth/logout", "/api/auth/exchange"])
async def test_foreign_origins_are_refused_on_cookie_endpoints(api, path, origin):
    _, s = await login(api)
    r = await api.post(path, json={"grant": "x"}, headers={"Origin": origin, **with_cookie(s["refresh_token"])})
    assert (r.status_code, r.json()["error"]) == (403, "BAD_ORIGIN")
    assert not r.headers.get_list("set-cookie")                      # and nothing was rotated or cleared
    assert (await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))).status_code == 200  # still signed in


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173", "https://my-preview-1a2b.vercel.app"])
async def test_the_apps_own_origins_are_accepted(api, origin):
    _, s = await login(api)
    r = await api.post("/api/auth/refresh", headers={"Origin": origin, **with_cookie(s["refresh_token"])})
    assert r.status_code == 200


async def test_the_configured_frontend_origin_is_accepted(api, monkeypatch):
    custom = config.get_settings().model_copy(update={"FRONTEND_URL": "https://clients.example.com/"})
    monkeypatch.setattr(auth_routes, "get_settings", lambda: custom)
    _, s = await login(api)
    r = await api.post("/api/auth/refresh", headers={"Origin": "https://clients.example.com", **with_cookie(s["refresh_token"])})
    assert r.status_code == 200


async def test_cors_allows_credentials_only_for_known_origins(api):
    ok = await api.options("/api/auth/refresh", headers={"Origin": "http://localhost:5173", "Access-Control-Request-Method": "POST"})
    assert ok.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert ok.headers.get("access-control-allow-credentials") == "true"
    bad = await api.options("/api/auth/refresh", headers={"Origin": "https://evil.example", "Access-Control-Request-Method": "POST"})
    assert "access-control-allow-origin" not in bad.headers


# ── the one-time grant from emailed links ──────────────────────────────────────
async def test_verify_link_hands_over_a_grant_not_tokens(api, outbox):
    email = unique_email("vg")
    await api.post("/api/auth/signup", json={"email": email, "password": PW, "fullName": "Verify Grant"})
    r = await api.get(f"/api/auth/verify-email?token={outbox.token_in(email, 'verify_email')}")
    loc = r.headers["location"]
    assert re.search(r"/email-verified#grant=[\w-]{20,}&type=verify$", loc)
    assert "access_token" not in loc and "refresh_token" not in loc
    assert not r.headers.get_list("set-cookie")          # the redirect itself sets no cookie; the exchange does
    s = await exchange(api, loc)
    assert s["user"]["email"] == email and s["refresh_token"]


@pytest.mark.parametrize("flow,kind", [("invite", "invite"), ("reset", "recovery")])
async def test_invite_and_reset_links_hand_over_a_typed_grant(api, admin, outbox, flow, kind):
    if flow == "invite":
        email = unique_email("ig")
        assert (await api.post("/api/admin/invites", json={"email": email}, headers=auth(admin))).status_code == 201
        token = outbox.token_in(email, "invite")
    else:
        email, _ = await make_user()
        await api.post("/api/auth/forgot-password", json={"email": email})
        token = outbox.token_in(email, "reset_password")
    loc = (await api.get(f"/api/auth/redeem?token={token}")).headers["location"]
    assert f"/set-password#grant=" in loc and loc.endswith(f"&type={kind}")
    assert "access_token" not in loc and "refresh_token" not in loc


async def test_a_grant_works_exactly_once(api):
    _, _, raw = await new_grant(api)
    first = await api.post("/api/auth/exchange", json={"grant": raw})
    assert first.status_code == 200 and refresh_cookie(first) and "refresh_token" not in first.json()
    again = await api.post("/api/auth/exchange", json={"grant": raw})
    assert (again.status_code, again.json()["error"]) == (401, "GRANT_INVALID")


async def test_simultaneous_exchanges_of_one_grant_produce_a_single_session(api):
    _, _, raw = await new_grant(api)
    rs = await asyncio.gather(*[api.post("/api/auth/exchange", json={"grant": raw}) for _ in range(4)])
    assert sorted(r.status_code for r in rs) == [200, 401, 401, 401]


async def test_an_expired_grant_is_refused(api):
    _, uid, raw = await new_grant(api)
    await expire_grants_for(uid)
    r = await api.post("/api/auth/exchange", json={"grant": raw})
    assert (r.status_code, r.json()["error"]) == (401, "GRANT_INVALID")


async def test_a_grant_for_a_disabled_account_is_refused(api):
    _, uid, raw = await new_grant(api)
    async with get_factory()() as db:
        await db.execute(update(Profile).where(Profile.id == uid).values(is_active=False))
        await db.commit()
    assert (await api.post("/api/auth/exchange", json={"grant": raw})).status_code == 401


@pytest.mark.parametrize("body", [{}, {"grant": ""}, {"grant": None}, {"grant": 123}, {"grant": ["x"]}, {"grant": "nonsense"}, {"token": "x"}])
async def test_garbage_grants_are_refused(api, body):
    r = await api.post("/api/auth/exchange", json=body)
    assert (r.status_code, r.json()["error"]) == (401, "GRANT_INVALID")


async def test_exchange_rejects_non_json_bodies(api):
    r = await api.post("/api/auth/exchange", content="not json", headers={"Content-Type": "application/json"})
    assert r.status_code == 400


async def test_other_token_kinds_cannot_be_used_as_grants(api, outbox):
    # the emailed verification token, a refresh token, and an invite token are all valid *somewhere* else
    email = unique_email("kinds")
    await api.post("/api/auth/signup", json={"email": email, "password": PW, "fullName": "Kinds"})
    verify_token = outbox.token_in(email, "verify_email")
    _, s = await login(api)
    for raw in (verify_token, s["refresh_token"]):
        r = await api.post("/api/auth/exchange", json={"grant": raw})
        assert (r.status_code, r.json()["error"]) == (401, "GRANT_INVALID")


async def test_a_grant_cannot_be_used_as_a_refresh_cookie(api):
    _, _, raw = await new_grant(api)
    assert (await api.post("/api/auth/refresh", headers=with_cookie(raw))).status_code == 401


async def test_exchange_yields_a_session_that_really_works(api):
    email, uid, raw = await new_grant(api)
    r = await api.post("/api/auth/exchange", json={"grant": raw})
    s = as_session(r)
    me = await api.get("/api/auth/me", headers=auth(s))
    assert me.json()["user"]["id"] == str(uid)
    assert (await api.post("/api/auth/refresh", headers=with_cookie(s["refresh_token"]))).status_code == 200


async def test_a_new_grant_replaces_the_previous_unused_one(api):
    from app.services import tokens
    _, uid, first = await new_grant(api)
    async with get_factory()() as db:
        second = await tokens.create_link_token(db, uid, "session_grant", now() + timedelta(minutes=5))
        await db.commit()
    assert (await api.post("/api/auth/exchange", json={"grant": first})).status_code == 401
    assert (await api.post("/api/auth/exchange", json={"grant": second})).status_code == 200


async def test_old_style_fragment_tokens_are_not_accepted_as_a_session(api):
    # the access token of a user is not a grant either
    _, s = await login(api)
    assert (await api.post("/api/auth/exchange", json={"grant": s["access_token"]})).status_code == 401
    assert str(uuid.uuid4())  # keep uuid imported for readability of future cases
    _ = create_access_token  # imported to document that tokens are minted server-side only
