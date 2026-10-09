"""Profile + avatar endpoints against the real database (test accounts are removed afterwards).
Storage is faked, so nothing here touches Supabase Storage."""
import pytest
from sqlalchemy import select

from app.db.models import Profile
from app.db.session import get_factory
from app.security import create_access_token, hash_password, now
from tests.conftest import auth, unique_email

pytestmark = pytest.mark.asyncio(loop_scope="session")

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 64
MB2 = 2 * 1024 * 1024


PASSWORD = "ProfilePass1!"
_hash: str | None = None


async def new_user(api, role="client", name="Pat Tester"):
    """A fresh verified account with a ready-made access token. Own account per test so shared
    fixtures stay untouched; the token is minted directly (login is covered by test_e2e) to keep this fast."""
    global _hash
    if _hash is None:
        _hash = await hash_password(PASSWORD)
    email = unique_email("prof")
    async with get_factory()() as db:
        p = Profile(email=email, full_name=name, role=role, email_verified_at=now(), password_hash=_hash)
        db.add(p)
        await db.flush()
        uid = str(p.id)
        token, _ = create_access_token(p.id, email, role)
        await db.commit()
    return {"access_token": token, "user": {"id": uid, "email": email, "role": role}, "password": PASSWORD}


async def stored(user_id):
    async with get_factory()() as db:
        return (await db.execute(select(Profile).where(Profile.id == user_id))).scalar_one()


def upload(api, session, content=PNG, ctype="image/png", filename="me.png"):
    return api.post("/api/auth/avatar", files={"file": (filename, content, ctype)}, headers=auth(session))


# ── PUT /api/auth/profile ──────────────────────────────────────────────────────
async def test_profile_requires_sign_in(api):
    r = await api.put("/api/auth/profile", json={"fullName": "X"})
    assert (r.status_code, r.json()["error"]) == (401, "NOT_SIGNED_IN")


async def test_profile_update_persists_and_is_visible_on_me(api):
    s = await new_user(api)
    r = await api.put("/api/auth/profile", json={"fullName": "Grace Hopper", "phone": "+1 (555) 010-0100"}, headers=auth(s))
    assert r.status_code == 200
    assert r.json()["user"]["fullName"] == "Grace Hopper" and r.json()["user"]["phone"] == "+1 (555) 010-0100"
    me = (await api.get("/api/auth/me", headers=auth(s))).json()["user"]
    assert (me["fullName"], me["phone"]) == ("Grace Hopper", "+1 (555) 010-0100")
    relogin = (await api.post("/api/auth/login", json={"email": s["user"]["email"], "password": s["password"]})).json()
    assert relogin["user"]["fullName"] == "Grace Hopper"


async def test_profile_values_are_trimmed(api):
    s = await new_user(api)
    u = (await api.put("/api/auth/profile", json={"fullName": "  Ada  ", "phone": "  555  "}, headers=auth(s))).json()["user"]
    assert (u["fullName"], u["phone"]) == ("Ada", "555")


async def test_profile_lengths_are_capped(api):
    s = await new_user(api)
    u = (await api.put("/api/auth/profile", json={"fullName": "N" * 500, "phone": "9" * 500}, headers=auth(s))).json()["user"]
    assert len(u["fullName"]) == 120 and len(u["phone"]) == 30


async def test_phone_can_be_cleared(api):
    s = await new_user(api)
    await api.put("/api/auth/profile", json={"phone": "555"}, headers=auth(s))
    for blank in ("", "   "):
        await api.put("/api/auth/profile", json={"phone": "555"}, headers=auth(s))
        u = (await api.put("/api/auth/profile", json={"phone": blank}, headers=auth(s))).json()["user"]
        assert u["phone"] == ""
    assert (await stored(s["user"]["id"])).phone is None


@pytest.mark.parametrize("blank", ["", "   ", "\t\n"])
async def test_name_cannot_be_blanked(api, blank):
    s = await new_user(api, name="Keep Me")
    r = await api.put("/api/auth/profile", json={"fullName": blank}, headers=auth(s))
    assert (r.status_code, r.json()["error"]) == (400, "NAME_REQUIRED")
    assert (await api.get("/api/auth/me", headers=auth(s))).json()["user"]["fullName"] == "Keep Me"


async def test_partial_update_leaves_other_fields_alone(api):
    s = await new_user(api, name="Original")
    await api.put("/api/auth/profile", json={"phone": "123"}, headers=auth(s))
    u = (await api.put("/api/auth/profile", json={"fullName": "Renamed"}, headers=auth(s))).json()["user"]
    assert (u["fullName"], u["phone"]) == ("Renamed", "123")


@pytest.mark.parametrize("body", [{"fullName": 123, "phone": 456}, {"fullName": None, "phone": None}, {"fullName": ["x"], "phone": {"a": 1}}, {}])
async def test_non_string_values_are_ignored(api, body):
    s = await new_user(api, name="Stable")
    u = (await api.put("/api/auth/profile", json=body, headers=auth(s))).json()["user"]
    assert u["fullName"] == "Stable" and u["phone"] == ""


async def test_unicode_and_markup_are_stored_as_plain_text(api):
    s = await new_user(api)
    name = "José Ñandú <b>Ünï</b> 李雷"
    u = (await api.put("/api/auth/profile", json={"fullName": name}, headers=auth(s))).json()["user"]
    assert u["fullName"] == name  # returned verbatim as JSON; the UI renders it as text


async def test_email_role_and_password_cannot_be_changed_through_profile(api):
    s = await new_user(api)
    r = await api.put("/api/auth/profile", json={
        "fullName": "Hacker", "email": "evil@e2e.test.invalid", "role": "admin", "password_hash": "x", "is_active": False,
    }, headers=auth(s))
    assert r.json()["user"]["role"] == "client" and r.json()["user"]["email"] == s["user"]["email"]
    assert (await api.get("/api/admin/clients", headers=auth(s))).status_code == 403
    assert (await api.post("/api/auth/login", json={"email": s["user"]["email"], "password": s["password"]})).status_code == 200


@pytest.mark.parametrize("raw", ["not json", "[1,2]", '"str"', "null", ""])
async def test_profile_rejects_malformed_bodies(api, raw):
    s = await new_user(api)
    r = await api.put("/api/auth/profile", content=raw, headers={**auth(s), "Content-Type": "application/json"})
    assert (r.status_code, r.json()["error"]) == (400, "Invalid payload")


async def test_users_only_change_their_own_profile(api):
    a, b = await new_user(api, name="Alice"), await new_user(api, name="Bob")
    await api.put("/api/auth/profile", json={"fullName": "Alice Changed"}, headers=auth(a))
    assert (await api.get("/api/auth/me", headers=auth(b))).json()["user"]["fullName"] == "Bob"


async def test_admins_can_edit_their_own_profile_too(api):
    s = await new_user(api, role="admin", name="Boss")
    u = (await api.put("/api/auth/profile", json={"fullName": "Big Boss", "phone": "1"}, headers=auth(s))).json()["user"]
    assert (u["fullName"], u["role"]) == ("Big Boss", "admin")


async def test_profile_update_with_no_changes_writes_no_audit_noise(api):
    s = await new_user(api)
    await api.put("/api/auth/profile", json={"fullName": 5}, headers=auth(s))
    from app.db.models import AuditLog
    async with get_factory()() as db:
        rows = (await db.execute(select(AuditLog).where(AuditLog.actor_id == s["user"]["id"], AuditLog.action == "profile.updated"))).scalars().all()
    assert rows == []


# ── POST /api/auth/avatar ──────────────────────────────────────────────────────
async def test_avatar_upload_requires_sign_in(api, fake_s3):
    r = await api.post("/api/auth/avatar", files={"file": ("a.png", PNG, "image/png")})
    assert (r.status_code, r.json()["error"]) == (401, "NOT_SIGNED_IN")
    assert fake_s3.objects == {}


async def test_avatar_upload_succeeds_and_stores_a_key_not_a_url(api, fake_s3):
    s = await new_user(api)
    r = await upload(api, s)
    assert r.status_code == 200, r.text
    uid = s["user"]["id"]
    assert r.json()["user"]["avatarUrl"].startswith(f"https://signed.test/{uid}.png")
    assert (await stored(uid)).avatar_url == f"{uid}.png"      # a durable key; signed URLs expire
    assert fake_s3.objects[f"{uid}.png"] == (PNG, "image/png")


async def test_avatar_shows_up_on_me_and_on_the_next_login(api, fake_s3):
    s = await new_user(api)
    await upload(api, s)
    me = (await api.get("/api/auth/me", headers=auth(s))).json()["user"]
    assert me["avatarUrl"].startswith("https://signed.test/")
    login = (await api.post("/api/auth/login", json={"email": s["user"]["email"], "password": s["password"]})).json()
    assert login["user"]["avatarUrl"].startswith("https://signed.test/")


async def test_each_upload_format_is_accepted(api, fake_s3):
    s = await new_user(api)
    gif, webp = b"GIF89a" + b"\x00" * 16, b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 16
    for body, ctype, ext in ((JPG, "image/jpeg", "jpg"), (gif, "image/gif", "gif"), (webp, "image/webp", "webp"), (PNG, "image/png", "png")):
        r = await upload(api, s, body, ctype, f"x.{ext}")
        assert r.status_code == 200, (ctype, r.text)
        assert list(fake_s3.objects) == [f"{s['user']['id']}.{ext}"]  # only the latest format is kept


async def test_replacing_a_picture_keeps_exactly_one_file(api, fake_s3):
    s = await new_user(api)
    await upload(api, s)
    await upload(api, s, PNG + b"2")
    assert list(fake_s3.objects) == [f"{s['user']['id']}.png"]


@pytest.mark.parametrize("ctype", ["text/plain", "application/pdf", "image/svg+xml", "application/octet-stream", "image/bmp", "image/tiff", "text/html"])
async def test_disallowed_content_types_are_rejected(api, fake_s3, ctype):
    s = await new_user(api)
    r = await upload(api, s, PNG, ctype, "x.bin")
    assert (r.status_code, r.json()["error"]) == (400, "INVALID_FILE_TYPE")
    assert fake_s3.objects == {} and (await stored(s["user"]["id"])).avatar_url is None


@pytest.mark.parametrize("body,label", [
    (b"<html><script>alert(1)</script></html>", "html"),
    (b"<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'/>", "svg"),
    (b"%PDF-1.7 fake", "pdf"),
    (b"MZ\x90\x00 executable", "exe"),
    (b"", "empty"),
    (b"\x00" * 100, "zeros"),
])
async def test_a_lying_content_type_does_not_get_past_the_byte_check(api, fake_s3, body, label):
    s = await new_user(api)
    r = await upload(api, s, body, "image/png", "innocent.png")
    assert (r.status_code, r.json()["error"]) == (400, "INVALID_FILE_TYPE"), label
    assert fake_s3.objects == {}


async def test_declared_type_must_match_the_real_type(api, fake_s3):
    s = await new_user(api)
    r = await upload(api, s, JPG, "image/png", "x.png")  # JPEG bytes, PNG label
    assert (r.status_code, r.json()["error"]) == (400, "INVALID_FILE_TYPE")


async def test_size_limit_is_exactly_two_megabytes(api, fake_s3):
    s = await new_user(api)
    ok = PNG + b"\x00" * (MB2 - len(PNG))
    assert len(ok) == MB2
    assert (await upload(api, s, ok)).status_code == 200
    too_big = PNG + b"\x00" * (MB2 - len(PNG) + 1)
    r = await upload(api, s, too_big)
    assert (r.status_code, r.json()["error"]) == (400, "FILE_TOO_LARGE")
    assert fake_s3.objects[f"{s['user']['id']}.png"][0] == ok  # the earlier good picture is untouched


async def test_an_enormous_upload_is_refused_without_being_stored(api, fake_s3):
    s = await new_user(api)
    r = await upload(api, s, PNG + b"\x00" * (10 * MB2))
    assert (r.status_code, r.json()["error"]) == (400, "FILE_TOO_LARGE")
    assert (await stored(s["user"]["id"])).avatar_url is None


async def test_missing_file_field_is_a_clean_400(api, fake_s3):
    s = await new_user(api)
    r = await api.post("/api/auth/avatar", data={"other": "x"}, headers=auth(s))
    assert r.status_code == 400 and r.json()["error"] == "Invalid payload"
    r = await api.post("/api/auth/avatar", headers=auth(s))
    assert r.status_code == 400


async def test_filename_cannot_choose_where_the_file_goes(api, fake_s3):
    a, b = await new_user(api), await new_user(api)
    await upload(api, a, PNG, "image/png", f"../../{b['user']['id']}.png")
    assert list(fake_s3.objects) == [f"{a['user']['id']}.png"]
    assert (await stored(b["user"]["id"])).avatar_url is None


async def test_one_users_upload_never_changes_another_users_avatar(api, fake_s3):
    a, b = await new_user(api), await new_user(api)
    await upload(api, a)
    await upload(api, b, JPG, "image/jpeg", "b.jpg")
    assert set(fake_s3.objects) == {f"{a['user']['id']}.png", f"{b['user']['id']}.jpg"}


async def test_storage_not_configured_gives_503_not_a_crash(api, fake_s3, monkeypatch):
    from app.routes import auth as auth_routes
    monkeypatch.setattr(auth_routes, "storage_configured", lambda: False)
    s = await new_user(api)
    r = await upload(api, s)
    assert (r.status_code, r.json()["error"]) == (503, "STORAGE_NOT_CONFIGURED")


async def test_storage_outage_gives_502_and_keeps_the_old_picture(api, fake_s3):
    s = await new_user(api)
    await upload(api, s)
    uid = s["user"]["id"]
    fake_s3.put_failures = 5
    r = await upload(api, s, PNG + b"new")
    assert (r.status_code, r.json()["error"]) == (502, "UPLOAD_FAILED")
    assert "fake failure" not in r.text and "supabase" not in r.text.lower()   # no storage internals leak
    assert (await stored(uid)).avatar_url == f"{uid}.png"
    assert fake_s3.objects[f"{uid}.png"][0] == PNG


async def test_a_legacy_full_url_avatar_still_renders(api, fake_s3):
    s = await new_user(api)
    legacy = "https://old.example/storage/v1/object/public/avatars/legacy.png"
    async with get_factory()() as db:
        p = (await db.execute(select(Profile).where(Profile.id == s["user"]["id"]))).scalar_one()
        p.avatar_url = legacy
        await db.commit()
    assert (await api.get("/api/auth/me", headers=auth(s))).json()["user"]["avatarUrl"] == legacy


async def test_a_signing_failure_hides_the_picture_instead_of_breaking_me(api, fake_s3):
    s = await new_user(api)
    await upload(api, s)
    fake_s3.presign_fails = True
    r = await api.get("/api/auth/me", headers=auth(s))
    assert r.status_code == 200 and r.json()["user"]["avatarUrl"] == ""


async def test_upload_is_audited_for_clients_only(api, fake_s3):
    from app.db.models import AuditLog
    c, a = await new_user(api), await new_user(api, role="admin")
    await upload(api, c)
    await upload(api, a)
    async with get_factory()() as db:
        rows = (await db.execute(select(AuditLog).where(AuditLog.action == "avatar.uploaded", AuditLog.actor_id.in_([c["user"]["id"], a["user"]["id"]])))).scalars().all()
    by_actor = {str(r.actor_id): r.client_id for r in rows}
    assert str(by_actor[c["user"]["id"]]) == c["user"]["id"] and by_actor[a["user"]["id"]] is None


# ── DELETE /api/auth/avatar ────────────────────────────────────────────────────
async def test_avatar_removal_requires_sign_in(api, fake_s3):
    assert (await api.delete("/api/auth/avatar")).status_code == 401


async def test_avatar_removal_clears_the_column_and_deletes_the_file(api, fake_s3):
    s = await new_user(api)
    await upload(api, s)
    r = await api.delete("/api/auth/avatar", headers=auth(s))
    assert r.status_code == 200 and r.json()["user"]["avatarUrl"] == ""
    assert fake_s3.objects == {}
    assert (await stored(s["user"]["id"])).avatar_url is None
    assert (await api.get("/api/auth/me", headers=auth(s))).json()["user"]["avatarUrl"] == ""


async def test_removing_when_there_is_no_avatar_is_harmless(api, fake_s3):
    s = await new_user(api)
    for _ in range(2):
        r = await api.delete("/api/auth/avatar", headers=auth(s))
        assert r.status_code == 200 and r.json()["user"]["avatarUrl"] == ""


async def test_removal_only_deletes_the_callers_file(api, fake_s3):
    a, b = await new_user(api), await new_user(api)
    await upload(api, a)
    await upload(api, b)
    await api.delete("/api/auth/avatar", headers=auth(a))
    assert list(fake_s3.objects) == [f"{b['user']['id']}.png"]


async def test_removal_still_works_when_storage_is_down(api, fake_s3):
    s = await new_user(api)
    await upload(api, s)
    fake_s3.list_fails = True  # cleanup is best effort; the user must still be able to remove their picture
    r = await api.delete("/api/auth/avatar", headers=auth(s))
    assert r.status_code == 200 and r.json()["user"]["avatarUrl"] == ""
    assert (await stored(s["user"]["id"])).avatar_url is None


async def test_removal_without_storage_configured_still_clears_the_column(api, fake_s3, monkeypatch):
    from app.routes import auth as auth_routes
    s = await new_user(api)
    await upload(api, s)
    monkeypatch.setattr(auth_routes, "storage_configured", lambda: False)
    assert (await api.delete("/api/auth/avatar", headers=auth(s))).status_code == 200
    assert (await stored(s["user"]["id"])).avatar_url is None


# ── interaction with the rest of auth ──────────────────────────────────────────
async def test_profile_and_avatar_survive_a_password_change(api, fake_s3):
    s = await new_user(api)
    await api.put("/api/auth/profile", json={"fullName": "Persist Me"}, headers=auth(s))
    await upload(api, s)
    r = await api.post("/api/auth/change-password", json={"currentPassword": s["password"], "newPassword": "BrandNewPass1!"}, headers=auth(s))
    fresh = r.json()["session"]["user"]
    assert fresh["fullName"] == "Persist Me" and fresh["avatarUrl"].startswith("https://signed.test/")
