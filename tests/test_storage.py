"""Unit tests for the avatar storage service. S3 is faked (see conftest.FakeS3); no network, no database."""
import uuid
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from app.db.models import Profile
from app.services import storage, tokens
from tests.conftest import s3_error

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
JPG = b"\xff\xd8\xff\xe0" + b"\x00" * 32
GIF = b"GIF89a" + b"\x00" * 32
WEBP = b"RIFF\x00\x00\x00\x00WEBPVP8 " + b"\x00" * 32

# ── detect_image_type ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("data,expected", [
    (PNG, "image/png"), (JPG, "image/jpeg"), (GIF, "image/gif"), (b"GIF87a" + b"\x00" * 8, "image/gif"), (WEBP, "image/webp"),
])
def test_detects_real_image_types(data, expected):
    assert storage.detect_image_type(data) == expected


@pytest.mark.parametrize("data", [
    b"", b"\x89PNG", b"GIF8", b"<html><script>alert(1)</script></html>", b"<svg xmlns='http://www.w3.org/2000/svg'/>",
    b"%PDF-1.7", b"RIFF\x00\x00\x00\x00WAVEfmt ", b"MZ\x90\x00", b"\x00" * 64, b"PK\x03\x04",
])
def test_rejects_non_images_and_lookalikes(data):
    assert storage.detect_image_type(data) is None


def test_png_signature_must_be_complete():
    assert storage.detect_image_type(b"\x89PNG\r\n\x1a") is None  # one byte short


# ── upload_avatar ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("ctype,ext,body", [
    ("image/png", "png", PNG), ("image/jpeg", "jpg", JPG), ("image/gif", "gif", GIF), ("image/webp", "webp", WEBP),
])
async def test_upload_stores_under_user_id_with_matching_extension(fake_s3, ctype, ext, body):
    uid = uuid.uuid4()
    key = await storage.upload_avatar(uid, body, ctype)
    assert key == f"{uid}.{ext}"
    assert fake_s3.objects[key] == (body, ctype)


async def test_upload_returns_a_key_not_a_url(fake_s3):
    key = await storage.upload_avatar(uuid.uuid4(), PNG, "image/png")
    assert not key.startswith("http") and "/" not in key


async def test_reupload_overwrites_in_place(fake_s3):
    uid = uuid.uuid4()
    await storage.upload_avatar(uid, PNG, "image/png")
    await storage.upload_avatar(uid, PNG + b"v2", "image/png")
    assert list(fake_s3.objects) == [f"{uid}.png"]
    assert fake_s3.objects[f"{uid}.png"][0].endswith(b"v2")


async def test_changing_format_removes_the_old_file(fake_s3):
    uid = uuid.uuid4()
    await storage.upload_avatar(uid, PNG, "image/png")
    await storage.upload_avatar(uid, JPG, "image/jpeg")
    assert list(fake_s3.objects) == [f"{uid}.jpg"]


async def test_upload_never_touches_other_users_files(fake_s3):
    a, b = uuid.uuid4(), uuid.uuid4()
    await storage.upload_avatar(b, PNG, "image/png")
    await storage.upload_avatar(a, JPG, "image/jpeg")
    assert set(fake_s3.objects) == {f"{a}.jpg", f"{b}.png"}


async def test_upload_creates_a_missing_bucket_and_retries(fake_s3):
    fake_s3.buckets.clear()
    uid = uuid.uuid4()
    key = await storage.upload_avatar(uid, PNG, "image/png")
    assert "avatars" in fake_s3.buckets and key in fake_s3.objects


async def test_upload_survives_one_transient_failure(fake_s3):
    fake_s3.put_failures = 1
    key = await storage.upload_avatar(uuid.uuid4(), PNG, "image/png")
    assert key in fake_s3.objects


async def test_upload_raises_when_storage_stays_down(fake_s3):
    fake_s3.put_failures = 5
    with pytest.raises(ClientError):
        await storage.upload_avatar(uuid.uuid4(), PNG, "image/png")
    assert fake_s3.objects == {}


async def test_a_failed_cleanup_does_not_fail_the_upload(fake_s3):
    fake_s3.list_fails = True
    uid = uuid.uuid4()
    assert await storage.upload_avatar(uid, PNG, "image/png") == f"{uid}.png"


# ── delete_avatar ──────────────────────────────────────────────────────────────
async def test_delete_removes_only_that_users_files(fake_s3):
    a, b = uuid.uuid4(), uuid.uuid4()
    fake_s3.objects.update({f"{a}.png": (b"", ""), f"{a}.jpg": (b"", ""), f"{b}.png": (b"", "")})
    await storage.delete_avatar(a)
    assert set(fake_s3.objects) == {f"{b}.png"}


async def test_delete_honours_keep(fake_s3):
    a = uuid.uuid4()
    fake_s3.objects.update({f"{a}.png": (b"", ""), f"{a}.jpg": (b"", "")})
    await storage.delete_avatar(a, keep=f"{a}.jpg")
    assert set(fake_s3.objects) == {f"{a}.jpg"}


async def test_delete_with_nothing_stored_is_a_noop(fake_s3):
    await storage.delete_avatar(uuid.uuid4())
    assert fake_s3.objects == {}


async def test_delete_swallows_storage_errors(fake_s3):
    fake_s3.list_fails = True
    await storage.delete_avatar(uuid.uuid4())  # must not raise


# ── resolve_avatar_url ─────────────────────────────────────────────────────────
def test_resolve_returns_none_for_no_avatar(fake_s3):
    assert storage.resolve_avatar_url(None) is None
    assert storage.resolve_avatar_url("") is None


def test_resolve_signs_a_stored_key_for_seven_days(fake_s3):
    url = storage.resolve_avatar_url("abc.png")
    assert url == f"https://signed.test/abc.png?expires={7 * 24 * 3600}"


def test_resolve_passes_legacy_full_urls_through_unchanged(fake_s3):
    legacy = "https://x.supabase.co/storage/v1/object/public/avatars/old.png"
    assert storage.resolve_avatar_url(legacy) == legacy


def test_resolve_hides_the_avatar_when_signing_fails(fake_s3):
    fake_s3.presign_fails = True
    assert storage.resolve_avatar_url("abc.png") is None


def test_resolve_returns_none_when_storage_is_not_configured(fake_s3, monkeypatch):
    monkeypatch.setattr(storage, "is_configured", lambda: False)
    assert storage.resolve_avatar_url("abc.png") is None


# ── configuration + bucket bootstrap ───────────────────────────────────────────
@pytest.mark.parametrize("missing", ["SUPABASE_URL", "SUPABASE_S3_ACCESS_KEY", "SUPABASE_S3_SECRET_KEY"])
def test_is_configured_needs_every_credential(monkeypatch, missing):
    full = dict(SUPABASE_URL="https://x.supabase.co", SUPABASE_S3_ACCESS_KEY="k", SUPABASE_S3_SECRET_KEY="s")
    monkeypatch.setattr(storage, "get_settings", lambda: SimpleNamespace(**{**full, missing: ""}))
    assert storage.is_configured() is False
    monkeypatch.setattr(storage, "get_settings", lambda: SimpleNamespace(**full))
    assert storage.is_configured() is True


def test_ensure_bucket_creates_once_and_is_idempotent(fake_s3):
    fake_s3.buckets.clear()
    storage.ensure_bucket()
    storage.ensure_bucket()
    assert fake_s3.buckets == {"avatars"}


def test_ensure_bucket_leaves_an_existing_bucket_alone(fake_s3):
    calls = []
    fake_s3.create_bucket = lambda Bucket: calls.append(Bucket)  # type: ignore[method-assign]
    storage.ensure_bucket()
    assert calls == []


def test_s3_error_helper_is_a_client_error():
    assert isinstance(s3_error("X"), ClientError)


# ── user serialisation ─────────────────────────────────────────────────────────
def _profile(**kw):
    return Profile(id=uuid.uuid4(), email="p@x.co", role="client", **kw)


def test_user_json_exposes_a_signed_url_never_the_raw_key(fake_s3):
    out = tokens.user_json(_profile(full_name="Pat", avatar_url="k.png", phone="555"))
    assert out["avatarUrl"].startswith("https://signed.test/k.png")
    assert out["fullName"] == "Pat" and out["phone"] == "555"
    assert set(out) == {"id", "email", "role", "fullName", "avatarUrl", "phone"}  # no password hash etc.


def test_user_json_uses_empty_strings_not_nulls(fake_s3):
    out = tokens.user_json(_profile())
    assert out["fullName"] == "" and out["avatarUrl"] == "" and out["phone"] == ""
