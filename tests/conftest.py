import os
import re
import uuid

os.environ["RATE_LIMIT_ENABLED"] = "false"  # must be set before the app is imported

import pytest_asyncio  # noqa: E402
from httpx import ASGITransport, AsyncClient  # noqa: E402
from sqlalchemy import delete, select  # noqa: E402

from app import mailer  # noqa: E402
from app.db.models import Invite, Profile, SignupRequest  # noqa: E402
from app.db.session import close_db, get_factory  # noqa: E402
from app.main import app  # noqa: E402
from app.security import hash_password, now  # noqa: E402

DOMAIN = "@e2e.test.invalid"


class Outbox:
    """Stands in for the GHL webhook: records every email instead of sending it."""

    def __init__(self):
        self.sent: list[dict] = []

    def link_to(self, email: str, kind: str) -> str:
        for m in reversed(self.sent):
            if m["to_email"] == email and m["type"] == kind:
                return m["link"]
        raise AssertionError(f"no {kind} email was sent to {email}")

    def token_in(self, email: str, kind: str) -> str:
        return re.search(r"token=([\w-]+)", self.link_to(email, kind)).group(1)


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def outbox():
    box = Outbox()
    real = mailer.post_to_ghl

    async def fake(payload):
        box.sent.append({**payload, "link": payload.get("verify_url") or payload.get("invite_url") or payload.get("reset_url") or ""})
        return True

    mailer.post_to_ghl = fake
    yield box
    mailer.post_to_ghl = real


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def api(outbox):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        yield client
    async with get_factory()() as db:
        ids = [r for r in (await db.execute(select(Profile.id).where(Profile.email.like("%" + DOMAIN)))).scalars()]
        await db.execute(delete(Invite).where(Invite.email.like("%" + DOMAIN)))
        await db.execute(delete(SignupRequest).where(SignupRequest.email.like("%" + DOMAIN)))
        if ids:
            await db.execute(delete(Profile).where(Profile.id.in_(ids)))
        await db.commit()
    await close_db()


def unique_email(tag: str) -> str:
    return f"{tag}-{uuid.uuid4().hex[:8]}{DOMAIN}"


def auth(session: dict) -> dict:
    return {"Authorization": "Bearer " + session["access_token"]}


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def admin(api):
    """A throwaway admin (never the real one), signed in."""
    email, password = unique_email("admin"), "AdminPass123!"
    async with get_factory()() as db:
        db.add(Profile(email=email, full_name="Test Admin", role="admin", email_verified_at=now(),
                       password_hash=await hash_password(password)))
        await db.commit()
    r = await api.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return r.json()


@pytest_asyncio.fixture(scope="session", loop_scope="session")
async def client_session(api, outbox):
    """A self-signed-up, email-verified client, signed in."""
    email, password = unique_email("client"), "ClientPass123!"
    r = await api.post("/api/auth/signup", json={"email": email, "password": password, "fullName": "Test Client"})
    assert r.status_code == 201, r.text
    token = outbox.token_in(email, "verify_email")
    r = await api.get(f"/api/auth/verify-email?token={token}")
    assert r.status_code == 302
    r = await api.post("/api/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    return {**r.json(), "password": password}


# ── storage fake ───────────────────────────────────────────────────────────────
import pytest  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402


def s3_error(op: str, code: str = "500") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": "fake failure"}}, op)


class FakeS3:
    """In-memory stand-in for the Supabase S3 client, so avatar tests never touch real storage."""

    def __init__(self):
        self.objects: dict[str, tuple[bytes, str]] = {}
        self.buckets = {"avatars"}
        self.put_failures = 0       # next N put_object calls raise
        self.presign_fails = False
        self.list_fails = False

    def head_bucket(self, Bucket):
        if Bucket not in self.buckets:
            raise s3_error("HeadBucket", "404")

    def create_bucket(self, Bucket):
        self.buckets.add(Bucket)

    def put_object(self, Bucket, Key, Body, ContentType):
        if self.put_failures:
            self.put_failures -= 1
            raise s3_error("PutObject")
        if Bucket not in self.buckets:
            raise s3_error("PutObject", "NoSuchBucket")
        self.objects[Key] = (Body.read(), ContentType)

    def generate_presigned_url(self, op, Params, ExpiresIn):
        if self.presign_fails:
            raise s3_error("Presign")
        return f"https://signed.test/{Params['Key']}?expires={ExpiresIn}"

    def list_objects_v2(self, Bucket, Prefix, MaxKeys):
        if self.list_fails:
            raise s3_error("ListObjectsV2")
        keys = [k for k in self.objects if k.startswith(Prefix)]
        return {"Contents": [{"Key": k} for k in keys]} if keys else {}

    def delete_objects(self, Bucket, Delete):
        for o in Delete["Objects"]:
            self.objects.pop(o["Key"], None)


@pytest.fixture
def fake_s3(monkeypatch):
    from app.routes import auth as auth_routes
    from app.services import storage

    fake = FakeS3()
    monkeypatch.setattr(storage, "_s3_client", lambda: fake)
    monkeypatch.setattr(storage, "is_configured", lambda: True)
    monkeypatch.setattr(auth_routes, "storage_configured", lambda: True)
    return fake
