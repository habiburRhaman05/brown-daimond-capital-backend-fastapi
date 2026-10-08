"""Supabase Storage integration for avatar uploads."""

import uuid

import httpx

from app.config import get_settings

BUCKET = "avatars"
MAX_SIZE = 2 * 1024 * 1024  # 2 MB
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}


def _headers() -> dict[str, str]:
    s = get_settings()
    return {
        "apikey": s.SUPABASE_SERVICE_KEY,
        "Authorization": f"Bearer {s.SUPABASE_SERVICE_KEY}",
    }


def _storage_url() -> str:
    return f"{get_settings().SUPABASE_URL.rstrip('/')}/storage/v1"


def is_configured() -> bool:
    s = get_settings()
    return bool(s.SUPABASE_URL and s.SUPABASE_SERVICE_KEY)


async def ensure_bucket() -> None:
    """Create the avatars bucket if it doesn't exist. Idempotent."""
    url = f"{_storage_url()}/bucket/{BUCKET}"
    async with httpx.AsyncClient(timeout=10) as client:
        r = await client.get(url, headers=_headers())
        if r.status_code == 200:
            return
        await client.post(
            f"{_storage_url()}/bucket",
            headers=_headers(),
            json={"id": BUCKET, "name": BUCKET, "public": True, "file_size_limit": MAX_SIZE,
                  "allowed_mime_types": list(ALLOWED_TYPES)},
        )


async def upload_avatar(user_id: uuid.UUID, data: bytes, content_type: str) -> str:
    """Upload an avatar image and return its public URL. Overwrites any previous avatar."""
    ext = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif"}.get(content_type, "jpg")
    path = f"{user_id}.{ext}"

    headers = {**_headers(), "Content-Type": content_type, "x-upsert": "true"}
    url = f"{_storage_url()}/object/{BUCKET}/{path}"

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.put(url, headers=headers, content=data)
        r.raise_for_status()

    return f"{get_settings().SUPABASE_URL.rstrip('/')}/storage/v1/object/public/{BUCKET}/{path}"


async def delete_avatar(user_id: uuid.UUID) -> None:
    """Remove all avatar files for a user."""
    async with httpx.AsyncClient(timeout=10) as client:
        # List files with the user_id prefix and delete them
        headers = _headers()
        r = await client.post(
            f"{_storage_url()}/object/list/{BUCKET}",
            headers=headers,
            json={"prefix": str(user_id), "limit": 10},
        )
        if r.status_code != 200:
            return
        files = r.json()
        if files:
            names = [f["name"] for f in files]
            await client.delete(
                f"{_storage_url()}/object/{BUCKET}",
                headers=headers,
                json={"prefixes": names},
            )
