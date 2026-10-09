"""Supabase Storage integration for avatar uploads via S3 protocol."""

import io
import uuid
from functools import lru_cache

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from app.config import get_settings

BUCKET = "avatars"
MAX_SIZE = 2 * 1024 * 1024  # 2 MB
ALLOWED_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
SIGNED_URL_EXPIRY = 7 * 24 * 3600  # 7 days


@lru_cache
def _s3_client():
    s = get_settings()
    return boto3.client(
        "s3",
        endpoint_url=s.SUPABASE_S3_ENDPOINT,
        aws_access_key_id=s.SUPABASE_S3_ACCESS_KEY,
        aws_secret_access_key=s.SUPABASE_S3_SECRET_KEY,
        region_name=s.SUPABASE_S3_REGION,
        config=BotoConfig(signature_version="s3v4"),
    )


def is_configured() -> bool:
    s = get_settings()
    return bool(s.SUPABASE_URL and s.SUPABASE_S3_ACCESS_KEY and s.SUPABASE_S3_SECRET_KEY)


def ensure_bucket() -> None:
    """Create the avatars bucket if it doesn't exist. Idempotent."""
    client = _s3_client()
    try:
        client.head_bucket(Bucket=BUCKET)
    except ClientError:
        client.create_bucket(Bucket=BUCKET)


def detect_image_type(data: bytes) -> str | None:
    """Identify the real image type from its leading bytes; the client-sent Content-Type is not trusted."""
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def get_signed_url(key: str) -> str:
    """Generate a signed URL for a private object."""
    return _s3_client().generate_presigned_url(
        "get_object",
        Params={"Bucket": BUCKET, "Key": key},
        ExpiresIn=SIGNED_URL_EXPIRY,
    )


async def upload_avatar(user_id: uuid.UUID, data: bytes, content_type: str) -> str:
    """Upload an avatar image and return the S3 object key."""
    ext = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif"}.get(content_type, "jpg")
    key = f"{user_id}.{ext}"

    try:
        _s3_client().put_object(
            Bucket=BUCKET,
            Key=key,
            Body=io.BytesIO(data),
            ContentType=content_type,
        )
    except ClientError:
        ensure_bucket()
        _s3_client().put_object(
            Bucket=BUCKET,
            Key=key,
            Body=io.BytesIO(data),
            ContentType=content_type,
        )

    await delete_avatar(user_id, keep=key)  # drop a previous picture stored under another extension
    return key


def resolve_avatar_url(avatar_url: str | None) -> str | None:
    """Turn a stored avatar key into a signed URL for the frontend."""
    if not avatar_url or not is_configured():
        return None
    if avatar_url.startswith("http"):
        return avatar_url
    try:
        return get_signed_url(avatar_url)
    except ClientError:
        return None


async def delete_avatar(user_id: uuid.UUID, keep: str | None = None) -> None:
    """Remove a user's avatar files (best effort), except the key to keep."""
    client = _s3_client()
    try:
        resp = client.list_objects_v2(Bucket=BUCKET, Prefix=str(user_id), MaxKeys=10)
        stale = [{"Key": o["Key"]} for o in resp.get("Contents", []) if o["Key"] != keep]
        if stale:
            client.delete_objects(Bucket=BUCKET, Delete={"Objects": stale})
    except ClientError:
        pass
