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


async def upload_avatar(user_id: uuid.UUID, data: bytes, content_type: str) -> str:
    """Upload an avatar image and return its public URL. Overwrites any previous avatar."""
    ext = {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp", "image/gif": "gif"}.get(content_type, "jpg")
    key = f"{user_id}.{ext}"

    _s3_client().put_object(
        Bucket=BUCKET,
        Key=key,
        Body=io.BytesIO(data),
        ContentType=content_type,
    )

    return f"{get_settings().SUPABASE_URL.rstrip('/')}/storage/v1/object/public/{BUCKET}/{key}"


async def delete_avatar(user_id: uuid.UUID) -> None:
    """Remove all avatar files for a user."""
    client = _s3_client()
    try:
        resp = client.list_objects_v2(Bucket=BUCKET, Prefix=str(user_id), MaxKeys=10)
        objects = resp.get("Contents", [])
        if objects:
            client.delete_objects(
                Bucket=BUCKET,
                Delete={"Objects": [{"Key": o["Key"]} for o in objects]},
            )
    except ClientError:
        pass
