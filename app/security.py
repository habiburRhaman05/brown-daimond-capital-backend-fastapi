import asyncio
import hashlib
import secrets
import time
import uuid
from datetime import datetime, timedelta, timezone

import bcrypt
from jose import JWTError, jwt

from app.config import get_settings

ALGORITHM = "HS256"
ISSUER = "bdcap-portal"
BCRYPT_ROUNDS = 12
# bcrypt only reads the first 72 bytes; refuse longer input instead of silently truncating it.
MAX_PASSWORD_BYTES = 72

# A real bcrypt hash of a random value: verifying against it burns the same time as a real
# check, so "no such account" and "wrong password" cannot be told apart by response time.
_DUMMY_HASH = bcrypt.hashpw(secrets.token_bytes(16), bcrypt.gensalt(BCRYPT_ROUNDS)).decode()


def now() -> datetime:
    return datetime.now(timezone.utc)


def password_ok(password: object) -> bool:
    return isinstance(password, str) and 8 <= len(password) <= 128 and len(password.encode()) <= MAX_PASSWORD_BYTES


async def hash_password(password: str) -> str:
    return await asyncio.to_thread(lambda: bcrypt.hashpw(password.encode(), bcrypt.gensalt(BCRYPT_ROUNDS)).decode())


async def verify_password(password: str, password_hash: str | None) -> bool:
    target = (password_hash or _DUMMY_HASH).encode()

    def check() -> bool:
        try:
            return bcrypt.checkpw(password.encode()[:MAX_PASSWORD_BYTES], target)
        except ValueError:
            return False

    ok = await asyncio.to_thread(check)
    return ok and password_hash is not None


def new_opaque_token() -> str:
    return secrets.token_urlsafe(48)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def create_access_token(user_id: uuid.UUID, email: str, role: str) -> tuple[str, int]:
    s = get_settings()
    iat = int(time.time())
    exp = iat + s.ACCESS_TOKEN_TTL_SECONDS
    claims = {"iss": ISSUER, "sub": str(user_id), "email": email, "role": role, "typ": "access", "iat": iat, "exp": exp}
    return jwt.encode(claims, s.JWT_SECRET, algorithm=ALGORITHM), exp


class TokenError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def decode_access_token(token: str) -> dict:
    s = get_settings()
    try:
        claims = jwt.decode(token, s.JWT_SECRET, algorithms=[ALGORITHM], issuer=ISSUER)
    except jwt.ExpiredSignatureError as exc:
        raise TokenError("SESSION_EXPIRED") from exc
    except JWTError as exc:
        raise TokenError("SESSION_EXPIRED") from exc
    if claims.get("typ") != "access" or not claims.get("sub"):
        raise TokenError("SESSION_EXPIRED")
    return claims


def expiry(*, hours: int = 0, minutes: int = 0, days: int = 0) -> datetime:
    return now() + timedelta(hours=hours, minutes=minutes, days=days)
