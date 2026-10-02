import logging
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.middleware import SlowAPIMiddleware
from sqlalchemy import select, text

from app.config import get_settings
from app.db.models import Profile
from app.db.session import close_db, db_configured, get_factory
from app.errors import install_error_handlers
from app.limiter import limiter
from app.routes import admin, auth, portal, public
from app.security import hash_password, now

settings = get_settings()

structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer() if settings.is_production else structlog.dev.ConsoleRenderer(),
    ],
    wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
)
log = structlog.get_logger()


async def bootstrap_admin() -> None:
    """Create the first admin from ADMIN_EMAIL / ADMIN_PASSWORD if there is none yet."""
    s = get_settings()
    if not (s.ADMIN_EMAIL and s.ADMIN_PASSWORD and db_configured()):
        return
    async with get_factory()() as db:
        if (await db.execute(select(Profile.id).where(Profile.role == "admin").limit(1))).first():
            return
        email = s.ADMIN_EMAIL.strip().lower()
        if (await db.execute(select(Profile.id).where(Profile.email == email))).first():
            log.warning("admin_bootstrap_skipped_email_in_use", email=email)
            return
        db.add(Profile(email=email, full_name=s.ADMIN_NAME, role="admin", email_verified_at=now(),
                       password_hash=await hash_password(s.ADMIN_PASSWORD)))
        await db.commit()
        log.info("admin_created", email=email)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.is_production and len(settings.JWT_SECRET) < 32:
        raise RuntimeError("JWT_SECRET must be set to a random value of at least 32 characters")
    try:
        await bootstrap_admin()
    except Exception as exc:  # the API should still boot so /api/health can say what is wrong
        log.error("admin_bootstrap_failed", error=repr(exc))
    log.info("startup", env=settings.ENV, db=db_configured())
    yield
    await close_db()


app = FastAPI(
    title="BDCap Client Portal API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None,
    openapi_url=None if settings.is_production else "/openapi.json",
)

app.state.limiter = limiter
install_error_handlers(app)
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_origin_regex=r"^https://[a-z0-9-]+\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    if request.url.path.startswith("/api/"):
        response.headers.setdefault("Cache-Control", "no-store")
    return response


for r in (auth.router, public.router, portal.portal_router, portal.client_router, admin.router):
    app.include_router(r)


@app.get("/api/health")
async def health():
    s = get_settings()
    db_state = "unconfigured"
    if db_configured():
        try:
            async with get_factory()() as db:
                await db.execute(text("SELECT 1"))
            db_state = "up"
        except Exception as exc:
            log.error("health_db_failed", error=repr(exc))
            db_state = "down"
    return {
        "ok": db_state in ("up", "unconfigured"),
        "timestamp": now().isoformat(),
        "db": db_state,
        "jwt_configured": len(s.JWT_SECRET) >= 32,
        "email_webhook_configured": bool(s.GHL_WEBHOOK_URL),
    }
