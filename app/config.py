from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    ENV: str = "development"

    DATABASE_URL: str = ""

    # Custom JWT auth
    JWT_SECRET: str = ""
    ACCESS_TOKEN_TTL_SECONDS: int = 3600
    REFRESH_TOKEN_TTL_DAYS: int = 30
    VERIFY_EMAIL_TTL_HOURS: int = 24
    RESET_PASSWORD_TTL_MINUTES: int = 60
    INVITE_TTL_DAYS: int = 7

    # Where the browser app lives, and where the emailed links must point back to this API
    FRONTEND_URL: str = "http://localhost:5173"
    PUBLIC_API_URL: str = "http://localhost:8000"
    CORS_ORIGINS: str = ""

    # Email goes out through a GoHighLevel workflow triggered by this webhook
    GHL_WEBHOOK_URL: str = ""
    GHL_WEBHOOK_SECRET: str = ""
    ADMIN_NOTIFY_EMAIL: str = ""

    # First-run admin; created at startup only if no admin exists yet
    ADMIN_EMAIL: str = ""
    ADMIN_PASSWORD: str = ""
    ADMIN_NAME: str = "Administrator"

    RATE_LIMIT_ENABLED: bool = True

    @property
    def is_production(self) -> bool:
        return self.ENV.lower() == "production"

    @property
    def async_database_url(self) -> str:
        url = self.DATABASE_URL.strip()
        for prefix in ("postgresql://", "postgres://"):
            if url.startswith(prefix):
                return "postgresql+asyncpg://" + url[len(prefix):]
        return url

    @property
    def cors_origin_list(self) -> list[str]:
        raw = [self.FRONTEND_URL, *self.CORS_ORIGINS.split(",")]
        out = [o.strip().rstrip("/") for o in raw if o.strip()]
        if not self.is_production:
            out += ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"]
        return sorted(set(out))


@lru_cache
def get_settings() -> Settings:
    return Settings()
