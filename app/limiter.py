from slowapi import Limiter
from slowapi.util import get_remote_address

from app.config import get_settings

# Keyed by client IP. Run uvicorn with --proxy-headers so that is the real visitor
# (X-Forwarded-For), not the Vercel or load-balancer hop in front of this API.
limiter = Limiter(key_func=get_remote_address, enabled=get_settings().RATE_LIMIT_ENABLED)
