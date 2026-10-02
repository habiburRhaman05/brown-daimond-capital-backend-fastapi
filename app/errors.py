from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException

import structlog

log = structlog.get_logger()


class ApiError(Exception):
    """Raised anywhere in a handler; becomes {"error": CODE, ...} with the given status."""

    def __init__(self, status: int, code: str, **extra):
        super().__init__(code)
        self.status = status
        self.code = code
        self.extra = extra


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(ApiError)
    async def _api_error(_: Request, exc: ApiError):
        return JSONResponse({"error": exc.code, **exc.extra}, status_code=exc.status)

    @app.exception_handler(RateLimitExceeded)
    async def _rate_limited(_: Request, __: RateLimitExceeded):
        return JSONResponse({"error": "TOO_MANY_ATTEMPTS"}, status_code=429)

    @app.exception_handler(RequestValidationError)
    async def _invalid(_: Request, __: RequestValidationError):
        return JSONResponse({"error": "Invalid payload"}, status_code=400)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException):
        code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED"}.get(exc.status_code, "REQUEST_FAILED")
        return JSONResponse({"error": code}, status_code=exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception):
        log.error("unhandled_error", path=request.url.path, error=repr(exc), exc_info=True)
        return JSONResponse({"error": "SERVER_ERROR"}, status_code=500)
