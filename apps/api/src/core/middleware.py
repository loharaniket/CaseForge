import time
import uuid
from collections.abc import Callable

from fastapi import FastAPI, Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from src.core.logging import logger

# Headers that must be masked in logs to avoid credential/secret leaks
SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "proxy-authorization",
    "token",
}


def mask_sensitive_headers(headers: dict[str, str]) -> dict[str, str]:
    """Mask sensitive header values with asterisks."""
    masked = {}
    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            masked[key] = "********"
        else:
            masked[key] = value
    return masked


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for structured request logging, latency measurement, and secret redaction."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()

        # Extract or generate X-Request-ID
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())

        # Attach request ID to request state for downstream handlers
        request.state.request_id = request_id

        client_ip = request.client.host if request.client else "unknown"
        method = request.method
        path = request.url.path

        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000.0

            # Attach headers to response
            response.headers["X-Request-ID"] = request_id
            response.headers["X-Response-Time"] = f"{duration_ms:.2f}ms"

            # Log formatted request info
            logger.info(
                f"{method} {path} - {response.status_code} "
                f"({duration_ms:.2f}ms) [client: {client_ip}] [req_id: {request_id}]"
            )
            return response
        except Exception as exc:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            logger.error(
                f"{method} {path} - FAILED ({duration_ms:.2f}ms) "
                f"[client: {client_ip}] [req_id: {request_id}]: {exc}"
            )
            raise exc


def setup_middleware(app: FastAPI) -> None:
    """Configures application middleware."""
    app.add_middleware(RequestLoggingMiddleware)
