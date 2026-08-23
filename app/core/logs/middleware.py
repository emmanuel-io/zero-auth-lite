"""Correlation-aware HTTP request logging middleware."""

import logging
from time import perf_counter
from typing import TYPE_CHECKING

from starlette.types import Message


if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


logger = logging.getLogger("app.http")


class RequestLoggingMiddleware:
    """Log one safe summary after each HTTP request completes."""

    def __init__(self, app: "ASGIApp") -> None:
        """Store the wrapped ASGI application."""
        self.app = app

    async def __call__(
        self,
        scope: "Scope",
        receive: "Receive",
        send: "Send",
    ) -> None:
        """Log the method, path, status, and duration for HTTP requests."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        status_code = 500
        started_at = perf_counter()

        async def send_with_status(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, send_with_status)
        finally:
            duration_ms = (perf_counter() - started_at) * 1000
            logger.info(
                "%s %s -> %d %.1fms",
                scope["method"],
                scope["path"],
                status_code,
                duration_ms,
            )
