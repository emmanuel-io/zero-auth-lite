"""Apply authoritative browser-session cookie intentions to final responses.

Clearing authenticated transport cannot be replaced by a later refresh. The
pre-session operation is the explicit transition that keeps the session clear
while issuing fresh anonymous CSRF state.
"""

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING

from fastapi import Request, Response, status
from starlette.types import Message

from app.browser_sessions.cookies import (
    delete_csrf_cookie,
    delete_session_cookie,
    session_csrf_uses_cookie,
    set_csrf_cookie,
    set_session_cookie,
)


if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send

    from app.browser_sessions.settings import BrowserSessionSettings, CSRFSettings


SESSION_COOKIE_MUTATION_STATE_KEY = "session_cookie_mutation"


class BrowserSessionCookieMutationKind(StrEnum):
    """Supported final-response browser-session cookie mutations."""

    REFRESH = "refresh"
    CLEAR_ALWAYS = "clear_always"
    CLEAR_ON_SUCCESS = "clear_on_success"
    PRE_SESSION = "pre_session"


@dataclass(frozen=True, slots=True)
class BrowserSessionCookieMutation:
    """Request-scoped intent applied after the endpoint builds its response."""

    kind: BrowserSessionCookieMutationKind
    session_id: str | None = None
    csrf_token: str | None = None
    max_age_seconds: int | None = None


def request_session_cookie_refresh(
    request: Request,
    *,
    session_id: str,
    csrf_token: str,
    max_age_seconds: int,
) -> None:
    """Record a cookie refresh for the final response."""
    existing = getattr(request.state, SESSION_COOKIE_MUTATION_STATE_KEY, None)
    if isinstance(existing, BrowserSessionCookieMutation) and existing.kind in {
        BrowserSessionCookieMutationKind.CLEAR_ALWAYS,
        BrowserSessionCookieMutationKind.CLEAR_ON_SUCCESS,
        BrowserSessionCookieMutationKind.PRE_SESSION,
    }:
        return
    setattr(
        request.state,
        SESSION_COOKIE_MUTATION_STATE_KEY,
        BrowserSessionCookieMutation(
            kind=BrowserSessionCookieMutationKind.REFRESH,
            session_id=session_id,
            csrf_token=csrf_token,
            max_age_seconds=max_age_seconds,
        ),
    )


def request_session_cookie_clear_always(request: Request) -> None:
    """Clear browser transport even when the final response is an error."""
    existing = getattr(request.state, SESSION_COOKIE_MUTATION_STATE_KEY, None)
    if (
        isinstance(existing, BrowserSessionCookieMutation)
        and existing.kind == BrowserSessionCookieMutationKind.PRE_SESSION
    ):
        return
    setattr(
        request.state,
        SESSION_COOKIE_MUTATION_STATE_KEY,
        BrowserSessionCookieMutation(
            kind=BrowserSessionCookieMutationKind.CLEAR_ALWAYS
        ),
    )


def request_session_cookie_clear_on_success(request: Request) -> None:
    """Clear browser transport only after transactional work succeeds."""
    existing = getattr(request.state, SESSION_COOKIE_MUTATION_STATE_KEY, None)
    if isinstance(existing, BrowserSessionCookieMutation) and existing.kind in {
        BrowserSessionCookieMutationKind.CLEAR_ALWAYS,
        BrowserSessionCookieMutationKind.PRE_SESSION,
    }:
        return
    setattr(
        request.state,
        SESSION_COOKIE_MUTATION_STATE_KEY,
        BrowserSessionCookieMutation(
            kind=BrowserSessionCookieMutationKind.CLEAR_ON_SUCCESS
        ),
    )


def request_pre_session_csrf_cookie(request: Request, *, csrf_token: str) -> None:
    """Clear authenticated transport and issue fresh anonymous CSRF state."""
    setattr(
        request.state,
        SESSION_COOKIE_MUTATION_STATE_KEY,
        BrowserSessionCookieMutation(
            kind=BrowserSessionCookieMutationKind.PRE_SESSION,
            csrf_token=csrf_token,
        ),
    )


class BrowserSessionResponseTransportMiddleware:
    """Apply request-scoped cookie intentions to the real response."""

    def __init__(
        self,
        app: "ASGIApp",
        *,
        csrf_settings: "CSRFSettings",
        session_settings: "BrowserSessionSettings",
    ) -> None:
        """Store the immutable cookie settings used for response mutations."""
        self.app = app
        self.csrf_settings = csrf_settings
        self.browser_session_settings = session_settings

    def _cookie_headers(
        self, mutation: BrowserSessionCookieMutation
    ) -> list[tuple[bytes, bytes]]:
        """Build only the Set-Cookie headers required by one mutation."""
        response = Response()
        if mutation.kind in {
            BrowserSessionCookieMutationKind.CLEAR_ALWAYS,
            BrowserSessionCookieMutationKind.CLEAR_ON_SUCCESS,
        }:
            delete_session_cookie(response, self.browser_session_settings)
            delete_csrf_cookie(response, self.csrf_settings)
        elif mutation.kind == BrowserSessionCookieMutationKind.PRE_SESSION:
            if mutation.csrf_token is None:
                msg = "Pre-session transport requires a CSRF token."
                raise RuntimeError(msg)
            delete_session_cookie(response, self.browser_session_settings)
            set_csrf_cookie(response, mutation.csrf_token, self.csrf_settings)
        else:
            if (
                mutation.session_id is None
                or mutation.csrf_token is None
                or mutation.max_age_seconds is None
            ):
                msg = "A session-cookie refresh requires complete transport state."
                raise RuntimeError(msg)
            set_session_cookie(
                response,
                mutation.session_id,
                self.browser_session_settings,
                max_age_seconds=mutation.max_age_seconds,
            )
            if session_csrf_uses_cookie(self.csrf_settings):
                set_csrf_cookie(
                    response,
                    mutation.csrf_token,
                    self.csrf_settings,
                    max_age_seconds=mutation.max_age_seconds,
                )
        return [header for header in response.raw_headers if header[0] == b"set-cookie"]

    def _affected_cookie_names(
        self, mutation: BrowserSessionCookieMutation
    ) -> frozenset[bytes]:
        """Return cookie names owned by a final transport mutation."""
        names = {self.browser_session_settings.cookie_name.encode()}
        refresh_skips_csrf_cookie = (
            mutation.kind == BrowserSessionCookieMutationKind.REFRESH
            and not session_csrf_uses_cookie(self.csrf_settings)
        )
        if not refresh_skips_csrf_cookie:
            names.add(self.csrf_settings.cookie_name.encode())
        return frozenset(names)

    @staticmethod
    def _set_cookie_name(header_value: bytes) -> bytes:
        """Extract the name from one Set-Cookie header value."""
        return header_value.split(b"=", 1)[0].strip()

    async def __call__(
        self,
        scope: "Scope",
        receive: "Receive",
        send: "Send",
    ) -> None:
        """Append requested cookie mutations when the final response starts."""
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_session_transport(message: Message) -> None:
            mutation = scope.get("state", {}).get(SESSION_COOKIE_MUTATION_STATE_KEY)
            if message["type"] == "http.response.start" and isinstance(
                mutation, BrowserSessionCookieMutation
            ):
                success_only = mutation.kind in {
                    BrowserSessionCookieMutationKind.REFRESH,
                    BrowserSessionCookieMutationKind.CLEAR_ON_SUCCESS,
                }
                should_apply = (
                    not success_only or message["status"] < status.HTTP_400_BAD_REQUEST
                )
                if should_apply:
                    affected_cookie_names = self._affected_cookie_names(mutation)
                    preserved_headers = [
                        header
                        for header in message["headers"]
                        if header[0].lower() != b"set-cookie"
                        or self._set_cookie_name(header[1]) not in affected_cookie_names
                    ]
                    message["headers"] = [
                        *preserved_headers,
                        *self._cookie_headers(mutation),
                    ]
            await send(message)

        await self.app(scope, receive, send_with_session_transport)
