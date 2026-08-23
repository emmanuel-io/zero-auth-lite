"""Validation helpers for public HTTP origins."""

from urllib.parse import urlsplit

from pydantic import AnyHttpUrl


def validate_absolute_http_origin(*, name: str, value: str) -> None:
    """Require an exact HTTP(S) origin without credentials or URL components."""
    try:
        AnyHttpUrl(value)
    except ValueError as exc:
        msg = f"{name} must be a valid absolute HTTP(S) origin"
        raise ValueError(msg) from exc
    parsed = urlsplit(value)
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        msg = f"{name} must be a valid absolute HTTP(S) origin"
        raise ValueError(msg)
