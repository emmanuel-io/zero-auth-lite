"""Browser navigation for the OAuth2 authorization flow."""

from urllib.parse import urlencode, urlsplit, urlunsplit

from app.settings.root import Settings


def authorization_login_url(settings: Settings, *, transaction_id: str) -> str:
    """Return the configured login entry point for an authorization transaction."""
    if settings.ui.authentication_is_builtin and settings.session.enabled:
        base_url = "/login"
    elif (
        not settings.ui.authentication_is_builtin
        and settings.ui.external_login_url is not None
    ):
        base_url = str(settings.ui.external_login_url)
    else:
        msg = "No browser authentication entry point is configured."
        raise RuntimeError(msg)

    parsed = urlsplit(base_url)
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            urlencode({"transaction_id": transaction_id}),
            "",
        )
    )
