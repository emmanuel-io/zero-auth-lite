"""Safe destination selection for server-rendered authentication flows."""

from urllib.parse import unquote, urlencode, urlsplit, urlunsplit

from app.settings.root import Settings


ASCII_CONTROL_LIMIT = 0x20


def management_authentication_entry_url(
    settings: Settings,
    *,
    transaction_id: str | None = None,
    user_code: str | None = None,
    return_url: str | None = None,
    notice: str | None = None,
) -> str:
    """Return the management login entry point with safe return state."""
    base_url = settings.ui.urls.login

    query = {
        key: value
        for key, value in (
            ("transaction_id", transaction_id),
            ("user_code", user_code),
            ("return_url", validated_internal_return_target(return_url)),
            ("notice", notice),
        )
        if value is not None
    }
    if not query:
        return base_url
    parsed = urlsplit(base_url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def management_logout_entry_url(settings: Settings) -> str:
    """Return the configured browser logout entry point."""
    return settings.ui.urls.logout


def workflow_completion_url(settings: Settings, *, notice: str) -> str:
    """Return the configured post-workflow authentication destination."""
    if settings.browser_session.enabled:
        return management_authentication_entry_url(settings, notice=notice)
    if settings.default_redirect_url is not None:
        return str(settings.default_redirect_url)
    return "/"


def validated_internal_return_target(value: str | None) -> str | None:
    """Return one same-origin path, rejecting open-redirect representations."""
    if not value or any(
        character.isspace() or ord(character) < ASCII_CONTROL_LIMIT
        for character in value
    ):
        return None
    parsed = urlsplit(value)
    decoded_path = unquote(parsed.path)
    if (
        parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or value.startswith("//")
        or "\\" in value
        or not decoded_path.startswith("/")
        or decoded_path.startswith("//")
        or "\\" in decoded_path
        or any(ord(character) < ASCII_CONTROL_LIMIT for character in decoded_path)
    ):
        return None
    return value


def login_destination(
    settings: Settings,
    *,
    transaction_id: str | None,
    user_code: str | None,
    return_url: str | None,
) -> str:
    """Choose a post-login destination in explicit security priority order."""
    if transaction_id:
        return (
            f"{settings.ui.urls.authorization_consent}?"
            f"{urlencode({'transaction_id': transaction_id})}"
        )
    if user_code:
        return (
            f"{settings.ui.urls.device_interaction}?"
            f"{urlencode({'user_code': user_code})}"
        )
    internal_target = validated_internal_return_target(return_url)
    if internal_target is not None:
        return internal_target
    if settings.default_redirect_url is not None:
        return str(settings.default_redirect_url)
    return "/"
