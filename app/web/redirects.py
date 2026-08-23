"""Safe destination selection for server-rendered authentication flows."""

from urllib.parse import unquote, urlencode, urlsplit, urlunsplit

from app.settings.root import Settings


ASCII_CONTROL_LIMIT = 0x20


def authentication_entry_url(
    settings: Settings,
    *,
    transaction_id: str | None = None,
    device_code: str | None = None,
    return_url: str | None = None,
) -> str:
    """Return the configured login entry point with opaque continuation state."""
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

    query = {
        key: value
        for key, value in (
            ("transaction_id", transaction_id),
            ("device_code", device_code),
            ("return_url", validated_internal_return_target(return_url)),
        )
        if value is not None
    }
    if not query:
        return base_url
    parsed = urlsplit(base_url)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query), ""))


def workflow_completion_url(settings: Settings, *, notice: str) -> str:
    """Return a post-workflow destination without extending external contracts."""
    if settings.ui.authentication_is_builtin and settings.session.enabled:
        return f"/login?{urlencode({'notice': notice})}"
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
    device_code: str | None,
    return_url: str | None,
) -> str:
    """Choose a post-login destination in explicit security priority order."""
    if transaction_id:
        return f"/consent?{urlencode({'transaction_id': transaction_id})}"
    if device_code:
        return f"/oauth2/device/verify?{urlencode({'user_code': device_code})}"
    internal_target = validated_internal_return_target(return_url)
    if internal_target is not None:
        return internal_target
    if settings.default_redirect_url is not None:
        return str(settings.default_redirect_url)
    return "/"
