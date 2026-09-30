"""OAuth2 request checks that require access to raw parameter multiplicity."""

from collections import Counter

from fastapi import Request

from app.oauth2.error_codes import OAuth2ErrorCode
from app.oauth2.errors import OAuth2ProtocolError


FORM_CONTENT_TYPES = frozenset(
    {
        "application/x-www-form-urlencoded",
        "multipart/form-data",
    }
)


def _has_repeated_names(items: list[tuple[str, object]]) -> bool:
    """Return whether one parameter name occurs more than once."""
    return any(count > 1 for count in Counter(name for name, _value in items).values())


async def reject_repeated_protocol_parameters(request: Request) -> None:
    """Reject ambiguous repeated OAuth2 query or form parameters."""
    if _has_repeated_names(list(request.query_params.multi_items())):
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_REQUEST)

    content_type = request.headers.get("content-type", "").partition(";")[0].strip()
    if content_type not in FORM_CONTENT_TYPES:
        return
    form = await request.form()
    if _has_repeated_names(list(form.multi_items())):
        raise OAuth2ProtocolError(error=OAuth2ErrorCode.INVALID_REQUEST)
