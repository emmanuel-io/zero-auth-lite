"""Shared rendering helpers for built-in browser pages."""

from dataclasses import dataclass
from pathlib import Path
from typing import cast

from fastapi import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.templating import Jinja2Templates

from app.identity.organizations.specs import OrganizationSpecs
from app.identity.users.specs import UserSpecs
from app.oauth2.specs import OAuth2Specs
from app.password.validation import MAX_PASSWORD_LENGTH, MIN_PASSWORD_LENGTH


TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"
templates = Jinja2Templates(directory=TEMPLATE_DIR)


@dataclass(frozen=True, slots=True)
class BrowserFormConstraints:
    """Domain limits exposed to native browser form validation."""

    organization_name_max: int = OrganizationSpecs.NAME_LENGTH_MAX
    email_max: int = UserSpecs.EMAIL_LENGTH_MAX
    first_name_max: int = UserSpecs.FIRST_NAME_LENGTH_MAX
    last_name_max: int = UserSpecs.LAST_NAME_LENGTH_MAX
    password_min: int = MIN_PASSWORD_LENGTH
    password_max: int = MAX_PASSWORD_LENGTH
    oauth2_client_name_max: int = OAuth2Specs.CLIENT_NAME_LENGTH_MAX
    oauth2_scope_list_max: int = OAuth2Specs.SCOPE_LIST_LENGTH_MAX


template_globals = cast(  # type: ignore[redundant-cast]
    "dict[str, object]", templates.env.globals
)
template_globals["form_constraints"] = BrowserFormConstraints()
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; script-src 'self'; form-action 'self'; "
    "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'"
)


def no_store_redirect(url: str, *, status_code: int = 303) -> RedirectResponse:
    """Redirect without allowing sensitive browser state to be cached."""
    return RedirectResponse(
        url,
        status_code=status_code,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


def render_page(
    request: Request,
    template_name: str,
    *,
    status_code: int = 200,
    **context: object,
) -> HTMLResponse:
    """Render an autoescaped browser page without caching sensitive state."""
    response = templates.TemplateResponse(
        request=request,
        name=template_name,
        context=context,
        status_code=status_code,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    return response
