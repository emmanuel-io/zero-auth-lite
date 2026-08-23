"""Shared rendering helpers for built-in browser pages."""

from pathlib import Path

from fastapi import Request
from starlette.responses import HTMLResponse
from starlette.templating import Jinja2Templates


TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
STATIC_DIR = Path(__file__).resolve().parent / "static"
templates = Jinja2Templates(directory=TEMPLATE_DIR)
CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; form-action 'self'; "
    "frame-ancestors 'none'; base-uri 'none'"
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
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    return response
