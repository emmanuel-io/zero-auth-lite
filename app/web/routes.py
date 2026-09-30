"""Route markers for server-rendered browser surfaces."""

from fastapi import Request
from fastapi.routing import APIRoute


class BrowserPageRoute(APIRoute):
    """Mark a route whose errors must be rendered for a browser."""


class ManagementPageRoute(BrowserPageRoute):
    """Mark a browser route that supports management HTML fragments."""


def browser_route(request: Request) -> BrowserPageRoute | None:
    """Return the resolved browser route, if the request targets one."""
    route = request.scope.get("route")
    return route if isinstance(route, BrowserPageRoute) else None
