"""Cache-control policy for authenticated application API responses."""

from fastapi import Response


def prevent_authenticated_response_storage(response: Response) -> None:
    """Prevent browsers and intermediaries from storing identity data."""
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
