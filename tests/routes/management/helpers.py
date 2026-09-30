"""Shared configuration helpers for management route tests."""

from collections.abc import Callable
from typing import Any

from tests.fixtures.settings import app_settings


def with_external_management_presentation() -> Callable[[Any], Any]:
    """Configure external identity workflows and management navigation."""
    return app_settings(
        ui={
            "identity_workflow_mode": "external",
            "management_authentication": "external",
            "urls": {
                "login": "https://frontend.test/login",
                "logout": "https://frontend.test/logout",
                "verification": "https://frontend.test/verify-email",
                "password_reset": "https://frontend.test/reset-password",
                "invitation": "https://frontend.test/accept-invite",
            },
        }
    )
