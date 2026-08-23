"""Shared pytest configuration for the Zero Auth Lite workspace."""

import pytest


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    """Run AnyIO tests on the supported asyncio backend."""
    return "asyncio"
