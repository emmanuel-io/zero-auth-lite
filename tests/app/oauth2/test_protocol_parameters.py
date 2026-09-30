"""Tests for raw OAuth2 parameter multiplicity checks."""

from typing import cast, TYPE_CHECKING

import httpx
import pytest
from app.oauth2.error_handler import oauth2_protocol_error_handler
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.protocol_parameters import reject_repeated_protocol_parameters
from fastapi import APIRouter, Depends, FastAPI, status


if TYPE_CHECKING:
    from starlette.types import ExceptionHandler


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("method", "target", "content", "headers"),
    [
        ("GET", "/protocol?state=one&state=two", None, None),
        (
            "POST",
            "/protocol",
            "grant_type=client_credentials&grant_type=refresh_token",
            {"Content-Type": "application/x-www-form-urlencoded"},
        ),
        (
            "POST",
            "/protocol",
            "client_id=one&client_id=two",
            {"Content-Type": "application/x-www-form-urlencoded"},
        ),
        (
            "POST",
            "/protocol",
            "token=one&token=two",
            {"Content-Type": "application/x-www-form-urlencoded"},
        ),
        (
            "POST",
            "/protocol",
            "decision=approve&decision=deny",
            {"Content-Type": "application/x-www-form-urlencoded"},
        ),
        ("GET", "/protocol?unknown=one&unknown=two", None, None),
    ],
)
async def test_repeated_protocol_parameters_are_rejected(
    method: str,
    target: str,
    content: str | None,
    headers: dict[str, str] | None,
) -> None:
    """Reject repeated known and unknown names before endpoint execution."""
    app = FastAPI()
    router = APIRouter(dependencies=[Depends(reject_repeated_protocol_parameters)])

    @router.api_route("/protocol", methods=["GET", "POST"])
    async def protocol() -> dict[str, bool]:
        return {"executed": True}

    app.include_router(router)
    app.add_exception_handler(
        OAuth2ProtocolError,
        cast("ExceptionHandler", oauth2_protocol_error_handler),
    )

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.request(
            method,
            target,
            content=content,
            headers=headers,
        )

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {"error": "invalid_request"}


@pytest.mark.asyncio
async def test_distinct_protocol_parameters_are_accepted() -> None:
    """Allow ordinary query and form requests to continue to typed extraction."""
    app = FastAPI()
    router = APIRouter(dependencies=[Depends(reject_repeated_protocol_parameters)])

    @router.post("/protocol")
    async def protocol() -> dict[str, bool]:
        return {"executed": True}

    app.include_router(router)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post(
            "/protocol?state=one",
            data={"grant_type": "client_credentials", "scope": "read"},
        )

    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {"executed": True}
