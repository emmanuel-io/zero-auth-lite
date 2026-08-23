"""Runtime tests for the OAuth2-only FastAPI validation boundary."""

import base64
from typing import Annotated, Literal

import httpx
import pytest
from app.db.errors import DatabaseBusyError
from app.oauth2.error_handler import oauth2_protocol_error_handler
from app.oauth2.errors import OAuth2ProtocolError
from app.oauth2.grants.dependencies import OAuth2ClientBasicDep
from app.oauth2.protocol_route import OAuth2ProtocolRoute
from fastapi import APIRouter, FastAPI, Form, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import AnyUrl


pytestmark = pytest.mark.unit


@pytest.mark.asyncio
async def test_protocol_validation_is_oauth2_scoped() -> None:
    """Convert protocol validation to 400 without changing application 422s."""
    app = FastAPI()
    protocol_router = APIRouter(route_class=OAuth2ProtocolRoute)

    @protocol_router.get("/oauth2/authorize")
    async def authorize(
        response_type: Annotated[Literal["code"], Query()],
        client_id: Annotated[str, Query(min_length=1)],
        redirect_uri: Annotated[AnyUrl, Query()],
    ) -> dict[str, str]:
        return {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": str(redirect_uri),
        }

    @protocol_router.post("/oauth2/token")
    async def token(
        grant_type: Annotated[Literal["client_credentials"], Form()],
    ) -> dict[str, str]:
        return {"grant_type": grant_type}

    @protocol_router.post("/oauth2/revoke")
    async def revoke(
        token: Annotated[str, Form(min_length=1)],
    ) -> dict[str, str]:
        return {"token": token}

    @protocol_router.post("/oauth2/introspect")
    async def introspect(
        token: Annotated[str, Form(min_length=1)],
    ) -> dict[str, str]:
        return {"token": token}

    @protocol_router.post("/oauth2/device_authorization")
    async def device_authorization(
        client_id: Annotated[str, Form(min_length=1)],
    ) -> dict[str, str]:
        return {"client_id": client_id}

    @protocol_router.post("/oauth2/client-auth")
    async def client_auth(
        basic_credentials: OAuth2ClientBasicDep,
        client_id: Annotated[str | None, Form()] = None,
        client_secret: Annotated[str | None, Form()] = None,
    ) -> dict[str, str]:
        if basic_credentials is not None and (client_id or client_secret):
            raise OAuth2ProtocolError(error="invalid_request")
        if basic_credentials is not None:
            return {
                "source": "header",
                "client_id": basic_credentials.username,
                "client_secret": basic_credentials.password,
            }
        if client_id and client_secret:
            return {
                "source": "body",
                "client_id": client_id,
                "client_secret": client_secret,
            }
        raise OAuth2ProtocolError(error="invalid_request")

    @app.post("/application")
    async def application(name: Annotated[str, Form()]) -> dict[str, str]:
        return {"name": name}

    app.include_router(protocol_router)
    app.add_exception_handler(OAuth2ProtocolError, oauth2_protocol_error_handler)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        malformed_authorize = await client.get("/oauth2/authorize")
        missing_grant = await client.post("/oauth2/token")
        unsupported_grant = await client.post(
            "/oauth2/token",
            data={"grant_type": "password"},
        )
        missing_revoke_token = await client.post("/oauth2/revoke")
        missing_introspect_token = await client.post("/oauth2/introspect")
        malformed_device = await client.post("/oauth2/device_authorization")
        basic_secret = base64.b64encode(b"client:secret").decode()
        basic_client_auth = await client.post(
            "/oauth2/client-auth",
            headers={"Authorization": f"Basic {basic_secret}"},
        )
        form_client_auth = await client.post(
            "/oauth2/client-auth",
            data={"client_id": "client", "client_secret": "secret"},
        )
        conflicting_client_auth = await client.post(
            "/oauth2/client-auth",
            headers={"Authorization": f"Basic {basic_secret}"},
            data={"client_id": "client", "client_secret": "secret"},
        )
        application_error = await client.post("/application")

    assert malformed_authorize.status_code == status.HTTP_400_BAD_REQUEST
    assert malformed_authorize.json() == {"error": "invalid_request"}
    assert missing_grant.status_code == status.HTTP_400_BAD_REQUEST
    assert missing_grant.json() == {"error": "invalid_request"}
    assert unsupported_grant.status_code == status.HTTP_400_BAD_REQUEST
    assert unsupported_grant.json() == {"error": "unsupported_grant_type"}
    assert missing_revoke_token.status_code == status.HTTP_400_BAD_REQUEST
    assert missing_revoke_token.json() == {"error": "invalid_request"}
    assert missing_introspect_token.status_code == status.HTTP_400_BAD_REQUEST
    assert missing_introspect_token.json() == {"error": "invalid_request"}
    assert malformed_device.status_code == status.HTTP_400_BAD_REQUEST
    assert malformed_device.json() == {"error": "invalid_request"}
    assert basic_client_auth.status_code == status.HTTP_200_OK
    assert basic_client_auth.json() == {
        "source": "header",
        "client_id": "client",
        "client_secret": "secret",
    }
    assert form_client_auth.status_code == status.HTTP_200_OK
    assert form_client_auth.json() == {
        "source": "body",
        "client_id": "client",
        "client_secret": "secret",
    }
    assert conflicting_client_auth.status_code == status.HTTP_400_BAD_REQUEST
    assert conflicting_client_auth.json() == {"error": "invalid_request"}
    assert application_error.status_code == status.HTTP_422_UNPROCESSABLE_CONTENT
    assert "detail" in application_error.json()


@pytest.mark.asyncio
async def test_database_busy_error_uses_oauth2_error_contract() -> None:
    """Translate database contention without leaking an application error body."""
    app = FastAPI()
    protocol_router = APIRouter(route_class=OAuth2ProtocolRoute)

    @protocol_router.post("/oauth2/busy")
    async def busy() -> None:
        raise DatabaseBusyError

    async def handle_oauth2_error(request: Request, exc: Exception) -> JSONResponse:
        assert isinstance(exc, OAuth2ProtocolError)
        return await oauth2_protocol_error_handler(request, exc)

    app.include_router(protocol_router)
    app.add_exception_handler(OAuth2ProtocolError, handle_oauth2_error)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        response = await client.post("/oauth2/busy")

    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert response.headers["retry-after"] == "1"
    assert response.json() == {"error": "temporarily_unavailable"}
