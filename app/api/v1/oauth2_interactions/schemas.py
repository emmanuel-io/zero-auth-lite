"""JSON contracts for external OAuth2 authorization and device interactions."""

from typing import Literal

from pydantic import BaseModel, ConfigDict


class OAuth2InteractionDecisionRequest(BaseModel):
    """Authenticated user decision for one OAuth2 interaction."""

    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "deny"]


class AuthorizationConsentRequiredResponse(BaseModel):
    """Consent details safe to render in an external frontend."""

    action: Literal["consent_required"] = "consent_required"
    client_name: str
    scopes: list[str]


class AuthorizationRedirectResponse(BaseModel):
    """Validated OAuth2 callback URL the browser must follow."""

    action: Literal["redirect"] = "redirect"
    redirect_url: str


type AuthorizationInteractionResponse = (
    AuthorizationConsentRequiredResponse | AuthorizationRedirectResponse
)


class DeviceInteractionResponse(BaseModel):
    """Device authorization details safe to show to the current user."""

    client_name: str
    scopes: list[str]
