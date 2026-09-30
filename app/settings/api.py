"""Settings for application-owned JSON API transports."""

from pydantic import BaseModel, ConfigDict


class APISettings(BaseModel):
    """Settings that control optional interactive JSON route adapters.

    Interactive routes cover sessions, identity workflows, and external OAuth2
    interactions. They do not control the `/me`, `/organization`, or `/server`
    APIs.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    interactive_auth_routes_enabled: bool = True
