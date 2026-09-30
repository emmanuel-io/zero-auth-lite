"""Tests for shared OAuth2 client-management error translation."""

import pytest
from app.oauth2.clients.management.app_errors import (
    InvalidOAuth2ClientError,
    OAuth2ClientManagementConflictError,
    OAuth2ClientNotFoundError,
    OAuth2ClientOrganizationAccessConflictError,
    raise_oauth2_client_management_error,
)
from app.oauth2.clients.management.errors import (
    InvalidOAuth2ClientPayloadError,
    OAuth2ClientConflictError,
    OAuth2ClientManagementErrorReason,
    OAuth2ClientManagementNotFoundError,
    OAuth2ClientOrganizationAccessConflictError as ServiceOrganizationConflictError,
    OAuth2ClientServiceError,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("service_error", "application_error", "code"),
    [
        (
            OAuth2ClientConflictError(),
            OAuth2ClientManagementConflictError,
            "OAUTH2_CLIENT_CONFLICT",
        ),
        (
            OAuth2ClientManagementNotFoundError(),
            OAuth2ClientNotFoundError,
            "OAUTH2_CLIENT_NOT_FOUND",
        ),
    ],
)
def test_translates_client_service_error_categories(
    service_error: OAuth2ClientServiceError,
    application_error: type[OAuth2ClientManagementConflictError]
    | type[OAuth2ClientNotFoundError],
    code: str,
) -> None:
    """Preserve the public category for service errors without a detail."""
    with pytest.raises(application_error) as caught:
        raise_oauth2_client_management_error(service_error)

    assert caught.value.code == code
    assert caught.value.response_payload().details == []


def test_translates_allowlisted_invalid_client_detail() -> None:
    """Expose a safe stable reason for invalid client configuration."""
    with pytest.raises(InvalidOAuth2ClientError) as caught:
        raise_oauth2_client_management_error(
            InvalidOAuth2ClientPayloadError(
                OAuth2ClientManagementErrorReason.GRANT_TYPES_REQUIRED
            )
        )

    detail = caught.value.response_payload().details[0]
    assert detail.type == "grant_types_required"
    assert detail.message == "At least one grant type is required."
    assert caught.value.display_message == detail.message


def test_translates_allowlisted_organization_conflict_detail() -> None:
    """Normalize a legacy internal reason before exposing it."""
    with pytest.raises(OAuth2ClientOrganizationAccessConflictError) as caught:
        raise_oauth2_client_management_error(
            ServiceOrganizationConflictError(
                OAuth2ClientManagementErrorReason.SINGLE_ORGANIZATION_REQUIRED
            )
        )

    detail = caught.value.response_payload().details[0]
    assert detail.type == "oauth2_client_single_organization_required"
    assert detail.message == (
        "Single-organization user access requires exactly one assignment."
    )


def test_unknown_detail_is_not_reflected() -> None:
    """Use a generic detail instead of publishing arbitrary service text."""
    raw_detail = "private database diagnostic"
    with pytest.raises(InvalidOAuth2ClientError) as caught:
        raise_oauth2_client_management_error(
            InvalidOAuth2ClientPayloadError(diagnostic=raw_detail)
        )

    payload = caught.value.response_payload()
    assert payload.details[0].type == "oauth2_client_configuration_invalid"
    assert raw_detail not in payload.model_dump_json()


def test_private_organization_diagnostic_is_not_reflected() -> None:
    """Use the organization fallback for a non-publishable conflict diagnostic."""
    raw_diagnostic = "private assignment diagnostic"
    with pytest.raises(OAuth2ClientOrganizationAccessConflictError) as caught:
        raise_oauth2_client_management_error(
            ServiceOrganizationConflictError(diagnostic=raw_diagnostic)
        )

    payload = caught.value.response_payload()
    assert payload.details[0].type == "oauth2_client_organization_access_conflict"
    assert raw_diagnostic not in payload.model_dump_json()


@pytest.mark.parametrize("reason", list(OAuth2ClientManagementErrorReason))
def test_every_publishable_reason_has_an_explicit_public_detail(
    reason: OAuth2ClientManagementErrorReason,
) -> None:
    """Fail when a typed service reason has no public translation."""
    with pytest.raises(InvalidOAuth2ClientError) as caught:
        raise_oauth2_client_management_error(InvalidOAuth2ClientPayloadError(reason))

    detail = caught.value.response_payload().details[0]
    assert detail.type == reason.value
    assert detail.message


def test_unknown_service_error_remains_unexpected() -> None:
    """Keep unmapped programming errors on the logged unexpected-error path."""

    class NewOAuth2ClientServiceError(OAuth2ClientServiceError):
        """Represent an unhandled future service error."""

    service_error = NewOAuth2ClientServiceError()
    with pytest.raises(
        RuntimeError,
        match="Unhandled OAuth2 client service error",
    ) as caught:
        raise_oauth2_client_management_error(service_error)

    assert caught.value.__cause__ is service_error
