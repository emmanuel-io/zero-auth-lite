"""Tests for OAuth2 user identity eligibility."""

import pytest
from app.oauth2.user_identity import load_eligible_oauth2_user_identity
from fastapi import FastAPI
from sqlalchemy.ext.asyncio import AsyncSession

from tests.app.identity.services.helpers import create_organization, create_user


pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_loads_active_verified_user_in_expected_organization(
    app: FastAPI, db_session: AsyncSession
) -> None:
    """Return the canonical identity when every OAuth2 invariant holds."""
    organization = await create_organization(app, name="Eligible Organization")
    user = await create_user(
        app,
        organization_id=organization.id,
        email="eligible@example.com",
    )

    identity = await load_eligible_oauth2_user_identity(
        db_session=db_session,
        user_id=user.id,
        organization_id=organization.id,
    )

    assert identity is not None
    assert identity.user.id == user.id
    assert identity.organization.id == organization.id


@pytest.mark.asyncio
async def test_rejects_missing_user(
    db_session: AsyncSession,
) -> None:
    """Return no identity when the user does not exist."""
    identity = await load_eligible_oauth2_user_identity(
        db_session=db_session,
        user_id=-1,
        organization_id=-1,
    )

    assert identity is None


@pytest.mark.asyncio
async def test_rejects_user_from_another_organization(
    app: FastAPI, db_session: AsyncSession
) -> None:
    """Bind OAuth2 user authority to the expected organization."""
    organization = await create_organization(app, name="Member Organization")
    other_organization = await create_organization(app, name="Other Organization")
    user = await create_user(
        app,
        organization_id=organization.id,
        email="wrong-organization@example.com",
    )

    identity = await load_eligible_oauth2_user_identity(
        db_session=db_session,
        user_id=user.id,
        organization_id=other_organization.id,
    )

    assert identity is None


@pytest.mark.asyncio
async def test_rejects_inactive_user(app: FastAPI, db_session: AsyncSession) -> None:
    """Exclude inactive users from OAuth2 authority."""
    organization = await create_organization(app, name="Inactive Organization")
    user = await create_user(
        app,
        organization_id=organization.id,
        email="inactive@example.com",
        is_active=False,
    )

    identity = await load_eligible_oauth2_user_identity(
        db_session=db_session,
        user_id=user.id,
        organization_id=organization.id,
    )

    assert identity is None


@pytest.mark.asyncio
async def test_rejects_unverified_user(app: FastAPI, db_session: AsyncSession) -> None:
    """Exclude users without a verified current email from OAuth2 authority."""
    organization = await create_organization(app, name="Unverified Organization")
    user = await create_user(
        app,
        organization_id=organization.id,
        email="unverified@example.com",
        email_verified=False,
    )

    identity = await load_eligible_oauth2_user_identity(
        db_session=db_session,
        user_id=user.id,
        organization_id=organization.id,
    )

    assert identity is None
