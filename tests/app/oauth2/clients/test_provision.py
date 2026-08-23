"""Tests for local OAuth2 machine-client provisioning."""

import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest
from app.db.models.oauth2_client import (
    OAuth2ClientDB,
    OAuth2ClientMachineOrganizationDB,
)
from app.db.models.organization import OrganizationDB
from app.identity.public_ids import format_organization_id
from app.oauth2.clients.access import OAuth2ClientMachineOrganizationAccess
from app.oauth2.clients.dtos import OAuth2ClientRegistrationDTO
from app.oauth2.clients.provision import (
    MachineClientProvisionError,
    main,
    persist_machine_client,
    prepare_machine_client,
    PreparedMachineClient,
)
from app.password.async_hashing import verify_password
from app.settings.root import Settings
from fastapi import FastAPI, status
from sqlalchemy import insert, select

from app.oauth2.clients import provision


pytestmark = pytest.mark.integration
TEST_CLIENT_SECRET = "one-time-secret"  # noqa: S105
TEST_CLIENT_SECRET_HASH = "stored-hash"  # noqa: S105


@pytest.mark.asyncio
async def test_provision_persists_confidential_client_and_selected_organization(
    app: FastAPI,
    client: httpx.AsyncClient,
) -> None:
    """Persist only the generated secret hash and explicit organization assignment."""
    async with app.state.core_session_factory() as db_session:
        organization = (
            await db_session.execute(
                insert(OrganizationDB)
                .values(name="Machine target")
                .returning(OrganizationDB)
            )
        ).scalar_one()
        await db_session.commit()
        prepared = await prepare_machine_client(
            settings=app.state.settings,
            password_hasher=app.state.password_hasher,
            name="Background worker",
            scopes=["organization:read"],
            machine_organization_access=OAuth2ClientMachineOrganizationAccess.SINGLE,
            organization_ids=[format_organization_id(organization.public_id)],
        )
        async with db_session.begin():
            await persist_machine_client(db_session, prepared)
        stored_client = await db_session.scalar(
            select(OAuth2ClientDB).where(OAuth2ClientDB.client_id == prepared.client_id)
        )
        assert stored_client is not None
        assignment_count = len(
            (
                await db_session.scalars(
                    select(OAuth2ClientMachineOrganizationDB).where(
                        OAuth2ClientMachineOrganizationDB.client_id == stored_client.id
                    )
                )
            ).all()
        )

    assert stored_client.client_secret != prepared.client_secret
    assert await verify_password(
        app.state.password_hasher,
        password=prepared.client_secret,
        password_hash=stored_client.client_secret or "",
    )
    assert stored_client.grant_types == ["client_credentials"]
    assert assignment_count == 1
    token_response = await client.post(
        "/oauth2/token",
        data={"grant_type": "client_credentials", "scope": "organization:read"},
        auth=(prepared.client_id, prepared.client_secret),
    )
    assert token_response.status_code == status.HTTP_200_OK
    assert token_response.json()["access_token"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "organization_ids"),
    [
        (OAuth2ClientMachineOrganizationAccess.NONE, ["org_0000000000000"]),
        (OAuth2ClientMachineOrganizationAccess.SINGLE, []),
        (OAuth2ClientMachineOrganizationAccess.SELECTED, []),
        (OAuth2ClientMachineOrganizationAccess.UNRESTRICTED, ["org_0000000000000"]),
    ],
)
async def test_provision_rejects_incoherent_assignment_shapes(
    app: FastAPI,
    mode: OAuth2ClientMachineOrganizationAccess,
    organization_ids: list[str],
) -> None:
    """Reject access policies whose assignment cardinality is ambiguous."""
    with pytest.raises(MachineClientProvisionError, match=r"access|requires"):
        await prepare_machine_client(
            settings=app.state.settings,
            password_hasher=app.state.password_hasher,
            name="Invalid worker",
            scopes=[],
            machine_organization_access=mode,
            organization_ids=organization_ids,
        )


def test_provision_cli_serializes_work_and_prints_secret_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Use the dedicated lock and expose generated credentials only on stdout."""
    prepared = PreparedMachineClient(
        registration=OAuth2ClientRegistrationDTO(
            name="CLI worker",
            grant_types=["client_credentials"],
            scopes=[],
            redirect_uris=[],
            is_confidential=True,
            requires_consent=False,
        ),
        client_id="client-id",
        client_secret=TEST_CLIENT_SECRET,
        client_secret_hash=TEST_CLIENT_SECRET_HASH,
        machine_organization_access=OAuth2ClientMachineOrganizationAccess.NONE,
        organization_ids=(),
    )
    observed_lock: list[tuple[Path, str]] = []

    @contextmanager
    def fake_lock(directory: Path, *, lock_filename: str) -> Iterator[None]:
        observed_lock.append((directory, lock_filename))
        yield

    async def fake_provision(
        *_args: object, **_kwargs: object
    ) -> PreparedMachineClient:
        return prepared

    settings = Settings(runtime_dir=tmp_path)
    monkeypatch.setattr(provision, "load_settings", lambda: settings)
    monkeypatch.setattr(provision, "configure_logging", lambda _level: None)
    monkeypatch.setattr(provision, "serialized_bootstrap", fake_lock)
    monkeypatch.setattr(provision, "provision_machine_client", fake_provision)

    main(["--name", "CLI worker"])

    output = json.loads(capsys.readouterr().out)
    assert output == {
        "client_id": "client-id",
        "client_secret": TEST_CLIENT_SECRET,
    }
    assert observed_lock == [(tmp_path / "bootstrap", "oauth2-client-provision.lock")]
    assert TEST_CLIENT_SECRET not in caplog.text
