"""Offline provisioning for confidential OAuth2 machine clients."""

from __future__ import annotations

import argparse
import asyncio
import json
from dataclasses import dataclass
from logging import getLogger
from typing import TYPE_CHECKING

from pydantic import ValidationError
from sqlalchemy import insert, select

from app.bootstrap.lock import serialized_bootstrap
from app.core.logs.config import configure_logging
from app.db.engine import create_engine, create_session_factory
from app.db.migrations import ensure_database_is_migrated
from app.db.models.oauth2_client import (
    OAuth2ClientDB,
    OAuth2ClientMachineOrganizationDB,
)
from app.db.models.organization import OrganizationDB
from app.identity.public_ids import parse_organization_id
from app.oauth2.clients.access import OAuth2ClientMachineOrganizationAccess
from app.oauth2.clients.credential_generation import (
    generate_oauth2_client_id,
    generate_oauth2_client_secret,
)
from app.oauth2.clients.dtos import OAuth2ClientRegistrationDTO
from app.oauth2.clients.management.policy import OAuth2ClientPolicy
from app.oauth2.settings import OAuth2GrantType
from app.oauth2.specs import OAuth2Specs
from app.password.async_hashing import hash_password
from app.password.pwdlib_hasher import PwdlibPasswordHasher
from app.settings.root import load_settings


if TYPE_CHECKING:
    from collections.abc import Sequence

    from sqlalchemy.ext.asyncio import AsyncSession

    from app.password.protocols import PasswordHasherProtocol
    from app.settings.root import Settings


logger = getLogger(__name__)
ERR_TOO_MANY_ORGANIZATIONS = "Too many organization assignments."
ERR_DUPLICATE_ORGANIZATIONS = "Organization identifiers must be unique."
ERR_SINGLE_ORGANIZATION = "single access requires exactly one organization ID."
ERR_SELECTED_ORGANIZATION = "selected access requires at least one organization ID."
ERR_INVALID_ORGANIZATION_ID = "Invalid organization identifier."
ERR_ORGANIZATION_NOT_FOUND = "One or more organizations do not exist."


class MachineClientProvisionError(ValueError):
    """Raised when local machine-client provisioning input is invalid."""


@dataclass(frozen=True, slots=True)
class PreparedMachineClient:
    """Validated machine registration with its generated credentials."""

    registration: OAuth2ClientRegistrationDTO
    client_id: str
    client_secret: str
    client_secret_hash: str
    machine_organization_access: OAuth2ClientMachineOrganizationAccess
    organization_ids: tuple[str, ...]


def _validate_assignment_shape(
    mode: OAuth2ClientMachineOrganizationAccess, organization_ids: Sequence[str]
) -> None:
    """Validate assignment cardinality without touching persistence."""
    count = len(organization_ids)
    if count > OAuth2Specs.CLIENT_ORGANIZATION_ASSIGNMENTS_MAX:
        raise MachineClientProvisionError(ERR_TOO_MANY_ORGANIZATIONS)
    if len(set(organization_ids)) != count:
        raise MachineClientProvisionError(ERR_DUPLICATE_ORGANIZATIONS)
    if (
        mode
        in {
            OAuth2ClientMachineOrganizationAccess.NONE,
            OAuth2ClientMachineOrganizationAccess.UNRESTRICTED,
        }
        and count
    ):
        msg = f"{mode.value} access does not accept organization IDs."
        raise MachineClientProvisionError(msg)
    if mode == OAuth2ClientMachineOrganizationAccess.SINGLE and count != 1:
        raise MachineClientProvisionError(ERR_SINGLE_ORGANIZATION)
    if mode == OAuth2ClientMachineOrganizationAccess.SELECTED and count == 0:
        raise MachineClientProvisionError(ERR_SELECTED_ORGANIZATION)


async def prepare_machine_client(  # noqa: PLR0913
    *,
    settings: Settings,
    password_hasher: PasswordHasherProtocol,
    name: str,
    scopes: Sequence[str],
    machine_organization_access: OAuth2ClientMachineOrganizationAccess,
    organization_ids: Sequence[str],
) -> PreparedMachineClient:
    """Validate input and hash a generated secret before opening a transaction."""
    _validate_assignment_shape(machine_organization_access, organization_ids)
    registration = OAuth2ClientRegistrationDTO(
        name=name,
        grant_types=[OAuth2GrantType.client_credentials.value],
        scopes=list(scopes),
        redirect_uris=[],
        is_confidential=True,
        requires_consent=False,
        is_active=True,
    )
    OAuth2ClientPolicy(settings.oauth2).validate(
        grant_types=registration.grant_types,
        redirect_uris=registration.redirect_uris,
        is_confidential=registration.is_confidential,
        requires_consent=registration.requires_consent,
    )
    client_secret = generate_oauth2_client_secret()
    return PreparedMachineClient(
        registration=registration,
        client_id=generate_oauth2_client_id(),
        client_secret=client_secret,
        client_secret_hash=await hash_password(password_hasher, client_secret),
        machine_organization_access=machine_organization_access,
        organization_ids=tuple(organization_ids),
    )


async def persist_machine_client(
    db_session: AsyncSession, prepared: PreparedMachineClient
) -> None:
    """Persist one prepared client inside the caller-owned transaction."""
    try:
        public_ids = [
            parse_organization_id(value) for value in prepared.organization_ids
        ]
    except ValueError as exc:
        raise MachineClientProvisionError(ERR_INVALID_ORGANIZATION_ID) from exc
    organizations = (
        (
            await db_session.scalars(
                select(OrganizationDB).where(
                    OrganizationDB.public_id.in_([int(value) for value in public_ids])
                )
            )
        ).all()
        if public_ids
        else []
    )
    by_public_id = {int(row.public_id): row for row in organizations}
    if len(by_public_id) != len(public_ids):
        raise MachineClientProvisionError(ERR_ORGANIZATION_NOT_FOUND)

    registration = prepared.registration
    client_db_id = (
        await db_session.execute(
            insert(OAuth2ClientDB)
            .values(
                client_id=prepared.client_id,
                client_secret=prepared.client_secret_hash,
                name=registration.name,
                grant_types=registration.grant_types,
                scopes=registration.scopes,
                redirect_uris=registration.redirect_uris,
                is_confidential=True,
                requires_consent=False,
                is_active=True,
                user_organization_access=registration.user_organization_access,
                machine_organization_access=prepared.machine_organization_access,
            )
            .returning(OAuth2ClientDB.id)
        )
    ).scalar_one()
    if public_ids:
        await db_session.execute(
            insert(OAuth2ClientMachineOrganizationDB),
            [
                {
                    "client_id": client_db_id,
                    "organization_id": by_public_id[int(public_id)].id,
                }
                for public_id in public_ids
            ],
        )
    await db_session.flush()


async def provision_machine_client(
    settings: Settings,
    *,
    name: str,
    scopes: Sequence[str],
    machine_organization_access: OAuth2ClientMachineOrganizationAccess,
    organization_ids: Sequence[str],
) -> PreparedMachineClient:
    """Prepare and atomically persist one local machine client."""
    prepared = await prepare_machine_client(
        settings=settings,
        password_hasher=PwdlibPasswordHasher(),
        name=name,
        scopes=scopes,
        machine_organization_access=machine_organization_access,
        organization_ids=organization_ids,
    )
    engine = create_engine(settings.db_path, echo=settings.db_echo)
    try:
        await ensure_database_is_migrated(engine)
        session_factory = create_session_factory(engine)
        async with session_factory.begin() as db_session:
            await persist_machine_client(db_session, prepared)
    finally:
        await engine.dispose()
    logger.info(
        (
            "event=oauth2_client_provisioned outcome=success client_id=%s "
            "machine_organization_access=%s"
        ),
        prepared.client_id,
        prepared.machine_organization_access,
    )
    return prepared


def _parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    """Parse machine-client provisioning arguments."""
    parser = argparse.ArgumentParser(
        description=(
            "Provision a confidential Zero Auth Lite client_credentials client."
        ),
    )
    parser.add_argument("--name", required=True, help="Client display name.")
    parser.add_argument(
        "--scope", action="append", default=[], help="Allowed scope; repeat as needed."
    )
    parser.add_argument(
        "--machine-organization-access",
        choices=[mode.value for mode in OAuth2ClientMachineOrganizationAccess],
        default=OAuth2ClientMachineOrganizationAccess.NONE.value,
    )
    parser.add_argument(
        "--organization-id",
        action="append",
        default=[],
        help="Public organization ID; repeat as needed.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> None:
    """Provision a machine client and print its one-time credentials as JSON."""
    args = _parse_args(argv)
    settings = load_settings()
    configure_logging(settings.app.log_level)
    try:
        with serialized_bootstrap(
            settings.runtime_dir / "bootstrap",
            lock_filename="oauth2-client-provision.lock",
        ):
            prepared = asyncio.run(
                provision_machine_client(
                    settings,
                    name=args.name,
                    scopes=args.scope,
                    machine_organization_access=OAuth2ClientMachineOrganizationAccess(
                        args.machine_organization_access
                    ),
                    organization_ids=args.organization_id,
                )
            )
    except (ValueError, ValidationError) as exc:
        raise SystemExit(str(exc)) from exc
    print(  # noqa: T201
        json.dumps(
            {
                "client_id": prepared.client_id,
                "client_secret": prepared.client_secret,
            },
            separators=(",", ":"),
        )
    )


if __name__ == "__main__":
    main()
