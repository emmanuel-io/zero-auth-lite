"""Tests for organization persistence models."""

from pathlib import Path

import pytest
from app.db.base import Base
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.identity.users.enums import OrganizationUserRole, UserEmailStatus
from sqlalchemy import create_engine, insert
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


pytestmark = pytest.mark.integration


def _create_membership_tables(connection: Connection) -> None:
    """Create the three tables needed by membership constraint tests."""
    Base.metadata.create_all(
        connection,
        tables=[
            OrganizationDB.__table__,
            UserDB.__table__,
            UserEmailDB.__table__,
            OrganizationMembershipDB.__table__,
        ],
    )


def test_organization_name_cannot_be_blank(tmp_path: Path) -> None:
    """Assert persistence rejects an organization without a meaningful name."""
    engine = create_engine(f"sqlite:///{tmp_path / 'blank-name.db'}")
    try:
        with engine.connect() as connection:
            Base.metadata.create_all(connection, tables=[OrganizationDB.__table__])
            with Session(connection) as db_session:
                db_session.add(OrganizationDB(name="   ", public_id=1))
                with pytest.raises(IntegrityError):
                    db_session.flush()
    finally:
        engine.dispose()


def test_organization_delete_is_restricted_while_users_exist(tmp_path: Path) -> None:
    """Assert ORM deletion preserves the user foreign-key restriction."""
    engine = create_engine(f"sqlite:///{tmp_path / 'models.db'}")
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            _create_membership_tables(connection)
            with Session(connection) as db_session:
                organization = (
                    db_session.execute(
                        insert(OrganizationDB)
                        .values(name="Occupied Organization", public_id=1)
                        .returning(OrganizationDB)
                    )
                ).scalar_one()
                user = (
                    db_session.execute(
                        insert(UserDB)
                        .values(
                            first_name="Organization",
                            last_name="Member",
                            hashed_password="not-used-in-this-test",  # noqa: S106
                            public_id=2,
                        )
                        .returning(UserDB)
                    )
                ).scalar_one()
                db_session.add(
                    UserEmailDB(
                        user_id=user.id,
                        email="occupied@example.com",
                        normalized_email="occupied@example.com",
                        status=UserEmailStatus.CURRENT,
                    )
                )
                db_session.add(
                    OrganizationMembershipDB(
                        user_id=user.id,
                        organization_id=organization.id,
                        role=OrganizationUserRole.MEMBER,
                    )
                )
                db_session.commit()

                db_session.delete(organization)

                with pytest.raises(IntegrityError):
                    db_session.flush()
    finally:
        engine.dispose()


def test_membership_rejects_operator_as_an_organization_role(tmp_path: Path) -> None:
    """Limit persisted organization roles to member and admin."""
    engine = create_engine(f"sqlite:///{tmp_path / 'invalid-role.db'}")
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            _create_membership_tables(connection)
            with Session(connection) as db_session:
                organization = OrganizationDB(name="Scoped Roles", public_id=1)
                user = UserDB(
                    hashed_password="not-used-in-this-test",  # noqa: S106
                    public_id=2,
                )
                db_session.add_all([organization, user])
                db_session.flush()
                db_session.add(
                    UserEmailDB(
                        user_id=user.id,
                        email="invalid-role@example.com",
                        normalized_email="invalid-role@example.com",
                        status=UserEmailStatus.CURRENT,
                    )
                )

                with pytest.raises(IntegrityError):
                    db_session.connection().exec_driver_sql(
                        "INSERT INTO organization_membership "
                        "(user_id, organization_id, role) VALUES (?, ?, ?)",
                        (user.id, organization.id, "operator"),
                    )
    finally:
        engine.dispose()


def test_user_delete_cascades_to_organization_membership(tmp_path: Path) -> None:
    """Remove membership state with its owning user."""
    engine = create_engine(f"sqlite:///{tmp_path / 'membership-cascade.db'}")
    try:
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA foreign_keys=ON")
            _create_membership_tables(connection)
            with Session(connection) as db_session:
                organization = OrganizationDB(name="Cascade", public_id=1)
                user = UserDB(
                    hashed_password="not-used-in-this-test",  # noqa: S106
                    public_id=2,
                )
                db_session.add_all([organization, user])
                db_session.flush()
                user_email = UserEmailDB(
                    user_id=user.id,
                    email="cascade@example.com",
                    normalized_email="cascade@example.com",
                    status=UserEmailStatus.CURRENT,
                )
                db_session.add(user_email)
                membership = OrganizationMembershipDB(
                    user_id=user.id,
                    organization_id=organization.id,
                    role=OrganizationUserRole.MEMBER,
                )
                db_session.add(membership)
                db_session.commit()
                user_id = user.id
                user_email_id = user_email.id

                db_session.delete(user)
                db_session.commit()

                assert db_session.get(OrganizationMembershipDB, user_id) is None
                assert db_session.get(UserEmailDB, user_email_id) is None
    finally:
        engine.dispose()
