"""Import canonical-server SQLAlchemy models for Alembic metadata discovery.

Alembic imports this module so `Base.metadata` sees every relational table
owned by the runnable server.
"""

from app.db.models.browser_session import BrowserSessionDB
from app.db.models.notification_outbox import NotificationOutboxDB
from app.db.models.oauth2_authorization_code import (
    OAuth2AuthorizationCodeDB,
)
from app.db.models.oauth2_authorization_transaction import (
    OAuth2AuthorizationTransactionDB,
)
from app.db.models.oauth2_client import OAuth2ClientDB
from app.db.models.oauth2_device_authorization import (
    OAuth2DeviceAuthorizationDB,
)
from app.db.models.oauth2_session import OAuth2SessionDB
from app.db.models.oauth2_token_state import (
    OAuth2RefreshTokenHistoryDB,
    OAuth2TokenStateDB,
)
from app.db.models.organization import OrganizationDB
from app.db.models.organization_membership import OrganizationMembershipDB
from app.db.models.user import UserDB, UserEmailDB
from app.db.models.workflow_token import UserWorkflowTokenDB


__all__ = [
    "BrowserSessionDB",
    "NotificationOutboxDB",
    "OAuth2AuthorizationCodeDB",
    "OAuth2AuthorizationTransactionDB",
    "OAuth2ClientDB",
    "OAuth2DeviceAuthorizationDB",
    "OAuth2RefreshTokenHistoryDB",
    "OAuth2SessionDB",
    "OAuth2TokenStateDB",
    "OrganizationDB",
    "OrganizationMembershipDB",
    "UserDB",
    "UserEmailDB",
    "UserWorkflowTokenDB",
]
