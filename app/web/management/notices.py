"""Server-owned notices displayed by management pages."""

from enum import StrEnum


class ManagementNotice(StrEnum):
    """Stable query-string codes for management mutation results."""

    BROWSER_SESSIONS_DELETED = "browser-sessions-deleted"
    CLIENT_DELETED = "client-deleted"
    CLIENT_SESSIONS_REVOKED = "client-sessions-revoked"
    CLIENT_UPDATED = "client-updated"
    INACTIVE_SESSIONS_DELETED = "inactive-sessions-deleted"
    INVITATION_PROCESSED = "invitation-processed"
    MACHINE_ACCESS_UPDATED = "machine-access-updated"
    OAUTH2_SESSION_REVOKED = "oauth2-session-revoked"
    OAUTH2_SESSIONS_DELETED = "oauth2-sessions-deleted"
    ORGANIZATION_CREATED = "organization-created"
    ORGANIZATION_SESSIONS_REVOKED = "organization-sessions-revoked"
    ORGANIZATION_UPDATED = "organization-updated"
    PROFILE_UPDATED = "profile-updated"
    SERVER_SESSIONS_REVOKED = "server-sessions-revoked"
    USER_ACCESS_UPDATED = "user-access-updated"
    USER_CREATED = "user-created"
    USER_DELETED = "user-deleted"
    USER_INVITED = "user-invited"
    USER_SESSIONS_REVOKED = "user-sessions-revoked"
    USER_UPDATED = "user-updated"


MANAGEMENT_NOTICE_MESSAGES: dict[ManagementNotice, str] = {
    ManagementNotice.BROWSER_SESSIONS_DELETED: "Browser sessions deleted.",
    ManagementNotice.CLIENT_DELETED: "Client deleted.",
    ManagementNotice.CLIENT_SESSIONS_REVOKED: "Client sessions revoked.",
    ManagementNotice.CLIENT_UPDATED: "Client updated.",
    ManagementNotice.INACTIVE_SESSIONS_DELETED: "Inactive sessions deleted.",
    ManagementNotice.INVITATION_PROCESSED: "Invitation request processed.",
    ManagementNotice.MACHINE_ACCESS_UPDATED: "Machine access updated.",
    ManagementNotice.OAUTH2_SESSION_REVOKED: "OAuth2 session revoked.",
    ManagementNotice.OAUTH2_SESSIONS_DELETED: "OAuth2 sessions deleted.",
    ManagementNotice.ORGANIZATION_CREATED: "Organization created.",
    ManagementNotice.ORGANIZATION_SESSIONS_REVOKED: ("Organization sessions revoked."),
    ManagementNotice.ORGANIZATION_UPDATED: "Organization updated.",
    ManagementNotice.PROFILE_UPDATED: "Profile updated.",
    ManagementNotice.SERVER_SESSIONS_REVOKED: "Server sessions revoked.",
    ManagementNotice.USER_ACCESS_UPDATED: "User access updated.",
    ManagementNotice.USER_CREATED: "User created.",
    ManagementNotice.USER_DELETED: "User deleted.",
    ManagementNotice.USER_INVITED: "User invited.",
    ManagementNotice.USER_SESSIONS_REVOKED: "User sessions revoked.",
    ManagementNotice.USER_UPDATED: "User updated.",
}


def management_notice_text(value: object) -> str | None:
    """Resolve one known notice code and ignore untrusted values."""
    if not isinstance(value, str):
        return None
    try:
        notice = ManagementNotice(value)
    except ValueError:
        return None
    return MANAGEMENT_NOTICE_MESSAGES[notice]
