"""User-bound continuation of external OAuth2 authorization interactions."""

from typing import Annotated

from fastapi import Depends

from app.oauth2.authorization.dependencies import AuthorizationRequestServiceDep
from app.oauth2.authorization.dtos import AuthorizationTransactionReadDTO
from app.oauth2.authorization.request import AuthorizationRequestInput
from app.oauth2.authorization.result import (
    AuthorizationRedirect,
    AuthorizationResult,
)
from app.oauth2.authorization.transaction import (
    AuthorizationTransactionServiceDep,
    hash_authorization_transaction_id,
)
from app.security.principals import InteractiveUserPrincipalContext


class AuthorizationInteractionService:
    """Continue and decide one server-side authorization transaction."""

    def __init__(
        self,
        *,
        authorization_service: AuthorizationRequestServiceDep,
        transaction_service: AuthorizationTransactionServiceDep,
    ) -> None:
        """Bind the services sharing the request transaction."""
        self.authorization_service = authorization_service
        self.transaction_service = transaction_service

    def _transaction_hash(self, transaction_id: str) -> str:
        """Hash one opaque interaction handle with the protocol secret."""
        secret = (
            self.authorization_service.settings.authorization_code_hash_secret
        ).get_secret_value()
        return hash_authorization_transaction_id(
            transaction_id=transaction_id,
            secret=secret,
        )

    @staticmethod
    def _request_input(
        transaction: AuthorizationTransactionReadDTO,
    ) -> AuthorizationRequestInput:
        """Rebuild protocol input from trusted persisted transaction state."""
        return AuthorizationRequestInput(
            response_type=transaction.response_type,
            client_id=str(transaction.client_id),
            redirect_uri=transaction.redirect_uri,
            scope=transaction.scope,
            state=transaction.state,
            nonce=transaction.nonce,
            code_challenge=transaction.code_challenge,
            code_challenge_method=transaction.code_challenge_method,
        )

    async def continue_interaction(
        self,
        *,
        transaction_id: str,
        user_ctx: InteractiveUserPrincipalContext,
    ) -> AuthorizationResult | None:
        """Bind an interaction and return consent data or a client redirect."""
        transaction_hash = self._transaction_hash(transaction_id)
        transaction = await self.transaction_service.bind_to_user(
            transaction_hash=transaction_hash,
            user_id=user_ctx.user_id,
            organization_id=user_ctx.organization_id,
        )
        if transaction is None:
            return None
        try:
            validated = await self.authorization_service.validate_request(
                self._request_input(transaction)
            )
        except ValueError:
            return None
        if isinstance(validated, AuthorizationRedirect):
            consumed = await self.transaction_service.consume(
                transaction_hash=transaction_hash,
                user_id=user_ctx.user_id,
                organization_id=user_ctx.organization_id,
            )
            return validated if consumed is not None else None
        if not validated.client.requires_consent:
            consumed = await self.transaction_service.consume(
                transaction_hash=transaction_hash,
                user_id=user_ctx.user_id,
                organization_id=user_ctx.organization_id,
            )
            if consumed is None:
                return None
        result = await self.authorization_service.authorize_validated(
            user_ctx=user_ctx,
            validated=validated,
        )
        if (
            isinstance(result, AuthorizationRedirect)
            and validated.client.requires_consent
        ):
            consumed = await self.transaction_service.consume(
                transaction_hash=transaction_hash,
                user_id=user_ctx.user_id,
                organization_id=user_ctx.organization_id,
            )
            if consumed is None:
                return None
        return result

    async def decide(
        self,
        *,
        transaction_id: str,
        decision: str,
        user_ctx: InteractiveUserPrincipalContext,
    ) -> AuthorizationRedirect | None:
        """Consume a bound interaction and apply its explicit user decision."""
        transaction = await self.transaction_service.consume(
            transaction_hash=self._transaction_hash(transaction_id),
            user_id=user_ctx.user_id,
            organization_id=user_ctx.organization_id,
        )
        if transaction is None:
            return None
        try:
            result = await self.authorization_service.authorize_code(
                user_ctx=user_ctx,
                response_type=transaction.response_type,
                client_id=str(transaction.client_id),
                redirect_uri=transaction.redirect_uri,
                scope=transaction.scope,
                state=transaction.state,
                nonce=transaction.nonce,
                code_challenge=transaction.code_challenge,
                code_challenge_method=transaction.code_challenge_method,
                consent=decision,
            )
        except ValueError:
            return None
        return result if isinstance(result, AuthorizationRedirect) else None


def get_authorization_interaction_service(
    authorization_service: AuthorizationRequestServiceDep,
    transaction_service: AuthorizationTransactionServiceDep,
) -> AuthorizationInteractionService:
    """Provide the external authorization-interaction coordinator."""
    return AuthorizationInteractionService(
        authorization_service=authorization_service,
        transaction_service=transaction_service,
    )


AuthorizationInteractionServiceDep = Annotated[
    AuthorizationInteractionService,
    Depends(get_authorization_interaction_service),
]
