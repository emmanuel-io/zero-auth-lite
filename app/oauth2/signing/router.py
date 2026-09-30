"""OAuth2 JSON Web Key Set router."""

from fastapi import APIRouter

from app.oauth2.signing.jwks import build_jwks
from app.oauth2.signing.keys import get_verify_keys
from app.oauth2.signing.schemas import JWKSResponse
from app.openapi_tags import OAUTH2_JWKS_TAG
from app.settings.dependencies import SettingsDep


router = APIRouter(tags=[OAUTH2_JWKS_TAG])


@router.get("/jwks.json", name="jwks")
async def jwks(settings: SettingsDep) -> JWKSResponse:
    """Return public JWT verification keys."""
    return JWKSResponse.model_validate(
        build_jwks(keys=get_verify_keys(settings.oauth2))
    )
