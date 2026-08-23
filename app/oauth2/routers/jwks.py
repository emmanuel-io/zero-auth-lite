"""OAuth2 JSON Web Key Set router."""

from fastapi import APIRouter, HTTPException, status

from app.oauth2.oidc.jwks import build_jwks
from app.oauth2.oidc.keys import get_verify_keys
from app.oauth2.oidc.schemas import JWKSResponse
from app.openapi_tags import OAUTH2_JWKS_TAG
from app.settings.dependencies import SettingsDep


router = APIRouter(tags=[OAUTH2_JWKS_TAG])


@router.get("/jwks.json", name="jwks")
async def jwks(settings: SettingsDep) -> JWKSResponse:
    """Return public JWT verification keys when JWKS is enabled."""
    if not settings.oauth2.jwks_enabled:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="not_found")
    return JWKSResponse.model_validate(
        build_jwks(keys=get_verify_keys(settings.oauth2))
    )
