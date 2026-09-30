"""Public operational health endpoints."""

from logging import getLogger
from typing import Literal

from fastapi import APIRouter, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.db.migrations import ensure_database_is_migrated
from app.openapi_tags import HEALTH_TAG


logger = getLogger(__name__)


class HealthResponse(BaseModel):
    """Minimal status returned to an operational health probe."""

    status: Literal["ok", "not_ready"] = Field(
        description="Whether the requested health condition is satisfied."
    )


router = APIRouter(prefix="/health", tags=[HEALTH_TAG])


@router.get("/live")
async def liveness() -> HealthResponse:
    """Report that the application process can serve requests."""
    return HealthResponse(status="ok")


@router.get(
    "/ready",
    responses={
        status.HTTP_200_OK: {
            "model": HealthResponse,
            "description": "SQLite is reachable and its Alembic schema is current.",
        },
        status.HTTP_503_SERVICE_UNAVAILABLE: {
            "model": HealthResponse,
            "description": "SQLite or its Alembic schema is not ready.",
        },
    },
)
async def readiness(request: Request) -> JSONResponse:
    """Report whether SQLite is reachable and migrated to the current heads."""
    try:
        await ensure_database_is_migrated(request.app.state.core_engine)
    # Readiness must fail closed for every state that cannot be verified.
    except Exception as exc:  # noqa: BLE001
        if not getattr(request.app.state, "readiness_failure_active", False):
            request.app.state.readiness_failure_active = True
            logger.warning(
                "event=readiness outcome=failure reason=%s",
                type(exc).__name__,
            )
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=HealthResponse(status="not_ready").model_dump(mode="json"),
        )
    if getattr(request.app.state, "readiness_failure_active", False):
        request.app.state.readiness_failure_active = False
        logger.info("event=readiness outcome=recovered")
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content=HealthResponse(status="ok").model_dump(mode="json"),
    )
