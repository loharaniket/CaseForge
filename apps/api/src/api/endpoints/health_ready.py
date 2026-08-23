from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.orm import Session

from src.core.config import settings
from src.db.session import check_db_connection, get_db
from src.schemas.health import DatabaseStatus, HealthStatus, LivenessResponse
from src.schemas.ready import ReadyResponse, ReadyStatus

router = APIRouter()


@router.get(
    "/health",
    response_model=LivenessResponse,
    tags=["Diagnostics"],
    summary="Application Liveness Check",
    description="Confirms that the FastAPI application process is up and responding to requests.",
)
def check_liveness() -> LivenessResponse:
    """Liveness probe: verifies process availability."""
    return LivenessResponse(
        status=HealthStatus.HEALTHY,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        timestamp=datetime.now(UTC),
    )


@router.get(
    "/ready",
    response_model=ReadyResponse,
    tags=["Diagnostics"],
    summary="Dependency Readiness Check",
    description="Verifies operational connectivity to essential dependencies (e.g. PostgreSQL database). Returns 200 when ready, 503 when degraded.",
    responses={
        200: {"description": "All required dependencies are connected and operational."},
        503: {"description": "One or more critical dependencies are unavailable."},
    },
)
def check_readiness(
    response: Response,
    db: Session = Depends(get_db),
) -> ReadyResponse:
    """Readiness probe: validates database connectivity."""
    is_db_connected = check_db_connection(session=db)

    if is_db_connected:
        return ReadyResponse(
            status=ReadyStatus.READY,
            database=DatabaseStatus.CONNECTED,
            version=settings.VERSION,
            timestamp=datetime.now(UTC),
            details={"database": "operational"},
        )

    response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
    return ReadyResponse(
        status=ReadyStatus.NOT_READY,
        database=DatabaseStatus.DISCONNECTED,
        version=settings.VERSION,
        timestamp=datetime.now(UTC),
        details={"database": "unreachable"},
    )
