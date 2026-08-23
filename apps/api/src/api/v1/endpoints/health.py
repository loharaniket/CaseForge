from datetime import UTC, datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.core.config import settings
from src.db.session import check_db_connection, get_db
from src.schemas.health import DatabaseStatus, HealthResponse, HealthStatus

router = APIRouter()


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health Check",
    description="Returns the current operational status of the ThreatTrace AI API and its database connection.",
)
def get_health(db: Session = Depends(get_db)) -> HealthResponse:
    """Performs system diagnostics and returns service status."""
    is_db_connected = check_db_connection(session=db)

    db_status = DatabaseStatus.CONNECTED if is_db_connected else DatabaseStatus.DISCONNECTED
    status = HealthStatus.HEALTHY if is_db_connected else HealthStatus.DEGRADED

    return HealthResponse(
        status=status,
        version=settings.VERSION,
        environment=settings.ENVIRONMENT,
        database=db_status,
        timestamp=datetime.now(UTC),
    )
