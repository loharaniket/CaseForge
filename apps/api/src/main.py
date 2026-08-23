from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from src.api.endpoints.email import router as email_router
from src.api.endpoints.health_ready import router as health_ready_router
from src.api.v1.endpoints.health import get_health
from src.api.v1.router import api_router
from src.core.config import Settings
from src.core.config import settings as global_settings
from src.core.errors import setup_exception_handlers
from src.core.logging import logger
from src.core.middleware import setup_middleware
from src.db.session import get_db
from src.schemas.health import HealthResponse


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan context manager for startup and shutdown events."""
    active_settings: Settings = getattr(app.state, "settings", global_settings)
    logger.info(
        f"Starting {active_settings.PROJECT_NAME} v{active_settings.VERSION} "
        f"[{active_settings.ENVIRONMENT}]"
    )
    yield
    logger.info(f"Shutting down {active_settings.PROJECT_NAME}")


def create_app(settings_override: Settings | None = None) -> FastAPI:
    """FastAPI Application Factory."""
    app_settings = settings_override or global_settings

    app = FastAPI(
        title=app_settings.PROJECT_NAME,
        version=app_settings.VERSION,
        description="ThreatTrace AI — Cybersecurity Email Investigation Platform Backend API",
        openapi_url=f"{app_settings.API_V1_STR}/openapi.json",
        docs_url=f"{app_settings.API_V1_STR}/docs",
        redoc_url=f"{app_settings.API_V1_STR}/redoc",
        lifespan=lifespan,
    )

    # Store settings on app state
    app.state.settings = app_settings

    # 1. Setup structured exception handlers
    setup_exception_handlers(app)

    # 2. Setup request logging and correlation middleware
    setup_middleware(app)

    # 3. Configure CORS middleware
    if app_settings.BACKEND_CORS_ORIGINS:
        origins = [str(origin).rstrip("/") for origin in app_settings.BACKEND_CORS_ORIGINS]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # 4. Mount top-level API routers
    # Mount /api/health and /api/ready
    app.include_router(health_ready_router, prefix="/api")

    # Mount /api/email for direct email ingestion
    app.include_router(email_router, prefix="/api/email", tags=["Email Ingestion"])

    # Mount /api/v1 versioned endpoints
    app.include_router(api_router, prefix=app_settings.API_V1_STR)

    # Root health alias for backward compatibility and container probes
    @app.get(
        "/health",
        response_model=HealthResponse,
        tags=["Diagnostics"],
        summary="Root Health Check",
        include_in_schema=True,
    )
    def root_health(db: Session = Depends(get_db)) -> HealthResponse:
        """Root health check endpoint."""
        return get_health(db=db)

    @app.get("/", tags=["System"], summary="Root Metadata")
    def root_info() -> dict:
        """Root metadata endpoint."""
        return {
            "name": app_settings.PROJECT_NAME,
            "version": app_settings.VERSION,
            "environment": app_settings.ENVIRONMENT,
            "docs_url": f"{app_settings.API_V1_STR}/docs",
        }

    return app


# Default application instance
app = create_app()
