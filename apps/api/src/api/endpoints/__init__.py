"""Top-level API endpoints (health, ready)."""

from src.api.endpoints.health_ready import router as health_ready_router

__all__ = ["health_ready_router"]
