from fastapi import APIRouter

from src.api.v1.endpoints import auth, health

api_router = APIRouter()
api_router.include_router(health.router, tags=["System"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
