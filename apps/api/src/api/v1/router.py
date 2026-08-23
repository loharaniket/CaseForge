from fastapi import APIRouter

from src.api.v1.endpoints import auth, email, health

api_router = APIRouter()
api_router.include_router(health.router, tags=["System"])
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(email.router, prefix="/email", tags=["Email Ingestion"])
