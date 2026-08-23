from typing import Literal

from pydantic import AnyHttpUrl, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # General
    PROJECT_NAME: str = "ThreatTrace AI API"
    VERSION: str = "0.1.0"
    ENVIRONMENT: Literal["development", "test", "staging", "production"] = "development"
    LOG_LEVEL: str = "INFO"

    # API Server
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_V1_STR: str = "/api/v1"

    # CORS
    BACKEND_CORS_ORIGINS: list[str | AnyHttpUrl] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
    ]

    # JWT Authentication
    JWT_SECRET_KEY: str = "threattrace_development_jwt_secret_key_change_in_production"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 8  # 8 hours

    # Evidence Storage & Upload Limits
    MAX_UPLOAD_SIZE_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    STORAGE_DIR: str = "storage/evidence"
    ALLOWED_EMAIL_EXTENSIONS: list[str] = [".eml"]

    # Database Configuration
    POSTGRES_SERVER: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str = "threattrace_user"
    POSTGRES_PASSWORD: str = "threattrace_secret_password"
    POSTGRES_DB: str = "threattrace"
    DATABASE_URL: str = "postgresql+psycopg://threattrace_user:threattrace_secret_password@localhost:5432/threattrace"

    # Database Connection Pool Settings
    POSTGRES_POOL_SIZE: int = 5
    POSTGRES_MAX_OVERFLOW: int = 10
    POSTGRES_POOL_TIMEOUT: int = 30
    POSTGRES_CONNECT_TIMEOUT: int = 2

    # Threat Intelligence External Providers (Keys from env only)
    ABUSEIPDB_API_KEY: str | None = None
    VIRUSTOTAL_API_KEY: str | None = None
    INTEL_CACHE_TTL_SECONDS: int = 3600

    @field_validator("LOG_LEVEL")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        valid_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper_v = v.upper()
        if upper_v not in valid_levels:
            raise ValueError(f"LOG_LEVEL must be one of {valid_levels}, got '{v}'")
        return upper_v

    @field_validator("API_PORT", "POSTGRES_PORT")
    @classmethod
    def validate_port(cls, v: int) -> int:
        if not (1 <= v <= 65535):
            raise ValueError(f"Port must be between 1 and 65535, got {v}")
        return v

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        valid_prefixes = (
            "postgresql://",
            "postgresql+psycopg://",
            "postgresql+asyncpg://",
            "sqlite://",
        )
        if not any(v.startswith(prefix) for prefix in valid_prefixes):
            raise ValueError(f"DATABASE_URL must start with one of {valid_prefixes}, got '{v}'")
        return v

    @field_validator("BACKEND_CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | list[str]) -> list[str] | str:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v


settings = Settings()
