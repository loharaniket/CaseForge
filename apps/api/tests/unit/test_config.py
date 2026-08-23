import pytest
from pydantic import ValidationError

from src.core.config import Settings


def test_settings_default_values():
    """Verify that default settings instantiate with expected values."""
    settings = Settings()
    assert settings.PROJECT_NAME == "ThreatTrace AI API"
    assert settings.VERSION == "0.1.0"
    assert settings.ENVIRONMENT in ["development", "test", "staging", "production"]
    assert settings.API_V1_STR == "/api/v1"
    assert len(settings.BACKEND_CORS_ORIGINS) >= 1
    assert settings.POSTGRES_POOL_SIZE == 5
    assert settings.POSTGRES_CONNECT_TIMEOUT == 2


def test_settings_cors_string_parsing():
    """Verify comma-separated CORS origins parsing."""
    settings = Settings(
        BACKEND_CORS_ORIGINS="http://localhost:3000,http://example.com"  # type: ignore
    )
    assert "http://localhost:3000" in settings.BACKEND_CORS_ORIGINS
    assert "http://example.com" in settings.BACKEND_CORS_ORIGINS


def test_settings_custom_values():
    """Verify settings initialization with custom values."""
    settings = Settings(
        PROJECT_NAME="Custom ThreatTrace",
        VERSION="2.0.0",
        ENVIRONMENT="staging",
        LOG_LEVEL="DEBUG",
        API_PORT=9000,
        POSTGRES_PORT=5433,
    )
    assert settings.PROJECT_NAME == "Custom ThreatTrace"
    assert settings.VERSION == "2.0.0"
    assert settings.ENVIRONMENT == "staging"
    assert settings.LOG_LEVEL == "DEBUG"
    assert settings.API_PORT == 9000
    assert settings.POSTGRES_PORT == 5433


def test_invalid_api_port_raises_error():
    """Verify that out-of-range API ports raise validation error."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(API_PORT=70000)
    assert "Port must be between 1 and 65535" in str(exc_info.value)

    with pytest.raises(ValidationError) as exc_info:
        Settings(API_PORT=0)
    assert "Port must be between 1 and 65535" in str(exc_info.value)


def test_invalid_log_level_raises_error():
    """Verify that invalid log level strings raise validation error."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(LOG_LEVEL="TRACE_VERBOSE")
    assert "LOG_LEVEL must be one of" in str(exc_info.value)


def test_invalid_database_url_raises_error():
    """Verify that unsupported database URL prefixes raise validation error."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(DATABASE_URL="mysql://user:pass@localhost/db")
    assert "DATABASE_URL must start with one of" in str(exc_info.value)
