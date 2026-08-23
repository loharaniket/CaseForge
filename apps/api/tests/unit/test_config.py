from src.core.config import Settings


def test_settings_default_values():
    """Verify that default settings instantiate with expected values."""
    settings = Settings()
    assert settings.PROJECT_NAME == "ThreatTrace AI API"
    assert settings.VERSION == "0.1.0"
    assert settings.ENVIRONMENT in ["development", "test", "production"]
    assert settings.API_V1_STR == "/api/v1"
    assert len(settings.BACKEND_CORS_ORIGINS) >= 1


def test_settings_cors_string_parsing():
    """Verify comma-separated CORS origins parsing."""
    settings = Settings(
        BACKEND_CORS_ORIGINS="http://localhost:3000,http://example.com"  # type: ignore
    )
    assert "http://localhost:3000" in settings.BACKEND_CORS_ORIGINS
    assert "http://example.com" in settings.BACKEND_CORS_ORIGINS
