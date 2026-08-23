from fastapi.testclient import TestClient

from src.core.config import settings


def test_health_endpoint_v1(client: TestClient):
    """Test /api/v1/health returns expected status and fields."""
    response = client.get(f"{settings.API_V1_STR}/health")
    assert response.status_code == 200
    data = response.json()
    assert "status" in data
    assert "version" in data
    assert "environment" in data
    assert "database" in data
    assert "timestamp" in data
    assert data["version"] == settings.VERSION


def test_health_endpoint_root(client: TestClient):
    """Test root /health alias."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded", "unhealthy"]


def test_root_info_endpoint(client: TestClient):
    """Test / root endpoint returns service metadata."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["name"] == settings.PROJECT_NAME
    assert data["version"] == settings.VERSION
    assert "docs_url" in data
