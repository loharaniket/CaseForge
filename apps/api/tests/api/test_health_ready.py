from fastapi.testclient import TestClient

from src.core.config import settings


def test_api_health_liveness(client: TestClient):
    """Test GET /api/health confirms application availability with HTTP 200."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["version"] == settings.VERSION
    assert data["environment"] == settings.ENVIRONMENT
    assert "timestamp" in data
    assert "X-Request-ID" in response.headers
    assert "X-Response-Time" in response.headers


def test_api_ready_success(client: TestClient):
    """Test GET /api/ready returns 200 when database is healthy."""
    response = client.get("/api/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["database"] == "connected"
    assert data["version"] == settings.VERSION
    assert "timestamp" in data
    assert data["details"]["database"] == "operational"


def test_api_ready_degraded_when_db_down(broken_db_client: TestClient):
    """Test GET /api/ready returns 503 Service Unavailable when database is disconnected."""
    response = broken_db_client.get("/api/ready")
    assert response.status_code == 503
    data = response.json()
    assert data["status"] == "not_ready"
    assert data["database"] == "disconnected"
    assert data["version"] == settings.VERSION
    assert "timestamp" in data
    assert data["details"]["database"] == "unreachable"


def test_v1_health_regression(client: TestClient):
    """Regression test: GET /api/v1/health still functions correctly."""
    response = client.get(f"{settings.API_V1_STR}/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded", "unhealthy"]
    assert data["version"] == settings.VERSION
    assert data["database"] in ["connected", "disconnected", "not_configured"]


def test_root_health_regression(client: TestClient):
    """Regression test: GET /health root probe functions correctly."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ["healthy", "degraded", "unhealthy"]
