import pytest
from fastapi.testclient import TestClient

def test_get_url_intelligence_api_unauthorized(client: TestClient):
    response = client.get("/api/v1/email/nonexistent-case-id/url-intelligence")
    assert response.status_code == 401

def test_enrich_url_intelligence_api_unauthorized(client: TestClient):
    response = client.post("/api/v1/email/some-case-id/url-intelligence")
    assert response.status_code == 401
