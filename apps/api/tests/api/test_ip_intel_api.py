import pytest
from fastapi.testclient import TestClient

def test_get_ip_intelligence_api_unauthorized(client: TestClient):
    response = client.get("/api/v1/email/nonexistent-case-id/ip-intelligence")
    assert response.status_code == 401

def test_enrich_ip_intelligence_api_unauthorized(client: TestClient):
    response = client.post("/api/v1/email/some-case-id/ip-intelligence")
    assert response.status_code == 401
