import io
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.user import User, UserRole

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


def _get_auth_headers(client: TestClient, db_session: Session) -> dict[str, str]:
    """Helper to provision test analyst and return auth header."""
    user = User(
        email="geo.api.analyst@threattrace.io",
        hashed_password=hash_password("GeoApiPass123!"),
        full_name="Geo API Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "geo.api.analyst@threattrace.io", "password": "GeoApiPass123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_enrich_case_geo_infrastructure_api(client: TestClient, db_session: Session):
    """Test POST /api/email/{case_id}/geo-infrastructure enriches all case IPs."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("geo_test.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    geo_res = client.post(f"/api/email/{case_id}/geo-infrastructure", headers=headers)
    assert geo_res.status_code == 200
    data = geo_res.json()

    assert data["case_id"] == case_id
    assert data["total_ips_analyzed"] > 0
    assert "Geolocation describes network infrastructure" in data["disclaimer"]
    assert "Attacker Location" not in str(data)
    assert len(data["ip_infrastructure"]) == data["total_ips_analyzed"]


def test_get_case_geo_infrastructure_on_demand_api(client: TestClient, db_session: Session):
    """Test GET /api/email/{case_id}/geo-infrastructure returns enriched infrastructure."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "multi_hop_relay.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("multi_geo.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    get_res = client.get(f"/api/email/{case_id}/geo-infrastructure", headers=headers)
    assert get_res.status_code == 200
    data = get_res.json()

    assert data["case_id"] == case_id
    assert data["total_ips_analyzed"] > 0


def test_geo_api_unauthenticated_rejected(client: TestClient):
    """Test unauthenticated request to GeoIP endpoint returns 401."""
    res = client.get("/api/email/some-case-id/geo-infrastructure")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_geo_api_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test GeoIP enrichment on nonexistent case returns 404."""
    headers = _get_auth_headers(client, db_session)
    res = client.get("/api/email/nonexistent-case-id-1234/geo-infrastructure", headers=headers)
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"
