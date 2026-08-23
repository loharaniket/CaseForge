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
        email="intel.api.analyst@threattrace.io",
        hashed_password=hash_password("IntelApiPass123!"),
        full_name="Intel API Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "intel.api.analyst@threattrace.io", "password": "IntelApiPass123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_query_case_threat_intel_api(client: TestClient, db_session: Session):
    """Test POST /api/email/{case_id}/threat-intel returns reputation results for all case IOCs."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("intel_test.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    intel_res = client.post(f"/api/email/{case_id}/threat-intel", headers=headers)
    assert intel_res.status_code == 200
    data = intel_res.json()

    assert data["case_id"] == case_id
    assert data["ip_lookups_count"] > 0
    assert data["domain_lookups_count"] > 0
    assert len(data["ip_results"]) == data["ip_lookups_count"]
    assert len(data["domain_results"]) == data["domain_lookups_count"]


def test_get_case_threat_intel_on_demand_api(client: TestClient, db_session: Session):
    """Test GET /api/email/{case_id}/threat-intel evaluates reputation on demand."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "multi_hop_relay.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("multi_intel.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    get_res = client.get(f"/api/email/{case_id}/threat-intel", headers=headers)
    assert get_res.status_code == 200
    data = get_res.json()

    assert data["case_id"] == case_id
    assert data["ip_lookups_count"] > 0


def test_intel_api_unauthenticated_rejected(client: TestClient):
    """Test unauthenticated request to threat intel endpoint returns 401."""
    res = client.get("/api/email/some-case-id/threat-intel")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_intel_api_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test threat intel on nonexistent case returns 404."""
    headers = _get_auth_headers(client, db_session)
    res = client.get("/api/email/nonexistent-case-id-1234/threat-intel", headers=headers)
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"
