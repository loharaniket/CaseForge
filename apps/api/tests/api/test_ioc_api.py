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
        email="ioc.api.analyst@threattrace.io",
        hashed_password=hash_password("IocApiPass123!"),
        full_name="IOC API Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "ioc.api.analyst@threattrace.io", "password": "IocApiPass123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_extract_case_iocs_api(client: TestClient, db_session: Session):
    """Test POST /api/email/{case_id}/iocs extracts and persists normalized IOCs."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("ioc_comp.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    ioc_res = client.post(f"/api/email/{case_id}/iocs", headers=headers)
    assert ioc_res.status_code == 200
    data = ioc_res.json()

    assert data["case_id"] == case_id
    assert data["total_count"] > 0
    assert "ipv4" in data["by_type"]
    assert "domain" in data["by_type"]
    assert "url" in data["by_type"]
    assert "email" in data["by_type"]
    assert len(data["iocs"]) == data["total_count"]


def test_get_case_iocs_on_demand_api(client: TestClient, db_session: Session):
    """Test GET /api/email/{case_id}/iocs returns extracted IOCs on demand."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("ioc_comp2.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    get_res = client.get(f"/api/email/{case_id}/iocs", headers=headers)
    assert get_res.status_code == 200
    data = get_res.json()

    assert data["case_id"] == case_id
    assert data["total_count"] > 0
    assert len(data["iocs"]) == data["total_count"]


def test_ioc_api_unauthenticated_rejected(client: TestClient):
    """Test unauthenticated request to IOC endpoint returns 401."""
    res = client.get("/api/email/some-case-id/iocs")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_ioc_api_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test IOC extraction on nonexistent case returns 404."""
    headers = _get_auth_headers(client, db_session)
    res = client.get("/api/email/nonexistent-case-id-1234/iocs", headers=headers)
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"
