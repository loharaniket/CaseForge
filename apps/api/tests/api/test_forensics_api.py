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
        email="forensics.api.analyst@threattrace.io",
        hashed_password=hash_password("ForensicsApiPass123!"),
        full_name="Forensics API Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "forensics.api.analyst@threattrace.io", "password": "ForensicsApiPass123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_analyze_header_forensics_api(client: TestClient, db_session: Session):
    """Test POST /api/email/{case_id}/header-forensics returns structured relay and spoof analysis."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "spoofed_return_path.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("spoofed.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    forensics_res = client.post(f"/api/email/{case_id}/header-forensics", headers=headers)
    assert forensics_res.status_code == 200
    data = forensics_res.json()

    assert data["case_id"] == case_id
    assert len(data["relay_hops"]) >= 1
    assert data["spf_status"] in ("softfail", "fail", "none", "pass")
    assert len(data["spoofing_indicators"]) > 0
    assert data["forensics_risk_score"] > 0.0


def test_get_header_forensics_on_demand_api(client: TestClient, db_session: Session):
    """Test GET /api/email/{case_id}/header-forensics generates analysis on-demand."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "multi_hop_relay.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("multi.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    get_res = client.get(f"/api/email/{case_id}/header-forensics", headers=headers)
    assert get_res.status_code == 200
    data = get_res.json()

    assert data["case_id"] == case_id
    assert len(data["relay_hops"]) == 3
    assert data["spf_status"] == "pass"
    assert data["dkim_status"] == "pass"
    assert data["dmarc_status"] == "pass"


def test_forensics_api_unauthenticated_rejected(client: TestClient):
    """Test unauthenticated request to forensics endpoint returns 401."""
    res = client.get("/api/email/some-case-id/header-forensics")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_forensics_api_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test header forensics on nonexistent case returns 404."""
    headers = _get_auth_headers(client, db_session)
    res = client.get("/api/email/nonexistent-case-id-1234/header-forensics", headers=headers)
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"
