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
        email="risk.api.analyst@threattrace.io",
        hashed_password=hash_password("RiskApiPass123!"),
        full_name="Risk API Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "risk.api.analyst@threattrace.io", "password": "RiskApiPass123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_compute_case_risk_api(client: TestClient, db_session: Session):
    """Test POST /api/email/{case_id}/risk-assessment calculates and returns risk response."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "credential_phishing.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("cred_phish.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    risk_res = client.post(f"/api/email/{case_id}/risk-assessment", headers=headers)
    assert risk_res.status_code == 200
    data = risk_res.json()

    assert data["case_id"] == case_id
    assert 0.0 <= data["total_score"] <= 100.0
    assert data["severity"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert "breakdown" in data
    assert data["weights_applied"]["ai_analysis"] == 0.40
    assert data["weights_applied"]["header_forensics"] == 0.25
    assert data["weights_applied"]["domain_reputation"] == 0.15
    assert data["weights_applied"]["ip_reputation"] == 0.10
    assert data["weights_applied"]["url_analysis"] == 0.10


def test_get_case_risk_on_demand_api(client: TestClient, db_session: Session):
    """Test GET /api/email/{case_id}/risk-assessment computes score on-demand."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "normal_email.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("normal.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    get_res = client.get(f"/api/email/{case_id}/risk-assessment", headers=headers)
    assert get_res.status_code == 200
    data = get_res.json()

    assert data["case_id"] == case_id
    assert data["severity"] == "LOW"
    assert data["total_score"] < 25.0


def test_risk_api_unauthenticated_rejected(client: TestClient):
    """Test unauthenticated request to risk endpoint returns 401."""
    res = client.get("/api/email/some-case-id/risk-assessment")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_risk_api_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test risk calculation on unknown case returns 404."""
    headers = _get_auth_headers(client, db_session)
    res = client.get("/api/email/unknown-case-id-8888/risk-assessment", headers=headers)
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"
