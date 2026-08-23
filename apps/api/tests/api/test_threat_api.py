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
        email="api.analyst@threattrace.io",
        hashed_password=hash_password("ApiAnalystPass123!"),
        full_name="Threat API Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "api.analyst@threattrace.io", "password": "ApiAnalystPass123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_analyze_uploaded_email_threat(client: TestClient, db_session: Session):
    """Test full flow: Upload phishing EML -> Call POST /threat-analysis -> Verify explainable classification."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "credential_phishing.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("cred_phish.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    # Trigger threat analysis endpoint
    threat_res = client.post(f"/api/email/{case_id}/threat-analysis", headers=headers)
    assert threat_res.status_code == 200
    data = threat_res.json()

    assert data["case_id"] == case_id
    assert data["classification"] == "phishing"
    assert data["confidence"] >= 0.80
    assert len(data["reasons"]) > 0
    assert data["model_version"] == "rule-based-heuristic-v1.0.0-dev"
    assert "credentials" in data["signals_detected"]


def test_get_threat_analysis_on_demand(client: TestClient, db_session: Session):
    """Test GET /threat-analysis retrieves assessment on-demand."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "normal_email.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("normal.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    # GET threat analysis directly
    get_res = client.get(f"/api/email/{case_id}/threat-analysis", headers=headers)
    assert get_res.status_code == 200
    data = get_res.json()

    assert data["case_id"] == case_id
    assert data["classification"] == "normal"
    assert data["confidence"] >= 0.85


def test_threat_analysis_unauthenticated_rejected(client: TestClient):
    """Test unauthenticated threat analysis returns 401."""
    res = client.get("/api/email/some-case-id/threat-analysis")
    assert res.status_code == 401
    assert res.json()["error"]["code"] == "UNAUTHORIZED"


def test_threat_analysis_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test threat analysis on unknown case returns 404."""
    headers = _get_auth_headers(client, db_session)
    res = client.get("/api/email/unknown-case-id-9999/threat-analysis", headers=headers)
    assert res.status_code == 404
    assert res.json()["error"]["code"] == "NOT_FOUND"
