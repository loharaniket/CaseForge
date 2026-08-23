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
        email="report.api.analyst@threattrace.io",
        hashed_password=hash_password("ReportApiPass123!"),
        full_name="Report API Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "report.api.analyst@threattrace.io", "password": "ReportApiPass123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_download_case_pdf_report_api(client: TestClient, db_session: Session):
    """Test GET /api/email/{case_id}/report/pdf returns valid PDF binary stream."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "credential_phishing.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("cred_phish.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    # Trigger threat detection and header forensics
    client.get(f"/api/email/{case_id}/threat-analysis", headers=headers)
    client.get(f"/api/email/{case_id}/header-forensics", headers=headers)
    client.get(f"/api/email/{case_id}/risk-assessment", headers=headers)

    # 1. Test PDF endpoint
    pdf_res = client.get(f"/api/email/{case_id}/report/pdf", headers=headers)
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"] == "application/pdf"
    assert "ThreatTrace_Investigation_Report_" in pdf_res.headers["content-disposition"]
    assert pdf_res.content.startswith(b"%PDF-")
    assert len(pdf_res.content) > 1000

    # 2. Test JSON report data endpoint
    data_res = client.get(f"/api/email/{case_id}/report/data", headers=headers)
    assert data_res.status_code == 200
    report_json = data_res.json()
    assert report_json["case_id"] == case_id
    assert report_json["threat_classification"] is not None
    assert report_json["threat_score"] >= 0.0
    assert len(report_json["recommendations"]) > 0


def test_report_api_unauthenticated_rejected(client: TestClient):
    """Test unauthenticated report requests return 401."""
    res_pdf = client.get("/api/email/some-case-id/report/pdf")
    assert res_pdf.status_code == 401

    res_data = client.get("/api/email/some-case-id/report/data")
    assert res_data.status_code == 401


def test_report_api_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test report requests for nonexistent case return 404."""
    headers = _get_auth_headers(client, db_session)
    res = client.get("/api/email/00000000-0000-0000-0000-000000000000/report/pdf", headers=headers)
    assert res.status_code == 404
