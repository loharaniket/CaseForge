import io
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.user import User, UserRole

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


def _get_auth_headers(client: TestClient, db: Session) -> dict[str, str]:
    """Helper creating a test analyst user and returning Bearer auth header."""
    user = db.query(User).filter_by(email="evidence_api_analyst@threattrace.io").first()
    if not user:
        user = User(
            email="evidence_api_analyst@threattrace.io",
            hashed_password=hash_password("Password123!"),
            full_name="Evidence API Analyst",
            role=UserRole.ANALYST,
            is_active=True,
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "evidence_api_analyst@threattrace.io", "password": "Password123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_upload_case_auto_records_evidence_and_verifies_api(
    client: TestClient, db_session: Session
):
    """Test uploading an email registers ORIGINAL_EMAIL evidence record and enables verification."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "credential_phishing.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("cred_phish.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    assert upload_res.status_code == 201
    case_id = upload_res.json()["case_id"]
    expected_sha256 = upload_res.json()["sha256"]

    # 1. Test GET /api/email/{case_id}/evidence
    ev_res = client.get(f"/api/email/{case_id}/evidence", headers=headers)
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert ev_data["case_id"] == case_id
    assert ev_data["total_evidence_records"] >= 1
    orig_record = next(r for r in ev_data["records"] if r["evidence_type"] == "ORIGINAL_EMAIL")
    assert orig_record["sha256_hash"] == expected_sha256
    assert orig_record["file_name"] == "cred_phish.eml"

    # 2. Test POST /api/email/{case_id}/evidence/verify
    verify_res = client.post(f"/api/email/{case_id}/evidence/verify", headers=headers)
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["case_id"] == case_id
    assert verify_data["all_valid"] is True
    assert len(verify_data["results"]) >= 1
    assert verify_data["results"][0]["status"] == "VERIFIED"
    assert verify_data["results"][0]["is_valid"] is True


def test_download_report_records_report_evidence_hash(client: TestClient, db_session: Session):
    """Test downloading PDF report automatically persists INVESTIGATION_REPORT evidence record."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "credential_phishing.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("report_cred.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    # Download PDF report
    pdf_res = client.get(f"/api/email/{case_id}/report/pdf", headers=headers)
    assert pdf_res.status_code == 200

    # Query evidence records
    ev_res = client.get(f"/api/email/{case_id}/evidence", headers=headers)
    assert ev_res.status_code == 200
    ev_data = ev_res.json()
    assert ev_data["total_evidence_records"] == 2
    types = [r["evidence_type"] for r in ev_data["records"]]
    assert "ORIGINAL_EMAIL" in types
    assert "INVESTIGATION_REPORT" in types

    # Verify all records
    verify_res = client.post(f"/api/email/{case_id}/evidence/verify", headers=headers)
    assert verify_res.status_code == 200
    verify_data = verify_res.json()
    assert verify_data["all_valid"] is True
    assert verify_data["total_verified"] == 2


def test_evidence_api_unauthenticated_rejected(client: TestClient):
    """Test unauthenticated requests to evidence endpoints return 401."""
    res_get = client.get("/api/email/some-case-id/evidence")
    assert res_get.status_code == 401

    res_post = client.post("/api/email/some-case-id/evidence/verify")
    assert res_post.status_code == 401


def test_evidence_api_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test evidence operations for nonexistent case UUID return 404."""
    headers = _get_auth_headers(client, db_session)

    res_get = client.get(
        "/api/email/00000000-0000-0000-0000-000000000000/evidence", headers=headers
    )
    assert res_get.status_code == 404

    res_post = client.post(
        "/api/email/00000000-0000-0000-0000-000000000000/evidence/verify", headers=headers
    )
    assert res_post.status_code == 404
