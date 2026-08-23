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
        email="parser.analyst@threattrace.io",
        hashed_password=hash_password("ParserPass2026!"),
        full_name="Parser Test Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "parser.analyst@threattrace.io", "password": "ParserPass2026!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_parse_uploaded_case_success(client: TestClient, db_session: Session):
    """Test full flow: Upload .eml -> Execute parse endpoint -> Verify structured output."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "phishing_email.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("phish_test.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    assert upload_res.status_code == 201
    case_id = upload_res.json()["case_id"]

    # Trigger parse endpoint
    parse_res = client.post(f"/api/email/{case_id}/parse", headers=headers)
    assert parse_res.status_code == 200
    parsed = parse_res.json()

    assert parsed["case_id"] == case_id
    assert "IT Support Helpdesk" in (parsed["from_name"] or "")
    assert "security-alerts@suspicious-domain-phish.com" in (parsed["from_address"] or "")
    assert "harvest@attacker-c2.net" in parsed["reply_to"]
    assert len(parsed["extracted_urls"]) >= 2
    assert (
        "http://login.suspicious-domain-phish.com/auth/verify?session=99a8b7c6"
        in parsed["extracted_urls"]
    )


def test_get_parsed_case_auto_trigger(client: TestClient, db_session: Session):
    """Test GET /api/email/{case_id}/parsed automatically parses if not yet parsed."""
    headers = _get_auth_headers(client, db_session)

    eml_bytes = (FIXTURES_DIR / "attachment_email.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("with_att.eml", io.BytesIO(eml_bytes), "message/rfc822")},
        headers=headers,
    )
    case_id = upload_res.json()["case_id"]

    # Direct GET /parsed without prior POST /parse
    get_res = client.get(f"/api/email/{case_id}/parsed", headers=headers)
    assert get_res.status_code == 200
    parsed = get_res.json()

    assert parsed["case_id"] == case_id
    assert len(parsed["attachments_metadata"]) == 1
    assert parsed["attachments_metadata"][0]["filename"] == "invoice_august_2026.pdf"
    assert parsed["attachments_metadata"][0]["extension"] == ".pdf"
    assert "https://vendor-supply.com/payments" in parsed["extracted_urls"]


def test_parse_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test parsing an unknown case_id returns 404."""
    headers = _get_auth_headers(client, db_session)

    response = client.get("/api/email/nonexistent-case-id-123/parsed", headers=headers)
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "NOT_FOUND"


def test_parse_unauthenticated_returns_401(client: TestClient):
    """Test unauthenticated request to /parsed returns 401."""
    response = client.get("/api/email/any-case-id/parsed")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"
