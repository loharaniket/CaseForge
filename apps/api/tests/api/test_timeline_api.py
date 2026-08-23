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
        email="timeline.api.analyst@threattrace.io",
        hashed_password=hash_password("TimelineApiPass123!"),
        full_name="Timeline API Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "timeline.api.analyst@threattrace.io", "password": "TimelineApiPass123!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_get_case_timeline_api(client: TestClient, db_session: Session):
    """Test GET /api/email/{case_id}/timeline returns chronological events."""
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

    timeline_res = client.get(f"/api/email/{case_id}/timeline", headers=headers)
    assert timeline_res.status_code == 200
    data = timeline_res.json()

    assert data["case_id"] == case_id
    assert data["total_events"] > 0
    assert "events" in data
    assert isinstance(data["events"], list)

    events = data["events"]
    # Check that events have valid schema properties
    for event in events:
        assert "event_id" in event
        assert "event_type" in event
        assert "title" in event
        assert "description" in event
        assert "source" in event
        assert "timestamp_quality" in event


def test_timeline_api_unauthenticated_rejected(client: TestClient):
    """Test unauthenticated request to /timeline returns 401."""
    res = client.get("/api/email/some-case-id/timeline")
    assert res.status_code == 401


def test_timeline_api_nonexistent_case_returns_404(client: TestClient, db_session: Session):
    """Test /timeline on non-existent case returns 404."""
    headers = _get_auth_headers(client, db_session)
    res = client.get("/api/email/00000000-0000-0000-0000-000000000000/timeline", headers=headers)
    assert res.status_code == 404
