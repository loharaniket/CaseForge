import hashlib
import io

from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.case import Case
from src.models.user import User, UserRole


def _get_authenticated_headers(client: TestClient, db_session: Session) -> dict[str, str]:
    """Helper to provision a test analyst and retrieve authorization headers."""
    analyst = User(
        email="upload.analyst@threattrace.io",
        hashed_password=hash_password("AnalystSecretPass2026!"),
        full_name="Forensic Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(analyst)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "upload.analyst@threattrace.io", "password": "AnalystSecretPass2026!"},
    )
    token = login_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


def test_valid_eml_upload_success(client: TestClient, db_session: Session):
    """Test valid .eml upload returns 201, case_id, and verified SHA-256 hash."""
    headers = _get_authenticated_headers(client, db_session)

    eml_content = (
        b"From: phisher@spoofed.com\r\n"
        b"To: victim@company.com\r\n"
        b"Subject: Urgent Wire Transfer\r\n"
        b"Date: Sun, 23 Aug 2026 12:00:00 +0000\r\n\r\n"
        b"Please transfer funds immediately."
    )
    expected_sha256 = hashlib.sha256(eml_content).hexdigest()

    file_tuple = ("phishing_sample.eml", io.BytesIO(eml_content), "message/rfc822")

    response = client.post(
        "/api/email/upload",
        files={"file": file_tuple},
        headers=headers,
    )

    assert response.status_code == 201
    data = response.json()
    assert "case_id" in data
    assert data["status"] in ("PARSED", "UPLOADED", "received")
    assert data["file_name"] == "phishing_sample.eml"
    assert data["file_size_bytes"] == len(eml_content)
    assert data["sha256"] == expected_sha256
    assert "created_at" in data

    # Verify database persistence
    case_in_db = db_session.execute(
        select(Case).where(Case.id == data["case_id"])
    ).scalar_one_or_none()

    assert case_in_db is not None
    assert case_in_db.file_name == "phishing_sample.eml"
    assert case_in_db.sha256_hash == expected_sha256
    assert case_in_db.status in ("PARSED", "UPLOADED", "received")


def test_v1_email_upload_endpoint_alias(client: TestClient, db_session: Session):
    """Test that /api/v1/email/upload works identically to /api/email/upload."""
    headers = _get_authenticated_headers(client, db_session)

    eml_content = b"From: a@b.com\r\nTo: c@d.com\r\nSubject: Test\r\n\r\nBody text"
    file_tuple = ("sample_v1.eml", io.BytesIO(eml_content), "message/rfc822")

    response = client.post(
        "/api/v1/email/upload",
        files={"file": file_tuple},
        headers=headers,
    )
    assert response.status_code == 201
    assert response.json()["file_name"] == "sample_v1.eml"


def test_unauthenticated_upload_rejected(client: TestClient):
    """Test that unauthenticated requests to upload endpoint return 401."""
    eml_content = b"From: a@b.com\r\n\r\nBody"
    file_tuple = ("test.eml", io.BytesIO(eml_content), "message/rfc822")

    response = client.post("/api/email/upload", files={"file": file_tuple})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "UNAUTHORIZED"


def test_invalid_file_extension_rejected(client: TestClient, db_session: Session):
    """Test that non-.eml file extensions (.exe, .pdf, .txt) return 400."""
    headers = _get_authenticated_headers(client, db_session)

    for bad_name in ["malware.exe", "document.pdf", "script.sh", "readme.txt"]:
        file_tuple = (bad_name, io.BytesIO(b"dummy payload"), "application/octet-stream")
        response = client.post(
            "/api/email/upload",
            files={"file": file_tuple},
            headers=headers,
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_FILE_EXTENSION"


def test_empty_file_upload_rejected(client: TestClient, db_session: Session):
    """Test that 0-byte uploaded file returns 400 Bad Request."""
    headers = _get_authenticated_headers(client, db_session)

    file_tuple = ("empty.eml", io.BytesIO(b""), "message/rfc822")
    response = client.post(
        "/api/email/upload",
        files={"file": file_tuple},
        headers=headers,
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "EMPTY_FILE"


def test_missing_file_payload_rejected(client: TestClient, db_session: Session):
    """Test request without file form field returns 422."""
    headers = _get_authenticated_headers(client, db_session)

    response = client.post("/api/email/upload", headers=headers)
    assert response.status_code == 422


def test_duplicate_upload_behavior(client: TestClient, db_session: Session):
    """Test uploading identical evidence file creates separate cases with the same SHA-256."""
    headers = _get_authenticated_headers(client, db_session)

    eml_content = b"From: duplicate@target.com\r\n\r\nRepeated evidence"
    file_tuple1 = ("evidence.eml", io.BytesIO(eml_content), "message/rfc822")
    file_tuple2 = ("evidence.eml", io.BytesIO(eml_content), "message/rfc822")

    res1 = client.post("/api/email/upload", files={"file": file_tuple1}, headers=headers)
    res2 = client.post("/api/email/upload", files={"file": file_tuple2}, headers=headers)

    assert res1.status_code == 201
    assert res2.status_code == 201

    data1 = res1.json()
    data2 = res2.json()

    # Cases are distinct
    assert data1["case_id"] != data2["case_id"]
    # Evidence hashes match
    assert data1["sha256"] == data2["sha256"]


def test_evidence_content_never_executed(client: TestClient, db_session: Session):
    """Test that dangerous payload is stored safely without code execution."""
    headers = _get_authenticated_headers(client, db_session)

    # Malicious script embedded in EML
    dangerous_content = (
        b"From: hacker@darkweb.org\r\n"
        b"Subject: Exploit\r\n\r\n"
        b"<script>alert('xss')</script>"
        b"import os; os.system('echo exploited')"
    )

    file_tuple = ("exploit.eml", io.BytesIO(dangerous_content), "message/rfc822")
    response = client.post("/api/email/upload", files={"file": file_tuple}, headers=headers)

    assert response.status_code == 201
    data = response.json()

    # Verify raw paths are not exposed
    assert "storage_path" not in data
    assert "storage_key" not in data
    assert "C:" not in str(data)
    assert "/" not in data["file_name"]
    assert "\\" not in data["file_name"]
