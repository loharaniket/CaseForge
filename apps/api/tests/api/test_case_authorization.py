from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.case import Case, CaseStatus
from src.models.user import User, UserRole
from src.services.auth.case_access import CaseAccessService
from src.services.storage import LocalEvidenceStorage

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def auth_users(db_session: Session) -> dict[str, tuple[User, str]]:
    """Creates User A (analyst), User B (analyst), and Admin User."""
    user_a = User(
        email="analyst.a@threattrace.io",
        hashed_password=hash_password("PassA123!"),
        full_name="Analyst Alice",
        role=UserRole.ANALYST,
        is_active=True,
    )
    user_b = User(
        email="analyst.b@threattrace.io",
        hashed_password=hash_password("PassB123!"),
        full_name="Analyst Bob",
        role=UserRole.ANALYST,
        is_active=True,
    )
    admin = User(
        email="soc.admin@threattrace.io",
        hashed_password=hash_password("AdminPass123!"),
        full_name="SOC Director",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add_all([user_a, user_b, admin])
    db_session.commit()

    return {
        "user_a": (user_a, "PassA123!"),
        "user_b": (user_b, "PassB123!"),
        "admin": (admin, "AdminPass123!"),
    }


def get_token(client: TestClient, email: str, password: str) -> str:
    """Helper to authenticate and retrieve JWT access token."""
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    return login_res.json()["access_token"]


def test_case_access_service_unit_rules(db_session: Session, tmp_path: Path):
    """Unit test: CaseAccessService enforces ownership rules and admin overrides."""
    user_a = User(
        email="unit.a@threattrace.io",
        hashed_password=hash_password("Pass123!"),
        full_name="Unit A",
        role=UserRole.ANALYST,
        is_active=True,
    )
    user_b = User(
        email="unit.b@threattrace.io",
        hashed_password=hash_password("Pass123!"),
        full_name="Unit B",
        role=UserRole.ANALYST,
        is_active=True,
    )
    admin = User(
        email="unit.admin@threattrace.io",
        hashed_password=hash_password("Pass123!"),
        full_name="Unit Admin",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add_all([user_a, user_b, admin])
    db_session.commit()

    storage = LocalEvidenceStorage(base_dir=str(tmp_path / "evidence"))
    eml_bytes = (FIXTURES_DIR / "phishing_email.eml").read_bytes()

    storage_key_a, sha_a = storage.save(eml_bytes, "case_a.eml")
    case_a = Case(
        user_id=user_a.id,
        file_name="case_a.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha_a,
        storage_key=storage_key_a,
        status=CaseStatus.UPLOADED,
    )

    storage_key_b, sha_b = storage.save(eml_bytes, "case_b.eml")
    case_b = Case(
        user_id=user_b.id,
        file_name="case_b.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha_b,
        storage_key=storage_key_b,
        status=CaseStatus.UPLOADED,
    )

    db_session.add_all([case_a, case_b])
    db_session.commit()

    service = CaseAccessService()

    # 1. User A can view own case A
    res_a = service.assert_can_view_case(case_a.id, user_a, db_session)
    assert res_a.id == case_a.id

    # 2. User A CANNOT view case B (raises NotFoundError / 404 to prevent ID enumeration)
    with pytest.raises(Exception) as exc_b:
        service.assert_can_view_case(case_b.id, user_a, db_session)
    assert getattr(exc_b.value, "status_code", 404) == 404

    # 3. User B can view own case B
    res_b = service.assert_can_view_case(case_b.id, user_b, db_session)
    assert res_b.id == case_b.id

    # 4. User B CANNOT view case A
    with pytest.raises(Exception) as exc_a:
        service.assert_can_view_case(case_a.id, user_b, db_session)
    assert getattr(exc_a.value, "status_code", 404) == 404

    # 5. Admin CAN view both Case A and Case B
    admin_res_a = service.assert_can_view_case(case_a.id, admin, db_session)
    admin_res_b = service.assert_can_view_case(case_b.id, admin, db_session)
    assert admin_res_a.id == case_a.id
    assert admin_res_b.id == case_b.id


def test_idor_protection_across_all_case_endpoints(
    client: TestClient,
    auth_users: dict[str, tuple[User, str]],
):
    """API Integration Test: Verifies User A cannot access User B's case across all 13 endpoints.

    End-to-End audit covers:
    - parse
    - parsed
    - threat-analysis (GET & POST)
    - header-forensics (GET & POST)
    - iocs (GET & POST)
    - threat-intel (GET & POST)
    - geo-infrastructure (GET & POST)
    - risk-assessment (GET & POST)
    - timeline
    - report/pdf
    - report/data
    - evidence
    - evidence/verify
    """
    user_a, pass_a = auth_users["user_a"]
    user_b, pass_b = auth_users["user_b"]
    admin_user, pass_admin = auth_users["admin"]

    token_a = get_token(client, user_a.email, pass_a)
    token_b = get_token(client, user_b.email, pass_b)
    token_admin = get_token(client, admin_user.email, pass_admin)

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    eml_bytes = (FIXTURES_DIR / "phishing_email.eml").read_bytes()

    # Upload Case A (owned by User A)
    upload_res_a = client.post(
        "/api/email/upload",
        files={"file": ("phishing_a.eml", eml_bytes, "message/rfc822")},
        headers=headers_a,
    )
    assert upload_res_a.status_code == 201
    case_a_id = upload_res_a.json()["case_id"]

    # Upload Case B (owned by User B)
    upload_res_b = client.post(
        "/api/email/upload",
        files={"file": ("phishing_b.eml", eml_bytes, "message/rfc822")},
        headers=headers_b,
    )
    assert upload_res_b.status_code == 201
    case_b_id = upload_res_b.json()["case_id"]

    # 1. User A successfully accesses own Case A
    res_a_parse = client.post(f"/api/email/{case_a_id}/parse", headers=headers_a)
    assert res_a_parse.status_code == 200

    res_a_parsed = client.get(f"/api/email/{case_a_id}/parsed", headers=headers_a)
    assert res_a_parsed.status_code == 200

    res_a_threat = client.get(f"/api/email/{case_a_id}/threat-analysis", headers=headers_a)
    assert res_a_threat.status_code == 200

    res_a_forensics = client.get(f"/api/email/{case_a_id}/header-forensics", headers=headers_a)
    assert res_a_forensics.status_code == 200

    res_a_iocs = client.get(f"/api/email/{case_a_id}/iocs", headers=headers_a)
    assert res_a_iocs.status_code == 200

    res_a_intel = client.get(f"/api/email/{case_a_id}/threat-intel", headers=headers_a)
    assert res_a_intel.status_code == 200

    res_a_geo = client.get(f"/api/email/{case_a_id}/geo-infrastructure", headers=headers_a)
    assert res_a_geo.status_code == 200

    res_a_risk = client.get(f"/api/email/{case_a_id}/risk-assessment", headers=headers_a)
    assert res_a_risk.status_code == 200

    res_a_timeline = client.get(f"/api/email/{case_a_id}/timeline", headers=headers_a)
    assert res_a_timeline.status_code == 200

    res_a_pdf = client.get(f"/api/email/{case_a_id}/report/pdf", headers=headers_a)
    assert res_a_pdf.status_code == 200

    res_a_report_data = client.get(f"/api/email/{case_a_id}/report/data", headers=headers_a)
    assert res_a_report_data.status_code == 200

    res_a_evidence = client.get(f"/api/email/{case_a_id}/evidence", headers=headers_a)
    assert res_a_evidence.status_code == 200

    res_a_verify = client.post(f"/api/email/{case_a_id}/evidence/verify", headers=headers_a)
    assert res_a_verify.status_code == 200

    # 2. User A attempts to access User B's Case B -> MUST BE BLOCKED (404 Not Found)
    # (Consistent 404 ensures zero leakage of Case B existence)
    endpoints_to_test = [
        ("POST", f"/api/email/{case_b_id}/parse"),
        ("GET", f"/api/email/{case_b_id}/parsed"),
        ("POST", f"/api/email/{case_b_id}/threat-analysis"),
        ("GET", f"/api/email/{case_b_id}/threat-analysis"),
        ("POST", f"/api/email/{case_b_id}/header-forensics"),
        ("GET", f"/api/email/{case_b_id}/header-forensics"),
        ("POST", f"/api/email/{case_b_id}/iocs"),
        ("GET", f"/api/email/{case_b_id}/iocs"),
        ("POST", f"/api/email/{case_b_id}/threat-intel"),
        ("GET", f"/api/email/{case_b_id}/threat-intel"),
        ("POST", f"/api/email/{case_b_id}/geo-infrastructure"),
        ("GET", f"/api/email/{case_b_id}/geo-infrastructure"),
        ("POST", f"/api/email/{case_b_id}/risk-assessment"),
        ("GET", f"/api/email/{case_b_id}/risk-assessment"),
        ("GET", f"/api/email/{case_b_id}/timeline"),
        ("GET", f"/api/email/{case_b_id}/report/pdf"),
        ("GET", f"/api/email/{case_b_id}/report/data"),
        ("GET", f"/api/email/{case_b_id}/evidence"),
        ("POST", f"/api/email/{case_b_id}/evidence/verify"),
    ]

    for method, path in endpoints_to_test:
        if method == "GET":
            response = client.get(path, headers=headers_a)
        else:
            response = client.post(path, headers=headers_a)

        assert response.status_code in (403, 404), (
            f"Expected 403 or 404 on {method} {path} for unauthorized user, got {response.status_code}"
        )
        assert response.status_code == 404

    # 3. User B can access Case B
    res_b_parsed = client.get(f"/api/email/{case_b_id}/parsed", headers=headers_b)
    assert res_b_parsed.status_code == 200

    # 4. User B CANNOT access Case A
    res_b_on_a = client.get(f"/api/email/{case_a_id}/parsed", headers=headers_b)
    assert res_b_on_a.status_code == 404

    # 5. Administrator CAN access both Case A and Case B
    admin_on_a = client.get(f"/api/email/{case_a_id}/parsed", headers=headers_admin)
    assert admin_on_a.status_code == 200

    admin_on_b = client.get(f"/api/email/{case_b_id}/parsed", headers=headers_admin)
    assert admin_on_b.status_code == 200
