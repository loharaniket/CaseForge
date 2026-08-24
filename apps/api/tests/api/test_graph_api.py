from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.user import User, UserRole

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def graph_test_users(db_session: Session) -> dict[str, tuple[User, str]]:
    user_a = User(
        email="analyst.graph.a@threattrace.io",
        hashed_password=hash_password("PassA123!"),
        full_name="Analyst A",
        role=UserRole.ANALYST,
        is_active=True,
    )
    user_b = User(
        email="analyst.graph.b@threattrace.io",
        hashed_password=hash_password("PassB123!"),
        full_name="Analyst B",
        role=UserRole.ANALYST,
        is_active=True,
    )
    admin = User(
        email="admin.graph@threattrace.io",
        hashed_password=hash_password("AdminPass123!"),
        full_name="Admin User",
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
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    return login_res.json()["access_token"]


def test_get_case_graph_api_success(
    client: TestClient,
    graph_test_users: dict[str, tuple[User, str]],
):
    """Test: Authenticated user retrieves threat graph with 200 OK and populated nodes/edges."""
    user_a, pass_a = graph_test_users["user_a"]
    token = get_token(client, user_a.email, pass_a)
    headers = {"Authorization": f"Bearer {token}"}

    eml_bytes = (FIXTURES_DIR / "phishing_email.eml").read_bytes()
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("phishing.eml", eml_bytes, "message/rfc822")},
        headers=headers,
    )
    assert upload_res.status_code == 201
    case_id = upload_res.json()["case_id"]

    # Request Graph
    graph_res = client.get(f"/api/email/{case_id}/graph", headers=headers)
    assert graph_res.status_code == 200

    data = graph_res.json()
    assert data["case_id"] == case_id
    assert data["status"] in ("available", "unavailable")
    assert data["total_nodes"] > 0
    assert "node_counts" in data
    assert "relationship_counts" in data
    assert len(data["nodes"]) == data["total_nodes"]


def test_graph_api_unauthenticated_rejected(client: TestClient):
    """Test: Unauthenticated requests to graph endpoint receive 401 Unauthorized."""
    response = client.get("/api/email/00000000-0000-0000-0000-000000000000/graph")
    assert response.status_code == 401


def test_graph_api_case_authorization_analyst_blocked(
    client: TestClient,
    graph_test_users: dict[str, tuple[User, str]],
):
    """Test: User A cannot view User B's case graph (404), while Admin has global visibility."""
    user_a, pass_a = graph_test_users["user_a"]
    user_b, pass_b = graph_test_users["user_b"]
    admin, pass_admin = graph_test_users["admin"]

    token_a = get_token(client, user_a.email, pass_a)
    token_b = get_token(client, user_b.email, pass_b)
    token_admin = get_token(client, admin.email, pass_admin)

    headers_a = {"Authorization": f"Bearer {token_a}"}
    headers_b = {"Authorization": f"Bearer {token_b}"}
    headers_admin = {"Authorization": f"Bearer {token_admin}"}

    eml_bytes = (FIXTURES_DIR / "phishing_email.eml").read_bytes()

    # Upload Case B owned by User B
    upload_res = client.post(
        "/api/email/upload",
        files={"file": ("case_b.eml", eml_bytes, "message/rfc822")},
        headers=headers_b,
    )
    assert upload_res.status_code == 201
    case_b_id = upload_res.json()["case_id"]

    # 1. User A attempts to access User B's graph -> 404 (IDOR defense)
    res_a = client.get(f"/api/email/{case_b_id}/graph", headers=headers_a)
    assert res_a.status_code == 404

    # 2. User B can access own graph -> 200
    res_b = client.get(f"/api/email/{case_b_id}/graph", headers=headers_b)
    assert res_b.status_code == 200

    # 3. Admin can access User B's graph -> 200
    res_admin = client.get(f"/api/email/{case_b_id}/graph", headers=headers_admin)
    assert res_admin.status_code == 200
