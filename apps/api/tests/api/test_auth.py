from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.user import User, UserRole


def test_user_registration(client: TestClient):
    """Test public user registration endpoint persists account with analyst role."""
    payload = {
        "email": "new.analyst@threattrace.io",
        "password": "StrongPassword2026!",
        "full_name": "Junior Analyst",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "new.analyst@threattrace.io"
    assert data["full_name"] == "Junior Analyst"
    assert data["role"] == "analyst"
    assert data["is_active"] is True
    assert "id" in data
    # Ensure password hash is NEVER leaked in schema
    assert "password" not in data
    assert "hashed_password" not in data


def test_security_prevent_privilege_escalation_public_registration(client: TestClient):
    """Security Test: Attempting to register with role='admin' MUST NOT grant admin privileges.

    The registration endpoint must ignore or strip any requested role and force UserRole.ANALYST.
    """
    payload = {
        "email": "attacker@example.com",
        "full_name": "Attacker",
        "password": "StrongPassword123!",
        "role": "admin",
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()

    # Verify returned role is strictly 'analyst', NOT 'admin'
    assert data["role"] == "analyst"
    assert data["role"] != "admin"

    # Login as this attacker to verify actual JWT claims and permissions
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "attacker@example.com", "password": "StrongPassword123!"},
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # Verify /auth/me returns analyst
    me_res = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "analyst"

    # Verify attacker CANNOT access admin-only route (403 Forbidden)
    admin_probe = client.get(
        "/api/v1/auth/admin-only",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert admin_probe.status_code == 403
    assert admin_probe.json()["error"]["code"] == "FORBIDDEN"


def test_admin_provisioning_endpoint_by_admin(client: TestClient, db_session: Session):
    """Test protected /admin/users endpoint allows authenticated administrator to provision admin/analyst."""
    admin = User(
        email="root.admin@threattrace.io",
        hashed_password=hash_password("RootAdminPass123!"),
        full_name="Root Admin",
        role=UserRole.ADMIN,
        is_active=True,
    )
    db_session.add(admin)
    db_session.commit()

    admin_login = client.post(
        "/api/v1/auth/login",
        json={"email": "root.admin@threattrace.io", "password": "RootAdminPass123!"},
    )
    admin_token = admin_login.json()["access_token"]

    # Admin provisions another admin
    provision_payload = {
        "email": "deputy.admin@threattrace.io",
        "password": "DeputyPass123!",
        "full_name": "Deputy Admin",
        "role": "admin",
    }
    create_res = client.post(
        "/api/v1/auth/admin/users",
        json=provision_payload,
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert create_res.status_code == 201
    assert create_res.json()["role"] == "admin"

    # Verify deputy admin can access admin-only route
    deputy_login = client.post(
        "/api/v1/auth/login",
        json={"email": "deputy.admin@threattrace.io", "password": "DeputyPass123!"},
    )
    deputy_token = deputy_login.json()["access_token"]
    deputy_probe = client.get(
        "/api/v1/auth/admin-only",
        headers={"Authorization": f"Bearer {deputy_token}"},
    )
    assert deputy_probe.status_code == 200


def test_admin_provisioning_endpoint_blocked_for_analyst(client: TestClient, db_session: Session):
    """Test /admin/users endpoint rejects requests from regular analysts with 403."""
    analyst = User(
        email="regular.analyst@threattrace.io",
        hashed_password=hash_password("AnalystPass123!"),
        full_name="Regular Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(analyst)
    db_session.commit()

    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "regular.analyst@threattrace.io", "password": "AnalystPass123!"},
    )
    analyst_token = login_res.json()["access_token"]

    payload = {
        "email": "rogue.admin@threattrace.io",
        "password": "RoguePassword123!",
        "full_name": "Rogue Admin",
        "role": "admin",
    }
    create_res = client.post(
        "/api/v1/auth/admin/users",
        json=payload,
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert create_res.status_code == 403
    assert create_res.json()["error"]["code"] == "FORBIDDEN"


def test_duplicate_registration_fails(client: TestClient):
    """Test registering an already-registered email returns 400 Bad Request."""
    payload = {
        "email": "duplicate@threattrace.io",
        "password": "Password123!",
        "full_name": "Test Duplicate",
    }
    res1 = client.post("/api/v1/auth/register", json=payload)
    assert res1.status_code == 201

    res2 = client.post("/api/v1/auth/register", json=payload)
    assert res2.status_code == 400
    data2 = res2.json()
    assert data2["error"]["code"] == "EMAIL_ALREADY_REGISTERED"


def test_login_success(client: TestClient, db_session: Session):
    """Test login with valid credentials returns 200 and JWT access token."""
    user = User(
        email="auth.test@threattrace.io",
        hashed_password=hash_password("ValidPassword2026!"),
        full_name="SOC Officer",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    login_payload = {
        "email": "auth.test@threattrace.io",
        "password": "ValidPassword2026!",
    }
    response = client.post("/api/v1/auth/login", json=login_payload)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["expires_in"] > 0
    assert data["user"]["email"] == "auth.test@threattrace.io"
    assert data["user"]["role"] == "analyst"
    assert "hashed_password" not in data["user"]


def test_login_invalid_password(client: TestClient, db_session: Session):
    """Test login with invalid password returns 401 Unauthorized."""
    user = User(
        email="user.wrongpass@threattrace.io",
        hashed_password=hash_password("CorrectPass123!"),
        full_name="Test User",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    response = client.post(
        "/api/v1/auth/login",
        json={"email": "user.wrongpass@threattrace.io", "password": "WrongPassword!"},
    )
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "INVALID_CREDENTIALS"


def test_login_nonexistent_user(client: TestClient):
    """Test login with nonexistent email returns 401 Unauthorized."""
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "nonexistent@threattrace.io", "password": "AnyPassword!"},
    )
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "INVALID_CREDENTIALS"


def test_get_current_user_me(client: TestClient, db_session: Session):
    """Test /api/v1/auth/me returns currently authenticated user profile."""
    user = User(
        email="me.analyst@threattrace.io",
        hashed_password=hash_password("MyPassword123!"),
        full_name="Current Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    # Login to get token
    login_res = client.post(
        "/api/v1/auth/login",
        json={"email": "me.analyst@threattrace.io", "password": "MyPassword123!"},
    )
    token = login_res.json()["access_token"]

    # Call /auth/me
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "me.analyst@threattrace.io"
    assert data["full_name"] == "Current Analyst"
    assert data["role"] == "analyst"
    assert "hashed_password" not in data


def test_get_current_user_unauthorized(client: TestClient):
    """Test /api/v1/auth/me without token returns 401 Unauthorized."""
    response = client.get("/api/v1/auth/me")
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "UNAUTHORIZED"


def test_get_current_user_invalid_token(client: TestClient):
    """Test /api/v1/auth/me with bogus token returns 401 Unauthorized."""
    response = client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer invalid.jwt.token.string"},
    )
    assert response.status_code == 401
    data = response.json()
    assert data["error"]["code"] == "INVALID_TOKEN"


def test_role_authorization_admin_only(client: TestClient, db_session: Session):
    """Test admin-only endpoint allows admin user and blocks analyst with 403."""
    admin = User(
        email="admin@threattrace.io",
        hashed_password=hash_password("AdminPass123!"),
        full_name="SOC Admin",
        role=UserRole.ADMIN,
        is_active=True,
    )
    analyst = User(
        email="analyst.user@threattrace.io",
        hashed_password=hash_password("AnalystPass123!"),
        full_name="SOC Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add_all([admin, analyst])
    db_session.commit()

    # Admin token
    admin_login = client.post(
        "/api/v1/auth/login",
        json={"email": "admin@threattrace.io", "password": "AdminPass123!"},
    )
    admin_token = admin_login.json()["access_token"]

    # Analyst token
    analyst_login = client.post(
        "/api/v1/auth/login",
        json={"email": "analyst.user@threattrace.io", "password": "AnalystPass123!"},
    )
    analyst_token = analyst_login.json()["access_token"]

    # 1. Admin access succeeds (200)
    admin_res = client.get(
        "/api/v1/auth/admin-only",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_res.status_code == 200
    assert admin_res.json()["message"] == "Admin authorization granted."

    # 2. Analyst access is forbidden (403)
    analyst_res = client.get(
        "/api/v1/auth/admin-only",
        headers={"Authorization": f"Bearer {analyst_token}"},
    )
    assert analyst_res.status_code == 403
    data = analyst_res.json()
    assert data["error"]["code"] == "FORBIDDEN"
