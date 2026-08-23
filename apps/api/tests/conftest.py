from collections.abc import Generator
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from src.core.config import Settings
from src.db.base import Base
from src.db.session import get_db
from src.main import create_app

# Use an in-memory SQLite database for deterministic unit & API testing
TEST_DATABASE_URL = "sqlite:///:memory:"

test_engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    """Create test tables before test session and drop them after."""
    Base.metadata.create_all(bind=test_engine)
    yield
    Base.metadata.drop_all(bind=test_engine)


@pytest.fixture
def db_session() -> Generator[Session, None, None]:
    """Provides a transactional database session for tests."""
    connection = test_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def client(db_session: Session) -> Generator[TestClient, None, None]:
    """TestClient fixture with overridden healthy get_db dependency."""
    app = create_app()

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def broken_db_client() -> Generator[TestClient, None, None]:
    """TestClient fixture simulating an unavailable / failing database connection."""
    app = create_app()

    def broken_get_db():
        mock_session = MagicMock(spec=Session)
        mock_session.execute.side_effect = Exception("Database connection refused")
        yield mock_session

    app.dependency_overrides[get_db] = broken_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def custom_settings() -> Settings:
    """Fixture providing custom valid Settings instance."""
    return Settings(
        PROJECT_NAME="ThreatTrace Custom Test",
        VERSION="1.2.3",
        ENVIRONMENT="test",
        LOG_LEVEL="DEBUG",
        DATABASE_URL="sqlite:///:memory:",
    )
