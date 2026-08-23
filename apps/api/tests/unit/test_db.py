from unittest.mock import MagicMock

from sqlalchemy import Column, Integer, String
from sqlalchemy.orm import Session

from src.db.base import Base
from src.db.session import check_db_connection


class DummyEntity(Base):
    """Test entity for ORM validation."""

    __tablename__ = "dummy_entity"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=False)


def test_check_db_connection_success(db_session: Session):
    """Verify check_db_connection returns True with an active connection."""
    assert check_db_connection(session=db_session) is True


def test_check_db_connection_failure():
    """Verify check_db_connection returns False when execution raises."""
    mock_session = MagicMock(spec=Session)
    mock_session.execute.side_effect = Exception("DB Connection Down")
    assert check_db_connection(session=mock_session) is False


def test_base_model_timestamps(db_session: Session):
    """Verify Base model timestamp defaults and persistence."""
    Base.metadata.create_all(bind=db_session.bind)

    entity = DummyEntity(name="Security Incident #1")
    db_session.add(entity)
    db_session.commit()
    db_session.refresh(entity)

    assert entity.id is not None
    assert entity.name == "Security Incident #1"
    assert entity.created_at is not None
    assert entity.updated_at is not None
