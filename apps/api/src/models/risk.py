import uuid
from typing import Any

from sqlalchemy import JSON, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class RiskAssessment(Base):
    """Deterministic threat risk calculation and severity scoring entity."""

    __tablename__ = "risk_assessments"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cases.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    total_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    breakdown: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    weights_applied: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)
    missing_components: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="risk_assessment")
