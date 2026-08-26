import uuid

from sqlalchemy import JSON, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class InvestigationConclusion(Base):
    """Explainable Investigation Conclusion Engine output."""

    __tablename__ = "investigation_conclusions"

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
    classification: Mapped[str] = mapped_column(String(50), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    primary_findings: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    supporting_evidence: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    probable_infrastructure: Mapped[str] = mapped_column(String(255), nullable=False)
    attribution_assessment: Mapped[str] = mapped_column(String(255), nullable=False)
    limitations: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="conclusion")
