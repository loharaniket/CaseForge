import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class AnalysisHistory(Base):
    """Append-only record of analysis events for an investigation case."""

    __tablename__ = "analysis_history"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    analysis_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        nullable=False,
    )
    parser_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    detector_version: Mapped[str | None] = mapped_column(String(50), nullable=True)
    intel_provider: Mapped[str | None] = mapped_column(String(100), nullable=True)
    provider_lookup_timestamp: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    result_status: Mapped[str] = mapped_column(String(50), nullable=False)

    # Relationships
    case = relationship("Case", back_populates="analysis_history")
