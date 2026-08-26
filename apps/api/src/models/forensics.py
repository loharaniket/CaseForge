import uuid
from typing import Any

from sqlalchemy import JSON, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class HeaderForensics(Base):
    """Forensic email transmission analysis and spoofing assessment entity."""

    __tablename__ = "header_forensics"

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
    relay_hops: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list, nullable=False)
    origin_ip_candidates: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    probable_origin_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    origin_analysis: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    spf_status: Mapped[str] = mapped_column(String(20), nullable=False)
    dkim_status: Mapped[str] = mapped_column(String(20), nullable=False)
    dmarc_status: Mapped[str] = mapped_column(String(20), nullable=False)
    authentication_details: Mapped[dict[str, Any]] = mapped_column(
        JSON, default=dict, nullable=False
    )
    spoofing_indicators: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    anomalies: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    forensics_risk_score: Mapped[float] = mapped_column(Float, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="header_forensics")
