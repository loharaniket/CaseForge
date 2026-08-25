import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base

class IPIntelligenceRecord(Base):
    """Normalized real IP intelligence extracted for a case."""
    
    __tablename__ = "ip_intelligence_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()), index=True)
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    
    country: Mapped[str | None] = mapped_column(String(100), nullable=True)
    region: Mapped[str | None] = mapped_column(String(100), nullable=True)
    city: Mapped[str | None] = mapped_column(String(100), nullable=True)
    latitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    longitude: Mapped[float | None] = mapped_column(Float, nullable=True)
    timezone: Mapped[str | None] = mapped_column(String(50), nullable=True)
    asn: Mapped[int | None] = mapped_column(Integer, nullable=True)
    isp: Mapped[str | None] = mapped_column(String(255), nullable=True)
    organization: Mapped[str | None] = mapped_column(String(255), nullable=True)
    hosting_provider: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    proxy_vpn_indicator: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    tor_indicator: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    reputation: Mapped[str | None] = mapped_column(String(50), nullable=True)
    abuse_threat_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    
    last_updated: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    case = relationship("Case", back_populates="ip_intelligence_records")
