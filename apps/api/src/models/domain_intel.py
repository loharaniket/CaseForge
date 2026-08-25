from datetime import datetime
import uuid
from sqlalchemy import Column, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from src.db.base import Base

class DomainIntelligenceRecord(Base):
    __tablename__ = "domain_intelligence_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("cases.id"), index=True)
    domain: Mapped[str] = mapped_column(String(255), index=True)
    
    # Metadata
    registrar: Mapped[str | None] = mapped_column(String(255), nullable=True)
    creation_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expiration_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    
    # DNS
    nameservers: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    a_records: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    aaaa_records: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    mx_records: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    txt_records: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    
    # Security Signals
    spf_record: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    dmarc_record: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    reputation: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    
    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    case = relationship("Case", back_populates="domain_intelligence")
