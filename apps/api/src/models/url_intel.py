import uuid
from datetime import datetime
from sqlalchemy import Column, String, Float, Boolean, DateTime, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from src.db.base import Base

class URLIntelligenceRecord(Base):
    __tablename__ = "url_intelligence_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True, default=lambda: str(uuid.uuid4()))
    case_id: Mapped[str] = mapped_column(String(36), ForeignKey("cases.id"), index=True)
    raw_url: Mapped[str] = mapped_column(String(2048), index=True)
    
    # Normalization
    scheme: Mapped[str | None] = mapped_column(String(16), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    registrable_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    path: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    query: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    fragment: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    port: Mapped[int | None] = mapped_column(nullable=True)
    
    # Flags
    is_raw_ip: Mapped[bool] = mapped_column(Boolean, default=False)
    is_shortener: Mapped[bool] = mapped_column(Boolean, default=False)
    has_excessive_subdomains: Mapped[bool] = mapped_column(Boolean, default=False)
    has_suspicious_path: Mapped[bool] = mapped_column(Boolean, default=False)
    has_credential_path: Mapped[bool] = mapped_column(Boolean, default=False)
    is_punycode: Mapped[bool] = mapped_column(Boolean, default=False)
    has_homoglyphs: Mapped[bool] = mapped_column(Boolean, default=False)
    is_lookalike: Mapped[bool] = mapped_column(Boolean, default=False)
    has_suspicious_query: Mapped[bool] = mapped_column(Boolean, default=False)
    has_mismatch_text: Mapped[bool] = mapped_column(Boolean, default=False)

    # Explanation and Analysis
    lookalike_target: Mapped[str | None] = mapped_column(String(255), nullable=True)
    explanation: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    
    # Intelligence
    reputation: Mapped[str | None] = mapped_column(String(64), nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    provider_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    
    redirect_chain: Mapped[list[dict] | None] = mapped_column(JSON, nullable=True)
    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=datetime.utcnow)

    case = relationship("Case", back_populates="url_intelligence")
