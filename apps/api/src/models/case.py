import uuid
from enum import StrEnum

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class CaseStatus(StrEnum):
    """Investigation case processing lifecycle states."""

    UPLOADED = "UPLOADED"
    PARSING = "PARSING"
    PARSED = "PARSED"
    FAILED = "FAILED"

class AnalysisStatus(StrEnum):
    """Overall background analysis status."""

    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"


class Case(Base):
    """Investigation case and uploaded evidence record entity."""

    __tablename__ = "cases"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        index=True,
    )
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    sha256_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    storage_key: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default=CaseStatus.UPLOADED, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    analysis_status: Mapped[str] = mapped_column(String(50), default=AnalysisStatus.QUEUED, nullable=False)
    analysis_step: Mapped[str] = mapped_column(String(100), default="Pending", nullable=False)

    # Relationships
    analyst = relationship("User", backref="cases")
    parsed_email = relationship(
        "ParsedEmail", back_populates="case", uselist=False, cascade="all, delete-orphan"
    )
    threat_assessment = relationship(
        "ThreatAssessment", back_populates="case", uselist=False, cascade="all, delete-orphan"
    )
    risk_assessment = relationship(
        "RiskAssessment", back_populates="case", uselist=False, cascade="all, delete-orphan"
    )
    header_forensics = relationship(
        "HeaderForensics", back_populates="case", uselist=False, cascade="all, delete-orphan"
    )
    iocs = relationship("CaseIOC", back_populates="case", cascade="all, delete-orphan")
    domain_intelligence: Mapped[list["DomainIntelligenceRecord"]] = relationship(
        "DomainIntelligenceRecord", back_populates="case", cascade="all, delete-orphan"
    )
    url_intelligence: Mapped[list["URLIntelligenceRecord"]] = relationship(
        "URLIntelligenceRecord", back_populates="case", cascade="all, delete-orphan"
    )
    ip_intelligence_records = relationship(
        "IPIntelligenceRecord", back_populates="case", cascade="all, delete-orphan"
    )
    evidence_records = relationship(
        "EvidenceRecord", back_populates="case", cascade="all, delete-orphan"
    )
    analysis_history = relationship(
        "AnalysisHistory", back_populates="case", cascade="all, delete-orphan"
    )
    campaign_links = relationship(
        "CampaignInvestigationLink", back_populates="case", cascade="all, delete-orphan"
    )
    conclusion = relationship(
        "InvestigationConclusion", back_populates="case", uselist=False, cascade="all, delete-orphan"
    )
