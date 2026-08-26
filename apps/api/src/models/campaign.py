import uuid
from datetime import datetime

from sqlalchemy import Float, ForeignKey, Integer, String, JSON, DateTime, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base

class Campaign(Base):
    """Campaign grouping related investigations."""

    __tablename__ = "campaigns"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: f"CAM-{str(uuid.uuid4())[:8].upper()}",
        index=True,
    )
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Aggregated indicators stored as JSON dict: {"domains": [], "ips": [], "urls": []}
    shared_indicators: Mapped[dict] = mapped_column(JSON, default=dict)
    
    # Aggregated infra stored as JSON dict: {"asns": [], "orgs": []}
    shared_infrastructure: Mapped[dict] = mapped_column(JSON, default=dict)
    
    confidence: Mapped[float] = mapped_column(Float, default=0.0)

    # Relationship to CampaignInvestigationLink
    investigation_links: Mapped[list["CampaignInvestigationLink"]] = relationship(
        "CampaignInvestigationLink", back_populates="campaign", cascade="all, delete-orphan"
    )

class CampaignInvestigationLink(Base):
    """Association table linking Case and Campaign with metadata."""

    __tablename__ = "campaign_investigations"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
    )
    campaign_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    case_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("cases.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    correlation_score: Mapped[float] = mapped_column(Float, default=0.0)
    matched_on: Mapped[list[str]] = mapped_column(JSON, default=list) # e.g. ["domain:evil.com", "ip:1.2.3.4"]
    
    campaign = relationship("Campaign", back_populates="investigation_links")
    case = relationship("Case")
