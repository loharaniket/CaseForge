import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.db.base import Base


class ParsedEmail(Base):
    """Structured forensic metadata and extracted email entity."""

    __tablename__ = "parsed_emails"

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
    sender: Mapped[str | None] = mapped_column(String(255), nullable=True)
    from_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    from_address: Mapped[str | None] = mapped_column(String(255), nullable=True)
    recipients: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    cc: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    bcc: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    reply_to: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    subject: Mapped[str | None] = mapped_column(Text, nullable=True)
    date_raw: Mapped[str | None] = mapped_column(String(255), nullable=True)
    date_parsed: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    message_id: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    body_plain: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_html: Mapped[str | None] = mapped_column(Text, nullable=True)
    extracted_urls: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    attachments_metadata: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON, default=list, nullable=False
    )
    raw_headers: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    # Relationships
    case = relationship("Case", back_populates="parsed_email")
