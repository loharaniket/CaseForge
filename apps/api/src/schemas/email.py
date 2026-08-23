from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class AttachmentMetadataResponse(BaseModel):
    """Attachment forensic metadata payload (attachment payload is never executed)."""

    filename: str = Field(..., description="Sanitized attachment filename")
    extension: str = Field(..., description="Attachment file extension (e.g. .pdf, .docx)")
    file_size_bytes: int = Field(..., description="Size of attachment in bytes")
    sha256: str = Field(..., description="Cryptographic SHA-256 hash of attachment payload")
    content_type: str = Field(..., description="MIME content type of attachment")


class ParsedEmailResponse(BaseModel):
    """Structured representation of a parsed forensic email."""

    id: str = Field(..., description="Unique parsed email record ID")
    case_id: str = Field(..., description="Associated investigation Case ID")
    sender: str | None = Field(None, description="Decoded From header string")
    from_name: str | None = Field(None, description="Extracted sender display name")
    from_address: str | None = Field(None, description="Extracted sender email address")
    recipients: list[str] = Field(default_factory=list, description="Primary To recipients list")
    cc: list[str] = Field(default_factory=list, description="CC recipients list")
    bcc: list[str] = Field(default_factory=list, description="BCC recipients list")
    reply_to: list[str] = Field(default_factory=list, description="Reply-To address list")
    subject: str | None = Field(None, description="Decoded email subject")
    date_raw: str | None = Field(None, description="Original unparsed Date header string")
    date_parsed: datetime | None = Field(None, description="Normalized UTC timestamp")
    message_id: str | None = Field(None, description="Email Message-ID")
    body_plain: str | None = Field(None, description="Extracted plain-text body content")
    body_html: str | None = Field(None, description="Extracted raw HTML body content")
    extracted_urls: list[str] = Field(
        default_factory=list, description="Extracted URLs list (unfetched)"
    )
    attachments_metadata: list[AttachmentMetadataResponse] = Field(
        default_factory=list, description="Forensic metadata for all email attachments"
    )
    raw_headers: dict[str, Any] = Field(
        default_factory=dict, description="Full map of RFC headers for forensic analysis"
    )
    created_at: datetime = Field(..., description="Record creation timestamp")

    model_config = ConfigDict(
        from_attributes=True,
        json_schema_extra={
            "example": {
                "id": "e4a7d650-7bfa-4c59-8132-0ec105be2ff1",
                "case_id": "4b5b7b62-7f28-4447-b847-f4726bfcefa0",
                "sender": "Financial Accounts <billing@suspicious-bank-alert.com>",
                "from_name": "Financial Accounts",
                "from_address": "billing@suspicious-bank-alert.com",
                "recipients": ["Finance Team <victim@organization.com>"],
                "cc": [],
                "bcc": [],
                "reply_to": [],
                "subject": "URGENT: Overdue Invoice #INV-2026-8891",
                "date_raw": "Sun, 23 Aug 2026 09:30:00 +0000",
                "date_parsed": "2026-08-23T09:30:00Z",
                "message_id": "20260823093000.8891@suspicious-bank-alert.com",
                "body_plain": "Please review the invoice...",
                "body_html": None,
                "extracted_urls": ["http://portal.suspicious-bank-alert.com/remit"],
                "attachments_metadata": [],
                "raw_headers": {"from": "Financial Accounts <billing@suspicious-bank-alert.com>"},
                "created_at": "2026-08-23T09:31:00Z",
            }
        },
    )
