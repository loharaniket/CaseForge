from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class AttachmentMetadata:
    """Safe forensic metadata for email attachments (payload is never executed)."""

    filename: str
    extension: str
    file_size_bytes: int
    sha256: str
    content_type: str


@dataclass
class ParsedEmailData:
    """Deterministic structured representation of a parsed email."""

    sender: str | None = None
    from_name: str | None = None
    from_address: str | None = None
    recipients: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    reply_to: list[str] = field(default_factory=list)
    subject: str | None = None
    date_raw: str | None = None
    date_parsed: datetime | None = None
    message_id: str | None = None
    body_plain: str | None = None
    body_html: str | None = None
    extracted_urls: list[str] = field(default_factory=list)
    attachments: list[AttachmentMetadata] = field(default_factory=list)
    raw_headers: dict[str, list[str] | str] = field(default_factory=dict)
