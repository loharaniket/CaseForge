import hashlib
from datetime import UTC
from email import policy
from email.header import decode_header
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import parseaddr, parsedate_to_datetime
from pathlib import Path
from typing import Any

from src.services.parser.interface import EmailParser
from src.services.parser.types import AttachmentMetadata, ParsedEmailData
from src.services.parser.url_extractor import extract_urls


def decode_rfc2047(header_val: str | None) -> str | None:
    """Decodes RFC 2047 encoded header words (e.g. =?UTF-8?B?...?=)."""
    if not header_val:
        return None

    try:
        decoded_chunks = decode_header(header_val)
        parts = []
        for chunk, encoding in decoded_chunks:
            if isinstance(chunk, bytes):
                encoding = encoding or "utf-8"
                try:
                    parts.append(chunk.decode(encoding, errors="replace"))
                except (LookupError, UnicodeDecodeError):
                    parts.append(chunk.decode("utf-8", errors="replace"))
            else:
                parts.append(str(chunk))
        return "".join(parts).strip()
    except Exception:
        return str(header_val).strip()


def parse_address_list(raw_header: str | None) -> list[str]:
    """Parses a comma-separated address header into cleaned address strings."""
    if not raw_header:
        return []

    addresses = []
    # Split on commas taking into account quoted names
    raw_entries = [entry.strip() for entry in str(raw_header).split(",") if entry.strip()]
    for entry in raw_entries:
        name, addr = parseaddr(entry)
        decoded_name = decode_rfc2047(name)
        if decoded_name and addr:
            addresses.append(f"{decoded_name} <{addr}>")
        elif addr:
            addresses.append(addr)
        elif decoded_name:
            addresses.append(decoded_name)
        elif entry:
            addresses.append(decode_rfc2047(entry) or entry)
    return addresses


class EMLParser(EmailParser):
    """Deterministic, resilient RFC 822/2822/5322 EML forensic email parser."""

    def parse(self, raw_content: bytes) -> ParsedEmailData:
        """Parses raw email bytes into structured forensic data.

        Handles malformed inputs and corrupt encodings gracefully without crashing.
        """
        if not raw_content:
            return ParsedEmailData()

        # Parse message using default policy
        try:
            msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw_content)
        except Exception:
            # Fallback for heavily corrupted headers
            try:
                msg: EmailMessage = BytesParser(policy=policy.compat32).parsebytes(raw_content)
            except Exception:
                return ParsedEmailData(body_plain=raw_content.decode("utf-8", errors="replace"))

        # 1. Header Extractions
        raw_from = str(msg.get("From", "") or "")
        from_display, from_addr = parseaddr(raw_from)
        decoded_from_display = decode_rfc2047(from_display)
        from_str = (
            f"{decoded_from_display} <{from_addr}>"
            if decoded_from_display and from_addr
            else (from_addr or decoded_from_display or decode_rfc2047(raw_from))
        )

        recipients = parse_address_list(msg.get("To"))
        cc_list = parse_address_list(msg.get("Cc"))
        bcc_list = parse_address_list(msg.get("Bcc"))
        reply_to_list = parse_address_list(msg.get("Reply-To"))

        raw_subject = msg.get("Subject")
        subject = decode_rfc2047(str(raw_subject)) if raw_subject is not None else None

        date_raw = str(msg.get("Date", "") or "")
        date_parsed = None
        if date_raw:
            try:
                parsed_dt = parsedate_to_datetime(date_raw)
                # Ensure UTC timezone
                if parsed_dt.tzinfo is None:
                    date_parsed = parsed_dt.replace(tzinfo=UTC)
                else:
                    date_parsed = parsed_dt.astimezone(UTC)
            except Exception:
                date_parsed = None

        message_id = str(msg.get("Message-ID", "") or "").strip("<> ") or None

        # 2. Collect All Raw Headers for Forensics
        raw_headers: dict[str, Any] = {}
        for key, val in msg.items():
            header_name = str(key)
            header_value = decode_rfc2047(str(val))
            if header_name in raw_headers:
                if isinstance(raw_headers[header_name], list):
                    raw_headers[header_name].append(header_value)
                else:
                    raw_headers[header_name] = [raw_headers[header_name], header_value]
            else:
                raw_headers[header_name] = header_value

        # 3. Body & Attachment Extractions
        plain_parts: list[str] = []
        html_parts: list[str] = []
        attachments: list[AttachmentMetadata] = []

        for part in msg.walk():
            # Skip container multipart types
            if part.is_multipart():
                continue

            content_disposition = str(part.get("Content-Disposition", "")).lower()
            filename = part.get_filename()

            is_attachment = "attachment" in content_disposition or (
                filename is not None and bool(filename.strip())
            )

            if is_attachment:
                # Safe Attachment Metadata Extraction (NEVER executed)
                raw_filename = filename or "unnamed_attachment"
                clean_filename = Path(decode_rfc2047(raw_filename) or raw_filename).name
                extension = Path(clean_filename).suffix.lower()

                try:
                    payload = part.get_payload(decode=True) or b""
                except Exception:
                    payload = b""

                sha256_hash = hashlib.sha256(payload).hexdigest()
                content_type = part.get_content_type() or "application/octet-stream"

                attachments.append(
                    AttachmentMetadata(
                        filename=clean_filename,
                        extension=extension,
                        file_size_bytes=len(payload),
                        sha256=sha256_hash,
                        content_type=content_type,
                    )
                )
            else:
                content_type = part.get_content_type()
                try:
                    payload_bytes = part.get_payload(decode=True)
                    if payload_bytes is not None:
                        charset = part.get_content_charset() or "utf-8"
                        try:
                            text_body = payload_bytes.decode(charset, errors="replace")
                        except (LookupError, UnicodeDecodeError):
                            text_body = payload_bytes.decode("utf-8", errors="replace")
                    else:
                        text_body = str(part.get_payload() or "")
                except Exception:
                    text_body = str(part.get_payload() or "")

                if content_type == "text/plain":
                    plain_parts.append(text_body)
                elif content_type == "text/html":
                    html_parts.append(text_body)

        body_plain = "\n\n".join(plain_parts).strip() if plain_parts else None
        body_html = "\n\n".join(html_parts).strip() if html_parts else None

        # 4. Safe URL Extraction (No network requests executed)
        extracted_urls = extract_urls(text_content=body_plain, html_content=body_html)

        return ParsedEmailData(
            sender=from_str or None,
            from_name=decoded_from_display or None,
            from_address=from_addr or None,
            recipients=recipients,
            cc=cc_list,
            bcc=bcc_list,
            reply_to=reply_to_list,
            subject=subject,
            date_raw=date_raw or None,
            date_parsed=date_parsed,
            message_id=message_id,
            body_plain=body_plain,
            body_html=body_html,
            extracted_urls=extracted_urls,
            attachments=attachments,
            raw_headers=raw_headers,
        )


# Default singleton instance
default_eml_parser = EMLParser()
