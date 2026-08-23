from dataclasses import asdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.models.case import Case
from src.models.email import ParsedEmail
from src.services.parser.eml_parser import default_eml_parser
from src.services.parser.interface import EmailParser
from src.services.storage import EvidenceStorage, get_evidence_storage


class ParserService:
    """Orchestrates forensic parsing between storage, EML parser, and database."""

    def __init__(
        self,
        parser: EmailParser | None = None,
        storage: EvidenceStorage | None = None,
    ) -> None:
        self.parser = parser or default_eml_parser
        self.storage = storage or get_evidence_storage()

    def parse_case(self, case_id: str, db: Session) -> ParsedEmail:
        """Loads evidence for case_id from storage, runs deterministic parsing, and stores record."""
        # 1. Retrieve case
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        # 2. Check if already parsed
        existing_parsed = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()

        if existing_parsed:
            return existing_parsed

        # 3. Retrieve raw evidence bytes from storage
        raw_bytes = self.storage.get(case.storage_key)
        if not raw_bytes:
            raise AppException(
                message=f"Evidence file for case '{case_id}' is unavailable in storage.",
                code="EVIDENCE_NOT_FOUND",
                status_code=404,
            )

        # 4. Deterministic forensic parsing
        data = self.parser.parse(raw_bytes)

        # 5. Format attachments metadata safely as JSON serializable list
        attachments_meta = [asdict(att) for att in data.attachments]

        # 6. Save ParsedEmail record
        parsed_record = ParsedEmail(
            case_id=case.id,
            sender=data.sender,
            from_name=data.from_name,
            from_address=data.from_address,
            recipients=data.recipients,
            cc=data.cc,
            bcc=data.bcc,
            reply_to=data.reply_to,
            subject=data.subject,
            date_raw=data.date_raw,
            date_parsed=data.date_parsed,
            message_id=data.message_id,
            body_plain=data.body_plain,
            body_html=data.body_html,
            extracted_urls=data.extracted_urls,
            attachments_metadata=attachments_meta,
            raw_headers=data.raw_headers,
        )

        db.add(parsed_record)
        case.status = "parsed"
        db.commit()
        db.refresh(parsed_record)

        return parsed_record

    def get_parsed_case(self, case_id: str, db: Session) -> ParsedEmail:
        """Retrieves parsed email record or parses it on-demand if not already parsed."""
        existing = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()

        if existing:
            return existing

        return self.parse_case(case_id, db)


# Default singleton instance
default_parser_service = ParserService()


def get_parser_service() -> ParserService:
    """Dependency injector for parser service."""
    return default_parser_service
