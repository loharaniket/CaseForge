from dataclasses import asdict

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.core.logging import logger
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.services.parser.eml_parser import default_eml_parser
from src.services.parser.interface import EmailParser
from src.services.storage import EvidenceStorage, get_evidence_storage


class ParserService:
    """Orchestrates forensic parsing between storage, EML parser, and database with transaction safety."""

    def __init__(
        self,
        parser: EmailParser | None = None,
        storage: EvidenceStorage | None = None,
    ) -> None:
        self.parser = parser or default_eml_parser
        self.storage = storage or get_evidence_storage()

    def parse_case(self, case_id: str, db: Session) -> ParsedEmail:
        """Loads evidence for case_id from storage, runs deterministic parsing, and stores record atomically."""
        # 1. Retrieve case
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        # 2. Check if already parsed (idempotent duplicate processing)
        existing_parsed = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()

        if existing_parsed:
            if case.status != CaseStatus.PARSED:
                case.status = CaseStatus.PARSED
                db.commit()
            return existing_parsed

        # 3. Retrieve raw evidence bytes from storage
        raw_bytes = self.storage.get(case.storage_key)
        if not raw_bytes:
            case.status = CaseStatus.FAILED
            case.error_message = f"Evidence file '{case.storage_key}' is unavailable in storage."
            db.commit()
            raise AppException(
                message=f"Evidence file for case '{case_id}' is unavailable in storage.",
                code="EVIDENCE_NOT_FOUND",
                status_code=404,
            )

        # 4. Atomic Transaction: Transition to PARSING -> Parse -> Persist -> PARSED
        case.status = CaseStatus.PARSING
        db.commit()

        try:
            # Deterministic forensic parsing
            data = self.parser.parse(raw_bytes)

            # Format attachments metadata safely as JSON serializable list
            attachments_meta = [asdict(att) for att in data.attachments]

            # Create ParsedEmail entity
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
            case.status = CaseStatus.PARSED
            case.error_message = None
            db.commit()
            db.refresh(parsed_record)

            return parsed_record

        except Exception as exc:
            # Rollback any uncommitted partial parsed email record
            db.rollback()
            logger.error(f"Forensic parsing failed for case '{case_id}': {exc}")

            # Persist failure state cleanly
            case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
            if case:
                case.status = CaseStatus.FAILED
                case.error_message = str(exc)
                db.commit()

            raise AppException(
                message=f"Forensic parsing failed for case '{case_id}': {exc}",
                code="PARSING_FAILED",
                status_code=500,
                details={"case_id": case_id, "error": str(exc)},
            ) from exc

    def get_parsed_case(self, case_id: str, db: Session) -> ParsedEmail:
        """Retrieves parsed email record or parses it on-demand if not already parsed."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        if case.status == CaseStatus.FAILED:
            raise AppException(
                message=f"Investigation case '{case_id}' parsing previously failed: {case.error_message}",
                code="CASE_PARSING_FAILED",
                status_code=400,
                details={"case_id": case_id, "error_message": case.error_message},
            )

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
