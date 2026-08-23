from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.ioc import CaseIOC
from src.services.ioc.extractor import IOCExtractor, default_ioc_extractor
from src.services.parser_service import ParserService, get_parser_service


class IOCService:
    """Service layer managing extraction and persistence of Indicators of Compromise (IOCs)."""

    def __init__(
        self,
        extractor: IOCExtractor | None = None,
        parser_service: ParserService | None = None,
    ) -> None:
        self.extractor = extractor or default_ioc_extractor
        self.parser_service = parser_service or get_parser_service()

    def extract_case_iocs(self, case_id: str, db: Session) -> list[CaseIOC]:
        """Extracts, normalizes, deduplicates, and persists all IOCs for an investigation case."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        if case.status == CaseStatus.FAILED:
            raise AppException(
                message=f"Cannot extract IOCs from failed case '{case_id}': {case.error_message}",
                code="CASE_PARSING_FAILED",
                status_code=400,
            )

        # 1. Check existing (idempotency)
        existing = db.execute(select(CaseIOC).where(CaseIOC.case_id == case_id)).scalars().all()
        if existing:
            return list(existing)

        # 2. Retrieve or parse structured email data
        parsed_email = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()

        if not parsed_email:
            parsed_email = self.parser_service.get_parsed_case(case_id=case_id, db=db)

        # 3. Extract normalized IOCs
        result = self.extractor.extract_from_email_data(parsed_email)

        records: list[CaseIOC] = []
        for ioc in result.iocs:
            record = CaseIOC(
                case_id=case.id,
                ioc_type=ioc.type.value,
                value=ioc.value,
                source=ioc.source,
                confidence=ioc.confidence,
                context=ioc.context,
            )
            records.append(record)
            db.add(record)

        db.commit()
        for r in records:
            db.refresh(r)

        return records

    def get_case_iocs(self, case_id: str, db: Session) -> list[CaseIOC]:
        """Retrieves existing IOCs for a case or extracts on demand."""
        existing = db.execute(select(CaseIOC).where(CaseIOC.case_id == case_id)).scalars().all()
        if existing:
            return list(existing)

        return self.extract_case_iocs(case_id=case_id, db=db)


# Default singleton instance
default_ioc_service = IOCService()


def get_ioc_service() -> IOCService:
    """Dependency injector for IOC extraction service."""
    return default_ioc_service
