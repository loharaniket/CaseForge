from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.threat import ThreatAssessment
from src.services.detector.interface import ThreatDetector
from src.services.detector.rule_based import default_rule_detector
from src.services.parser_service import ParserService, get_parser_service


class DetectionService:
    """Orchestrates email threat detection, explainability generation, and database persistence."""

    def __init__(
        self,
        detector: ThreatDetector | None = None,
        parser_service: ParserService | None = None,
    ) -> None:
        self.detector = detector or default_rule_detector
        self.parser_service = parser_service or get_parser_service()

    def analyze_case(self, case_id: str, db: Session) -> ThreatAssessment:
        """Evaluates an investigation case for cybersecurity threats and persists the assessment."""
        # 1. Verify case existence
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        if case.status == CaseStatus.FAILED:
            raise AppException(
                message=f"Cannot analyze threat on failed case '{case_id}': {case.error_message}",
                code="CASE_PARSING_FAILED",
                status_code=400,
            )

        # 2. Check if already assessed (idempotency)
        existing = db.execute(
            select(ThreatAssessment).where(ThreatAssessment.case_id == case_id)
        ).scalar_one_or_none()

        if existing:
            return existing

        # 3. Retrieve or trigger parsed email data
        parsed_email = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()

        if not parsed_email:
            parsed_email = self.parser_service.get_parsed_case(case_id=case_id, db=db)

        # 4. Execute decoupled threat detector
        result = self.detector.detect(parsed_email)

        # 5. Persist ThreatAssessment entity
        assessment = ThreatAssessment(
            case_id=case.id,
            classification=result.classification.value,
            confidence=result.confidence,
            reasons=result.reasons,
            model_version=result.model_version,
            signals_detected=result.signals_detected,
        )

        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        return assessment

    def get_assessment(self, case_id: str, db: Session) -> ThreatAssessment:
        """Retrieves existing threat assessment or runs detection on-demand."""
        existing = db.execute(
            select(ThreatAssessment).where(ThreatAssessment.case_id == case_id)
        ).scalar_one_or_none()

        if existing:
            return existing

        return self.analyze_case(case_id=case_id, db=db)


# Default singleton instance
default_detection_service = DetectionService()


def get_detection_service() -> DetectionService:
    """Dependency injector for detection service."""
    return default_detection_service
