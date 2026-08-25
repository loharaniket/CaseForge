from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.threat import ThreatAssessment
from src.services.detector.interface import ThreatDetector
from src.services.detector.rule_based import default_rule_detector
from src.services.detector.extended import extended_detector
from src.models.forensics import HeaderForensics
from src.models.url_intel import URLIntelligenceRecord

class CompositeContext:
    def __init__(self, parsed, auth_details, url_intel):
        self._parsed = parsed
        self.auth_details = auth_details
        self.url_intel = url_intel
    def __getattr__(self, name):
        return getattr(self._parsed, name)

from src.services.parser_service import ParserService, get_parser_service


class DetectionService:
    """Orchestrates email threat detection, explainability generation, and database persistence."""

    def __init__(
        self,
        detector: ThreatDetector | None = None,
        parser_service: ParserService | None = None,
    ) -> None:
        self.detector = detector or extended_detector
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
        # Fetch URL intelligence
        url_intel = db.execute(
            select(URLIntelligenceRecord).where(URLIntelligenceRecord.case_id == case_id)
        ).scalars().all()
        
        # Fetch Header Forensics (authentication results)
        hf = db.execute(select(HeaderForensics).where(HeaderForensics.case_id == case_id)).scalar_one_or_none()
        auth_details = {}
        if hf:
            # We don't have authentication directly on the DB model, but we can look for raw_headers in parsed_email
            # Wait, the prompt says "authentication results". If it's not on HF model, we can parse from raw_headers
            auth_res = parsed_email.raw_headers.get("Authentication-Results", "") if parsed_email.raw_headers else ""
            if isinstance(auth_res, list): auth_res = " ".join(auth_res)
            auth_details["spf_status"] = "fail" if "spf=fail" in auth_res.lower() else ("pass" if "spf=pass" in auth_res.lower() else "neutral")
            auth_details["dkim_status"] = "fail" if "dkim=fail" in auth_res.lower() else ("pass" if "dkim=pass" in auth_res.lower() else "neutral")

        context = CompositeContext(parsed_email, auth_details, url_intel)
        result = self.detector.detect(context)

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
