from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.models.case import Case, CaseStatus
from src.models.forensics import HeaderForensics
from src.models.risk import RiskAssessment
from src.models.threat import ThreatAssessment
from src.services.detection_service import DetectionService, get_detection_service
from src.services.detector.types import ThreatCategory
from src.services.forensics.service import HeaderForensicsService, get_forensics_service
from src.services.risk.types import RiskCalculationResult, RiskScoreBreakdown, RiskSeverity


class RiskScoringService:
    """Deterministic cybersecurity threat risk scoring engine.

    Enforces exact MVP weighting formula (Rule 13):
    - AI Analysis: 40%
    - Header Forensics: 25%
    - Domain Reputation: 15%
    - IP Reputation: 10%
    - URL Analysis: 10%

    All sub-scores and final scores are strictly normalized to 0.0 – 100.0.
    """

    WEIGHT_AI = 0.40
    WEIGHT_HEADER_FORENSICS = 0.25
    WEIGHT_DOMAIN_REPUTATION = 0.15
    WEIGHT_IP_REPUTATION = 0.10
    WEIGHT_URL_ANALYSIS = 0.10

    def __init__(
        self,
        detection_service: DetectionService | None = None,
        forensics_service: HeaderForensicsService | None = None,
    ) -> None:
        self.detection_service = detection_service or get_detection_service()
        self.forensics_service = forensics_service or get_forensics_service()

    @classmethod
    def get_weights(cls) -> dict[str, float]:
        """Returns the immutable weight distribution table."""
        return {
            "ai_analysis": cls.WEIGHT_AI,
            "header_forensics": cls.WEIGHT_HEADER_FORENSICS,
            "domain_reputation": cls.WEIGHT_DOMAIN_REPUTATION,
            "ip_reputation": cls.WEIGHT_IP_REPUTATION,
            "url_analysis": cls.WEIGHT_URL_ANALYSIS,
        }

    @staticmethod
    def _normalize_subscore(value: float | None) -> tuple[float, bool]:
        """Normalizes an input component score to 0.0 - 100.0, reporting missingness."""
        if value is None:
            return 0.0, True
        try:
            val_float = float(value)
            normalized = min(100.0, max(0.0, val_float))
            return round(normalized, 2), False
        except (ValueError, TypeError):
            return 0.0, True

    @classmethod
    def determine_severity(cls, score: float) -> RiskSeverity:
        """Evaluates explicit severity boundaries:

        0.0  - 24.99: LOW
        25.0 - 49.99: MEDIUM
        50.0 - 74.99: HIGH
        75.0 - 100.0: CRITICAL
        """
        clamped_score = min(100.0, max(0.0, score))
        if clamped_score < 25.0:
            return RiskSeverity.LOW
        elif clamped_score < 50.0:
            return RiskSeverity.MEDIUM
        elif clamped_score < 75.0:
            return RiskSeverity.HIGH
        else:
            return RiskSeverity.CRITICAL

    def calculate_score(
        self,
        ai_score: float | None = None,
        header_score: float | None = None,
        domain_score: float | None = None,
        ip_score: float | None = None,
        url_score: float | None = None,
    ) -> RiskCalculationResult:
        """Calculates deterministic weighted risk score from component sub-scores."""
        missing: list[str] = []

        norm_ai, ai_missing = self._normalize_subscore(ai_score)
        if ai_missing:
            missing.append("ai_analysis")

        norm_header, header_missing = self._normalize_subscore(header_score)
        if header_missing:
            missing.append("header_forensics")

        norm_domain, domain_missing = self._normalize_subscore(domain_score)
        if domain_missing:
            missing.append("domain_reputation")

        norm_ip, ip_missing = self._normalize_subscore(ip_score)
        if ip_missing:
            missing.append("ip_reputation")

        norm_url, url_missing = self._normalize_subscore(url_score)
        if url_missing:
            missing.append("url_analysis")

        breakdown = RiskScoreBreakdown(
            ai=norm_ai,
            header_forensics=norm_header,
            domain_reputation=norm_domain,
            ip_reputation=norm_ip,
            url_analysis=norm_url,
        )

        # Deterministic Weighted Formula Calculation
        weighted_sum = (
            (norm_ai * self.WEIGHT_AI)
            + (norm_header * self.WEIGHT_HEADER_FORENSICS)
            + (norm_domain * self.WEIGHT_DOMAIN_REPUTATION)
            + (norm_ip * self.WEIGHT_IP_REPUTATION)
            + (norm_url * self.WEIGHT_URL_ANALYSIS)
        )

        total_score = round(min(100.0, max(0.0, weighted_sum)), 2)
        severity = self.determine_severity(total_score)

        return RiskCalculationResult(
            total_score=total_score,
            severity=severity,
            breakdown=breakdown,
            weights_applied=self.get_weights(),
            missing_components=missing,
        )

    def calculate_case_risk(self, case_id: str, db: Session) -> RiskAssessment:
        """Computes and persists risk assessment for an investigation case."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        if case.status == CaseStatus.FAILED:
            raise AppException(
                message=f"Cannot compute risk score on failed case '{case_id}': {case.error_message}",
                code="CASE_PARSING_FAILED",
                status_code=400,
            )

        # 1. Check if already computed (idempotency)
        existing = db.execute(
            select(RiskAssessment).where(RiskAssessment.case_id == case_id)
        ).scalar_one_or_none()

        if existing:
            return existing

        # 2. Retrieve threat assessment
        threat = db.execute(
            select(ThreatAssessment).where(ThreatAssessment.case_id == case_id)
        ).scalar_one_or_none()

        if not threat:
            threat = self.detection_service.get_assessment(case_id=case_id, db=db)

        # Map AI threat classification to 0-100 risk score
        ai_score = 0.0
        if threat.classification in (ThreatCategory.PHISHING, ThreatCategory.BEC):
            ai_score = threat.confidence * 100.0
        elif threat.classification == ThreatCategory.SPAM:
            ai_score = threat.confidence * 60.0
        elif threat.classification == ThreatCategory.NORMAL:
            ai_score = (1.0 - threat.confidence) * 20.0

        # 3. Retrieve header forensics
        forensics = db.execute(
            select(HeaderForensics).where(HeaderForensics.case_id == case_id)
        ).scalar_one_or_none()

        if not forensics:
            try:
                forensics = self.forensics_service.get_case_forensics(case_id=case_id, db=db)
            except Exception:
                forensics = None

        header_score = forensics.forensics_risk_score if forensics else None

        # Calculate using exact weighted formula (domain, ip, url default to 0.0 with missing audit)
        calc_result = self.calculate_score(
            ai_score=ai_score,
            header_score=header_score,
            domain_score=None,
            ip_score=None,
            url_score=None,
        )

        assessment = RiskAssessment(
            case_id=case.id,
            total_score=calc_result.total_score,
            severity=calc_result.severity.value,
            breakdown=calc_result.breakdown.to_dict(),
            weights_applied=calc_result.weights_applied,
            missing_components=calc_result.missing_components,
        )

        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        return assessment

    def get_case_risk(self, case_id: str, db: Session) -> RiskAssessment:
        """Retrieves existing case risk assessment or computes on-demand."""
        existing = db.execute(
            select(RiskAssessment).where(RiskAssessment.case_id == case_id)
        ).scalar_one_or_none()

        if existing:
            return existing

        return self.calculate_case_risk(case_id=case_id, db=db)


# Default singleton instance
default_risk_service = RiskScoringService()


def get_risk_service() -> RiskScoringService:
    """Dependency injector for risk scoring service."""
    return default_risk_service
