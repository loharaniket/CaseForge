import asyncio
import concurrent.futures
import logging
import re
from collections.abc import Coroutine
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.models.risk import RiskAssessment
from src.models.threat import ThreatAssessment
from src.services.detection_service import DetectionService, get_detection_service
from src.services.detector.types import ThreatCategory
from src.services.forensics.service import HeaderForensicsService, get_forensics_service
from src.services.intel.service import ThreatIntelService, get_intel_service
from src.services.ioc.service import IOCService, get_ioc_service
from src.services.ioc.types import IOCType
from src.services.parser.url_extractor import extract_urls
from src.services.risk.types import RiskCalculationResult, RiskScoreBreakdown, RiskSeverity

logger = logging.getLogger("threattrace")


def _run_sync(coro: Coroutine[Any, Any, Any]) -> Any:
    """Executes an async coroutine synchronously even when called within an active event loop."""
    try:
        asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    except RuntimeError:
        return asyncio.run(coro)


RE_IP_HOST_IN_URL = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}", re.IGNORECASE)

SUSPICIOUS_URL_KEYWORDS = {
    "verify",
    "verification",
    "login",
    "signin",
    "sign-in",
    "credential",
    "password",
    "auth",
    "authenticate",
    "account",
    "secure",
    "security",
    "update",
    "banking",
    "bank",
    "reset",
    "session",
    "token",
    "validate",
    "validation",
    "invoice",
    "remit",
    "payment",
    "wire",
}


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
        ioc_service: IOCService | None = None,
        intel_service: ThreatIntelService | None = None,
    ) -> None:
        self.detection_service = detection_service or get_detection_service()
        self.forensics_service = forensics_service or get_forensics_service()
        self.ioc_service = ioc_service or get_ioc_service()
        self.intel_service = intel_service or get_intel_service()

    @classmethod
    def get_weights(cls) -> dict[str, float]:
        """Returns the immutable base weight distribution table."""
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

    @classmethod
    def evaluate_url_risk(
        cls,
        urls: list[str],
        malicious_domains: set[str] | None = None,
        malicious_ips: set[str] | None = None,
    ) -> float:
        """Deterministically evaluates URL threat indicators from extracted URLs.

        Strict security guarantee: No outgoing socket or HTTP requests are made.
        Evaluates heuristic risk signals:
        - Raw IP host in URL: +50 pts (evasion/phishing pattern)
        - Suspicious credential / banking / urgency keyword in path/query: +30 pts
        - URL host domain matches confirmed malicious domain from intel: +40 pts
        - URL host IP matches confirmed malicious IP from intel: +40 pts
        - Non-HTTPS HTTP link with credential keyword: +15 pts
        - Deep subdomain nesting (> 4 levels): +10 pts

        Returns normalized score clamped to 0.0 – 100.0.
        """
        if not urls:
            return 0.0

        mal_doms = {d.lower().strip() for d in (malicious_domains or set())}
        mal_ips = {ip.strip() for ip in (malicious_ips or set())}

        max_url_risk = 0.0

        for url in urls:
            u_score = 0.0
            clean_url = url.strip()
            if not clean_url:
                continue

            try:
                parsed = urlparse(clean_url)
                host = (parsed.netloc.split(":")[0]).strip("[]").lower()
                path_lower = parsed.path.lower()
                query_lower = parsed.query.lower()
                combined_path_query = f"{path_lower}?{query_lower}"

                # 1. Raw IP in URL host (+50)
                if RE_IP_HOST_IN_URL.search(clean_url) or (
                    len(host.split(".")) == 4 and all(part.isdigit() for part in host.split("."))
                ):
                    u_score += 50.0

                # 2. Suspicious credential harvesting / banking keywords in path/query (+30)
                if any(kw in combined_path_query for kw in SUSPICIOUS_URL_KEYWORDS):
                    u_score += 30.0

                # 3. Known malicious domain match (+40)
                if host in mal_doms or any(host.endswith(f".{d}") for d in mal_doms):
                    u_score += 40.0

                # 4. Known malicious IP match (+40)
                if host in mal_ips:
                    u_score += 40.0

                # 5. Insecure HTTP with sensitive keyword (+15)
                if parsed.scheme.lower() == "http" and any(
                    kw in combined_path_query for kw in SUSPICIOUS_URL_KEYWORDS
                ):
                    u_score += 15.0

                # 6. Deep subdomain nesting (> 4 labels) (+10)
                if len(host.split(".")) > 4:
                    u_score += 10.0

            except Exception:
                u_score = 20.0

            if u_score > max_url_risk:
                max_url_risk = u_score

        return min(100.0, max(0.0, max_url_risk))

    def calculate_score(
        self,
        ai_score: float | None = None,
        header_score: float | None = None,
        domain_score: float | None = None,
        ip_score: float | None = None,
        url_score: float | None = None,
        renormalize: bool = True,
    ) -> RiskCalculationResult:
        """Calculates deterministic weighted risk score from component sub-scores.

        Formula weights (Rule 13):
        - AI Analysis: 40%
        - Header Forensics: 25%
        - Domain Reputation: 15%
        - IP Reputation: 10%
        - URL Analysis: 10%

        Missing Data Policy:
        - If renormalize=True and available weights < 1.0, available weights are scaled proportionally
          so the final score is normalized to 0.0 - 100.0 without artificially deflating risk.
        - If renormalize=False or all components are available, standard weighting is applied.
        """
        missing: list[str] = []

        components: dict[str, tuple[float | None, float]] = {
            "ai_analysis": (ai_score, self.WEIGHT_AI),
            "header_forensics": (header_score, self.WEIGHT_HEADER_FORENSICS),
            "domain_reputation": (domain_score, self.WEIGHT_DOMAIN_REPUTATION),
            "ip_reputation": (ip_score, self.WEIGHT_IP_REPUTATION),
            "url_analysis": (url_score, self.WEIGHT_URL_ANALYSIS),
        }

        normalized_scores: dict[str, float] = {}
        avail_weight_sum = 0.0
        raw_weighted_sum = 0.0

        for comp_name, (raw_val, base_weight) in components.items():
            norm_val, is_missing = self._normalize_subscore(raw_val)
            normalized_scores[comp_name] = norm_val
            if is_missing:
                missing.append(comp_name)
            else:
                avail_weight_sum += base_weight
                raw_weighted_sum += norm_val * base_weight

        breakdown = RiskScoreBreakdown(
            ai=normalized_scores["ai_analysis"],
            header_forensics=normalized_scores["header_forensics"],
            domain_reputation=normalized_scores["domain_reputation"],
            ip_reputation=normalized_scores["ip_reputation"],
            url_analysis=normalized_scores["url_analysis"],
        )

        if renormalize and avail_weight_sum > 0.0:
            total_score = round(min(100.0, max(0.0, raw_weighted_sum / avail_weight_sum)), 2)
            weights_applied = {
                comp_name: round(base_weight / avail_weight_sum, 4)
                if comp_name not in missing
                else 0.0
                for comp_name, (_, base_weight) in components.items()
            }
        else:
            total_score = round(min(100.0, max(0.0, raw_weighted_sum)), 2)
            weights_applied = self.get_weights()

        severity = self.determine_severity(total_score)

        return RiskCalculationResult(
            total_score=total_score,
            severity=severity,
            breakdown=breakdown,
            weights_applied=weights_applied,
            missing_components=missing,
        )

    def calculate_case_risk(self, case_id: str, db: Session) -> RiskAssessment:
        """Computes and persists risk assessment across all 5 investigation dimensions."""
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

        # 2. Retrieve threat detection (AI Analysis - 40%)
        threat = db.execute(
            select(ThreatAssessment).where(ThreatAssessment.case_id == case_id)
        ).scalar_one_or_none()

        if not threat:
            threat = self.detection_service.get_assessment(case_id=case_id, db=db)

        ai_score = 0.0
        if threat:
            if threat.classification in (ThreatCategory.PHISHING, ThreatCategory.BEC):
                ai_score = threat.confidence * 100.0
            elif threat.classification == ThreatCategory.SPAM:
                ai_score = threat.confidence * 60.0
            elif threat.classification == ThreatCategory.NORMAL:
                ai_score = (1.0 - threat.confidence) * 20.0

        # 3. Retrieve header forensics (25%)
        forensics = db.execute(
            select(HeaderForensics).where(HeaderForensics.case_id == case_id)
        ).scalar_one_or_none()

        if not forensics:
            try:
                forensics = self.forensics_service.get_case_forensics(case_id=case_id, db=db)
            except Exception:
                forensics = None

        header_score = forensics.forensics_risk_score if forensics else None

        # 4. Retrieve or extract IOCs
        try:
            case_iocs = self.ioc_service.get_case_iocs(case_id=case_id, db=db)
        except Exception:
            case_iocs = []

        # 5. Retrieve threat intelligence for Domain (15%) and IP (10%)
        domain_score: float | None = None
        ip_score: float | None = None
        malicious_domains: list[str] = []
        malicious_ips: list[str] = []

        try:
            intel_data = _run_sync(
                self.intel_service.analyze_case_indicators(case_id=case_id, db=db)
            )
            malicious_domains = intel_data.get("malicious_domains", [])
            malicious_ips = intel_data.get("malicious_ips", [])

            # Domain score
            domain_lookups_count = intel_data.get("domain_lookups_count", 0)
            max_domain_score = intel_data.get("max_domain_score")
            if domain_lookups_count > 0:
                domain_score = float(max_domain_score) if max_domain_score is not None else None
            else:
                domain_score = 0.0

            # IP score
            ip_lookups_count = intel_data.get("ip_lookups_count", 0)
            max_ip_score = intel_data.get("max_ip_score")
            if ip_lookups_count > 0:
                ip_score = float(max_ip_score) if max_ip_score is not None else None
            else:
                ip_score = 0.0

        except Exception as e:
            logger.warning(
                f"Risk calculation threat intel enrichment failed for case {case_id}: {e}"
            )
            domain_score = None
            ip_score = None

        # 6. Retrieve extracted URLs and compute URL analysis score (10%)
        urls = [ioc.value for ioc in case_iocs if ioc.ioc_type == IOCType.URL]
        if not urls:
            parsed_email = db.execute(
                select(ParsedEmail).where(ParsedEmail.case_id == case_id)
            ).scalar_one_or_none()
            if parsed_email:
                urls = extract_urls(
                    text_content=parsed_email.body_plain,
                    html_content=parsed_email.body_html,
                )

        url_score: float | None = None
        try:
            url_score = self.evaluate_url_risk(
                urls=urls,
                malicious_domains=set(malicious_domains),
                malicious_ips=set(malicious_ips),
            )
        except Exception as e:
            logger.warning(f"URL risk evaluation failed for case {case_id}: {e}")
            url_score = None

        # 7. Calculate deterministic weighted score
        calc_result = self.calculate_score(
            ai_score=ai_score,
            header_score=header_score,
            domain_score=domain_score,
            ip_score=ip_score,
            url_score=url_score,
            renormalize=True,
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
