import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import NotFoundError
from src.models.case import Case
from src.models.conclusion import InvestigationConclusion
from src.models.domain_intel import DomainIntelligenceRecord
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.models.ip_intel import IPIntelligenceRecord
from src.models.risk import RiskAssessment
from src.models.threat import ThreatAssessment
from src.services.geo.service import get_geoip_service
from src.services.intel.service import get_intel_service

logger = logging.getLogger("threattrace")


class ConclusionEngineService:
    """Explainable Investigation Conclusion Engine.
    
    Synthesizes existing structured evidence into a unified analyst conclusion
    without AI hallucinations.
    """

    def __init__(self, intel_service=None, geoip_service=None):
        self.intel_service = intel_service or get_intel_service()
        self.geoip_service = geoip_service or get_geoip_service()

    def generate_conclusion(self, case_id: str, db: Session) -> InvestigationConclusion:
        """Deterministically generates a concise analyst conclusion."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' not found.")

        existing = db.execute(
            select(InvestigationConclusion).where(InvestigationConclusion.case_id == case_id)
        ).scalar_one_or_none()
        if existing:
            return existing

        threat = db.execute(
            select(ThreatAssessment).where(ThreatAssessment.case_id == case_id)
        ).scalar_one_or_none()
        risk = db.execute(
            select(RiskAssessment).where(RiskAssessment.case_id == case_id)
        ).scalar_one_or_none()
        forensics = db.execute(
            select(HeaderForensics).where(HeaderForensics.case_id == case_id)
        ).scalar_one_or_none()

        classification = "UNKNOWN"
        confidence = 0.0
        if threat:
            raw_class = threat.classification.upper()
            mapping = {
                "NORMAL": "LEGITIMATE",
                "SPAM": "SUSPICIOUS",
                "PHISHING": "PHISHING",
                "BEC": "BUSINESS_EMAIL_COMPROMISE",
            }
            classification = mapping.get(raw_class, raw_class)
            confidence = threat.confidence

        risk_score = risk.total_score if risk else 0.0

        primary_findings = []
        supporting_evidence = []
        
        if threat and threat.reasons:
            primary_findings.extend(threat.reasons[:3])
            supporting_evidence.extend(threat.reasons[3:])
        
        if forensics:
            if forensics.spf_status == "fail" or forensics.dmarc_status == "fail":
                primary_findings.append(f"Sender authentication failure (SPF: {forensics.spf_status}, DMARC: {forensics.dmarc_status})")
            else:
                supporting_evidence.append(f"Sender authentication evaluation passed (SPF: {forensics.spf_status})")

            if forensics.spoofing_indicators:
                primary_findings.append(f"Spoofing indicator: {forensics.spoofing_indicators[0]}")
            
            if forensics.probable_origin_ip:
                supporting_evidence.append(f"Email originated from IP {forensics.probable_origin_ip}")

        # Sync DB check for Malicious Intel
        ip_intel = db.execute(
            select(IPIntelligenceRecord).where(
                IPIntelligenceRecord.case_id == case_id
            )
        ).scalars().all()
        for ip in ip_intel:
            if (ip.abuse_threat_score and ip.abuse_threat_score > 50) or ip.reputation == "malicious":
                primary_findings.append(f"Malicious IP identified: {ip.ip_address} (Score: {ip.abuse_threat_score or 'N/A'})")

        dom_intel = db.execute(
            select(DomainIntelligenceRecord).where(
                DomainIntelligenceRecord.case_id == case_id
            )
        ).scalars().all()
        for dom in dom_intel:
            if (dom.risk_score and dom.risk_score > 50) or dom.reputation == "malicious":
                primary_findings.append(f"Malicious Domain identified: {dom.domain} (Score: {dom.risk_score or 'N/A'})")

        probable_infra = "Unknown infrastructure"
        if forensics and forensics.probable_origin_ip:
            try:
                geo_data = self.geoip_service.analyze_case_infrastructure(case_id, db)
                if geo_data and "probable_infrastructure_origin" in geo_data and geo_data["probable_infrastructure_origin"]:
                    probable_infra = geo_data["probable_infrastructure_origin"]
                else:
                    probable_infra = f"IP {forensics.probable_origin_ip}"
            except Exception:
                probable_infra = f"IP {forensics.probable_origin_ip}"

        attribution_assessment = "Origin cannot be conclusively attributed to a human actor."
        limitations = [
            "Forensic evaluation is derived from static RFC headers and deterministic threat intelligence feeds.",
            "Dynamic mailbox telemetry and recipient interaction logs are external to this report scope.",
        ]

        if not primary_findings:
            primary_findings.append("No critical threat signals detected.")

        conclusion = InvestigationConclusion(
            case_id=case_id,
            classification=classification,
            risk_score=risk_score,
            confidence=confidence,
            primary_findings=primary_findings,
            supporting_evidence=supporting_evidence,
            probable_infrastructure=probable_infra,
            attribution_assessment=attribution_assessment,
            limitations=limitations,
        )

        db.add(conclusion)
        db.commit()
        db.refresh(conclusion)
        return conclusion


default_conclusion_engine = ConclusionEngineService()


def get_conclusion_engine() -> ConclusionEngineService:
    """Dependency injector for conclusion engine service."""
    return default_conclusion_engine
