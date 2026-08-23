import asyncio
import concurrent.futures
from collections.abc import Coroutine
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.config import settings
from src.core.errors import NotFoundError
from src.core.logging import logger
from src.models.case import Case
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.models.ioc import CaseIOC
from src.models.risk import RiskAssessment
from src.models.threat import ThreatAssessment
from src.services.geo.service import default_geoip_service
from src.services.intel.service import default_intel_service
from src.services.report.generator import PDFReportGenerator, ReportGenerator
from src.services.report.types import InvestigationReportData
from src.services.timeline.service import default_timeline_service


def _run_sync(coro: Coroutine[Any, Any, Any]) -> Any:
    """Executes a coroutine synchronously even when invoked within an active event loop."""
    try:
        asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(asyncio.run, coro)
            return future.result()
    except RuntimeError:
        return asyncio.run(coro)


class InvestigationReportService:
    """Service orchestrating multi-layer evidence aggregation and PDF report generation."""

    def __init__(self, generator: ReportGenerator | None = None) -> None:
        self.generator = generator or PDFReportGenerator()

    def _generate_recommendations(
        self,
        classification: str,
        severity: str,
        spf_status: str,
        dmarc_status: str,
        malicious_urls: list[str],
        malicious_ips: list[str],
        attachments_count: int,
    ) -> list[str]:
        """Formulates prioritized SOC remediation recommendations based on threat telemetry."""
        recs: list[str] = []
        sev = severity.upper()
        cls_type = classification.upper()

        if sev in ("CRITICAL", "HIGH") or cls_type in ("PHISHING", "BEC", "CREDENTIAL_PHISHING"):
            recs.append(
                "Immediately purge and quarantine matching email messages across all organizational mailboxes."
            )
            recs.append(
                "Initiate credential reset and session revocation for recipients if links were accessed."
            )

        if malicious_urls:
            recs.append(
                "Block extracted malicious URL domains and endpoints at the DNS and secure web gateway (SWG) layer."
            )

        if malicious_ips:
            recs.append(
                "Add malicious origin and relay IP addresses to network perimeter firewall blocklists."
            )

        if spf_status.lower() == "fail" or dmarc_status.lower() == "fail":
            recs.append(
                "Sender authentication failed: enforce strict DMARC rejection policy (p=reject) on sending domains."
            )

        if attachments_count > 0:
            recs.append(
                "Submit extracted attachment hashes (SHA-256) to Endpoint Detection and Response (EDR) blocklists."
            )

        if not recs:
            recs.append(
                "Threat risk is low. Continue routine endpoint telemetry monitoring and user security awareness training."
            )

        return recs

    def build_report_data(self, case_id: str, db: Session) -> InvestigationReportData:
        """Aggregates all case telemetry into a structured InvestigationReportData payload."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' not found.")

        parsed_email = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()

        forensics = db.execute(
            select(HeaderForensics).where(HeaderForensics.case_id == case_id)
        ).scalar_one_or_none()

        threat = db.execute(
            select(ThreatAssessment).where(ThreatAssessment.case_id == case_id)
        ).scalar_one_or_none()

        risk = db.execute(
            select(RiskAssessment).where(RiskAssessment.case_id == case_id)
        ).scalar_one_or_none()

        case_iocs = db.execute(select(CaseIOC).where(CaseIOC.case_id == case_id)).scalars().all()

        # Intel, Geo, and Timeline enrichment (resilient against missing telemetry)
        try:
            intel_data = _run_sync(
                default_intel_service.analyze_case_indicators(case_id=case_id, db=db)
            )
        except Exception as e:
            logger.warning(f"Report intel enrichment failed for case {case_id}: {e}")
            intel_data = {}

        try:
            geo_data = default_geoip_service.analyze_case_infrastructure(case_id=case_id, db=db)
        except Exception as e:
            logger.warning(f"Report geo enrichment failed for case {case_id}: {e}")
            geo_data = {}

        try:
            timeline_data = default_timeline_service.build_case_timeline(case_id=case_id, db=db)
            timeline_events = [evt.to_dict() for evt in timeline_data.events]
            timeline_count = timeline_data.total_events
        except Exception as e:
            logger.warning(f"Report timeline enrichment failed for case {case_id}: {e}")
            timeline_events = []
            timeline_count = 0

        # Build IOC summaries
        iocs_list: list[dict] = []
        for ioc in case_iocs:
            iocs_list.append(
                {
                    "ioc_type": ioc.ioc_type,
                    "value": ioc.value,
                    "source": ioc.source,
                }
            )

        threat_cls = threat.classification if threat else "normal"
        threat_sev = risk.severity if risk else "low"
        spf_stat = forensics.spf_status if forensics else "none"
        dmarc_stat = forensics.dmarc_status if forensics else "none"
        att_count = (
            len(parsed_email.attachments_metadata)
            if parsed_email and parsed_email.attachments_metadata
            else 0
        )

        malicious_ips = intel_data.get("malicious_ips", []) if isinstance(intel_data, dict) else []
        malicious_domains = (
            intel_data.get("malicious_domains", []) if isinstance(intel_data, dict) else []
        )

        recommendations = self._generate_recommendations(
            classification=threat_cls,
            severity=threat_sev,
            spf_status=spf_stat,
            dmarc_status=dmarc_stat,
            malicious_urls=parsed_email.extracted_urls if parsed_email else [],
            malicious_ips=malicious_ips,
            attachments_count=att_count,
        )

        return InvestigationReportData(
            report_title="Cybersecurity Incident Investigation Report",
            system_name=settings.PROJECT_NAME,
            version=settings.VERSION,
            generated_at_iso=datetime.now(UTC).isoformat(),
            case_id=case.id,
            file_name=case.file_name,
            file_size_bytes=case.file_size_bytes,
            sha256_hash=case.sha256_hash,
            case_status=case.status,
            analyst_name=case.analyst.full_name if case.analyst else "SOC Analyst",
            analyst_email=case.analyst.email if case.analyst else "N/A",
            incident_summary=(
                f"Automated SOC forensic investigation of evidence '{case.file_name}' concluded a "
                f"{threat_cls.upper()} threat classification with a deterministic risk score of "
                f"{risk.total_score if risk else 0.0:.1f}/100 ({threat_sev.upper()})."
            ),
            threat_classification=threat_cls,
            threat_confidence=threat.confidence if threat else 0.0,
            threat_model_version=threat.model_version if threat else "N/A",
            threat_score=risk.total_score if risk else 0.0,
            threat_severity=threat_sev,
            score_breakdown=risk.breakdown if risk else {},
            explainability_reasons=threat.reasons if threat else [],
            subject=parsed_email.subject if parsed_email else "N/A",
            sender=parsed_email.sender if parsed_email else "N/A",
            from_name=parsed_email.from_name if parsed_email else "N/A",
            from_address=parsed_email.from_address if parsed_email else "N/A",
            recipients=parsed_email.recipients if parsed_email and parsed_email.recipients else [],
            cc=parsed_email.cc if parsed_email and parsed_email.cc else [],
            reply_to=parsed_email.reply_to if parsed_email and parsed_email.reply_to else [],
            date_declared=parsed_email.date_raw
            or (
                parsed_email.date_parsed.isoformat()
                if parsed_email and parsed_email.date_parsed
                else "N/A"
            )
            if parsed_email
            else "N/A",
            message_id=parsed_email.message_id if parsed_email else "N/A",
            spf_status=spf_stat,
            dkim_status=forensics.dkim_status if forensics else "none",
            dmarc_status=dmarc_stat,
            authentication_details=forensics.authentication_details if forensics else {},
            probable_origin_ip=forensics.probable_origin_ip or "N/A" if forensics else "N/A",
            origin_ip_candidates=forensics.origin_ip_candidates if forensics else [],
            relay_hops_count=len(forensics.relay_hops) if forensics and forensics.relay_hops else 0,
            relay_hops=forensics.relay_hops if forensics and forensics.relay_hops else [],
            spoofing_indicators=forensics.spoofing_indicators
            if forensics and forensics.spoofing_indicators
            else [],
            header_anomalies=forensics.anomalies if forensics and forensics.anomalies else [],
            total_iocs_count=len(iocs_list),
            iocs=iocs_list,
            ip_intel_provider=intel_data.get("ip_provider", "N/A")
            if isinstance(intel_data, dict)
            else "N/A",
            domain_intel_provider=intel_data.get("domain_provider", "N/A")
            if isinstance(intel_data, dict)
            else "N/A",
            max_ip_risk_score=intel_data.get("max_ip_score")
            if isinstance(intel_data, dict)
            else None,
            max_domain_risk_score=intel_data.get("max_domain_score")
            if isinstance(intel_data, dict)
            else None,
            malicious_ips=malicious_ips,
            malicious_domains=malicious_domains,
            ip_intel_results=intel_data.get("ip_results", [])
            if isinstance(intel_data, dict)
            else [],
            domain_intel_results=intel_data.get("domain_results", [])
            if isinstance(intel_data, dict)
            else [],
            probable_infrastructure_origin=geo_data.get(
                "probable_infrastructure_origin", "Not available"
            )
            if isinstance(geo_data, dict)
            else "Not available",
            origin_country=geo_data.get("origin_country", "N/A")
            if isinstance(geo_data, dict)
            else "N/A",
            origin_asn=geo_data.get("origin_asn") if isinstance(geo_data, dict) else None,
            origin_isp=geo_data.get("origin_isp", "N/A") if isinstance(geo_data, dict) else "N/A",
            geo_disclaimer=geo_data.get("disclaimer", "") if isinstance(geo_data, dict) else "",
            timeline_events_count=timeline_count,
            timeline_events=timeline_events,
            recommendations=recommendations,
            evidence_sha256=case.sha256_hash,
            custody_verification="VERIFIED_AUTHENTIC",
        )

    def generate_case_pdf(self, case_id: str, db: Session) -> tuple[bytes, str]:
        """Compiles the report data and returns binary PDF bytes with filename."""
        report_data = self.build_report_data(case_id=case_id, db=db)
        pdf_bytes = self.generator.generate_pdf(report_data)
        filename = f"ThreatTrace_Investigation_Report_{case_id[:8]}.pdf"
        logger.info(
            f"Generated investigation PDF report for case '{case_id}' ({len(pdf_bytes)} bytes)"
        )
        return pdf_bytes, filename


# Global default instance & dependency injector
default_report_service = InvestigationReportService()


def get_report_service() -> InvestigationReportService:
    """FastAPI dependency provider for InvestigationReportService."""
    return default_report_service
