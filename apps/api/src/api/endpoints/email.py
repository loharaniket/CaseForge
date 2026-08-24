from pathlib import Path

from fastapi import APIRouter, Depends, File, Response, UploadFile, status
from sqlalchemy.orm import Session

from src.api.deps import get_current_active_user, get_db
from src.core.config import settings
from src.core.errors import AppException
from src.models.case import Case, CaseStatus
from src.models.user import User
from src.schemas.email import ParsedEmailResponse
from src.schemas.evidence import (
    CaseEvidenceListResponse,
    CaseEvidenceVerificationResponse,
    EvidenceRecordSchema,
    EvidenceVerificationResultSchema,
)
from src.schemas.forensics import HeaderForensicsResponse
from src.schemas.geo import CaseGeoInfrastructureResponse, GeoLocationResultSchema
from src.schemas.intel import CaseThreatIntelResponse, ReputationResultSchema
from src.schemas.ioc import CaseIOCListResponse, IOCRecordSchema
from src.schemas.report import InvestigationReportDataResponse
from src.schemas.risk import RiskAssessmentResponse
from src.schemas.threat import ThreatAssessmentResponse
from src.schemas.timeline import ForensicTimelineResponse
from src.schemas.upload import EmailUploadResponse
from src.services.detection_service import DetectionService, get_detection_service
from src.services.evidence.service import (
    EvidenceIntegrityService,
    get_evidence_integrity_service,
)
from src.services.evidence.types import EvidenceType
from src.services.forensics.service import HeaderForensicsService, get_forensics_service
from src.services.geo.service import GeoIPService, get_geoip_service
from src.services.intel.service import ThreatIntelService, get_intel_service
from src.services.ioc.service import IOCService, get_ioc_service
from src.services.parser_service import ParserService, get_parser_service
from src.services.report.service import InvestigationReportService, get_report_service
from src.services.risk.service import RiskScoringService, get_risk_service
from src.services.storage import EvidenceStorage, get_evidence_storage
from src.services.timeline.service import ForensicTimelineService, get_timeline_service

router = APIRouter()


@router.post(
    "/upload",
    response_model=EmailUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Secure EML Email Ingestion & Forensic Parsing",
    description="Accepts an untrusted .eml email file from an authenticated analyst, calculates cryptographic evidence SHA-256, safely persists the raw file, creates a Case record, and parses forensic metadata into PostgreSQL.",
    responses={
        201: {"description": "Evidence ingested, case created, and email parsed"},
        400: {"description": "Invalid file extension or empty file"},
        401: {"description": "Authentication required"},
        413: {"description": "File exceeds maximum size limit"},
    },
)
async def upload_eml(
    file: UploadFile = File(..., description="Suspicious raw RFC822 (.eml) email file"),
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    storage: EvidenceStorage = Depends(get_evidence_storage),
    parser_service: ParserService = Depends(get_parser_service),
    evidence_service: EvidenceIntegrityService = Depends(get_evidence_integrity_service),
) -> EmailUploadResponse:
    """Safely ingests, hashes, and parses a raw .eml evidence file."""
    original_filename = file.filename or "unknown.eml"
    sanitized_filename = Path(original_filename).name

    # 1. Validate extension
    if not sanitized_filename.lower().endswith(".eml"):
        raise AppException(
            message="Invalid file format. Only RFC 822 (.eml) files are accepted.",
            code="INVALID_FILE_EXTENSION",
            status_code=status.HTTP_400_BAD_REQUEST,
            details={
                "allowed_extensions": settings.ALLOWED_EMAIL_EXTENSIONS,
                "received": sanitized_filename,
            },
        )

    # 2. Read bytes safely up to maximum allowed size
    max_size = settings.MAX_UPLOAD_SIZE_BYTES
    content = bytearray()
    chunk_size = 64 * 1024  # 64 KB chunks

    while True:
        chunk = await file.read(chunk_size)
        if not chunk:
            break
        content.extend(chunk)
        if len(content) > max_size:
            raise AppException(
                message=f"Uploaded file exceeds maximum allowed size of {max_size // (1024 * 1024)}MB.",
                code="FILE_TOO_LARGE",
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                details={"max_size_bytes": max_size, "received_bytes": len(content)},
            )

    if len(content) == 0:
        raise AppException(
            message="Uploaded email file is empty (0 bytes).",
            code="EMPTY_FILE",
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    raw_bytes = bytes(content)

    # 3. Store raw evidence safely via EvidenceStorage abstraction
    storage_key, sha256_hash = storage.save(raw_bytes, sanitized_filename)

    # 4. Create case record in PostgreSQL in UPLOADED status
    new_case = Case(
        user_id=current_user.id,
        file_name=sanitized_filename,
        file_size_bytes=len(raw_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    # 5. Persist baseline cryptographic evidence record
    evidence_service.record_evidence_hash(
        case_id=new_case.id,
        evidence_type=EvidenceType.ORIGINAL_EMAIL,
        data=raw_bytes,
        file_name=sanitized_filename,
        metadata={"storage_key": storage_key},
        db=db,
    )
    db.commit()

    # 6. Automatically trigger transactional parsing into PostgreSQL
    try:
        parser_service.parse_case(case_id=new_case.id, db=db)
        db.refresh(new_case)
    except Exception:
        # Failure state is safely recorded in new_case.status = FAILED
        db.refresh(new_case)

    return EmailUploadResponse(
        case_id=new_case.id,
        status=new_case.status,
        file_name=new_case.file_name,
        file_size_bytes=new_case.file_size_bytes,
        sha256=new_case.sha256_hash,
        created_at=new_case.created_at,
        error_message=new_case.error_message,
    )


@router.post(
    "/{case_id}/parse",
    response_model=ParsedEmailResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute EML Forensic Parsing",
    description="Deterministically parses raw evidence for an investigation case into structured headers, body, attachment hashes, and extracted URLs.",
    responses={
        200: {"description": "Case parsed successfully"},
        401: {"description": "Authentication required"},
        404: {"description": "Case or evidence file not found"},
    },
)
def parse_email_case(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    parser_service: ParserService = Depends(get_parser_service),
) -> ParsedEmailResponse:
    """Triggers forensic parsing of an ingested email."""
    parsed_record = parser_service.parse_case(case_id=case_id, db=db)
    return ParsedEmailResponse.model_validate(parsed_record)


@router.get(
    "/{case_id}/parsed",
    response_model=ParsedEmailResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Parsed Forensic Email Data",
    description="Retrieves the structured forensic email analysis for a specified case.",
    responses={
        200: {"description": "Parsed email data"},
        401: {"description": "Authentication required"},
        404: {"description": "Case or evidence file not found"},
    },
)
def get_parsed_email_case(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    parser_service: ParserService = Depends(get_parser_service),
) -> ParsedEmailResponse:
    """Retrieves or parses on demand the structured forensic data."""
    parsed_record = parser_service.get_parsed_case(case_id=case_id, db=db)
    return ParsedEmailResponse.model_validate(parsed_record)


@router.post(
    "/{case_id}/threat-analysis",
    response_model=ThreatAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Explainable Threat Detection",
    description="Runs deterministic heuristic threat detection on an ingested case, classifying it into normal, spam, phishing, or BEC with explainable forensic signals.",
    responses={
        200: {"description": "Threat assessment generated"},
        400: {"description": "Case processing failed or unparseable"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def analyze_email_threat(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ThreatAssessmentResponse:
    """Triggers threat detection evaluation on an email case."""
    assessment = detection_service.analyze_case(case_id=case_id, db=db)
    return ThreatAssessmentResponse.model_validate(assessment)


@router.get(
    "/{case_id}/threat-analysis",
    response_model=ThreatAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Threat Assessment Result",
    description="Retrieves or evaluates on demand the explainable threat classification for a case.",
    responses={
        200: {"description": "Threat assessment data"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def get_email_threat(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ThreatAssessmentResponse:
    """Retrieves or generates on demand the threat assessment."""
    assessment = detection_service.get_assessment(case_id=case_id, db=db)
    return ThreatAssessmentResponse.model_validate(assessment)


@router.post(
    "/{case_id}/header-forensics",
    response_model=HeaderForensicsResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Header Forensic & Relay Analysis",
    description="Reconstructs the Received relay chain, identifies candidate origin IPs, extracts SPF/DKIM/DMARC status, and checks for spoofing.",
    responses={
        200: {"description": "Header forensics analysis completed"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def analyze_header_forensics(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    forensics_service: HeaderForensicsService = Depends(get_forensics_service),
) -> HeaderForensicsResponse:
    """Analyzes email relay headers and sender authentication."""
    assessment = forensics_service.analyze_case(case_id=case_id, db=db)
    return HeaderForensicsResponse.model_validate(assessment)


@router.get(
    "/{case_id}/header-forensics",
    response_model=HeaderForensicsResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Header Forensic Result",
    description="Retrieves or executes on-demand header forensic relay analysis for a case.",
    responses={
        200: {"description": "Header forensics data"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def get_header_forensics(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    forensics_service: HeaderForensicsService = Depends(get_forensics_service),
) -> HeaderForensicsResponse:
    """Retrieves or generates on-demand header forensics."""
    assessment = forensics_service.get_case_forensics(case_id=case_id, db=db)
    return HeaderForensicsResponse.model_validate(assessment)


@router.post(
    "/{case_id}/iocs",
    response_model=CaseIOCListResponse,
    status_code=status.HTTP_200_OK,
    summary="Extract and Normalize Case IOCs",
    description="Deterministically extracts and deduplicates all Indicators of Compromise (IPv4, IPv6, domains, URLs, emails, attachment SHA-256 hashes) from case evidence.",
    responses={
        200: {"description": "IOC extraction completed and persisted"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def extract_case_iocs(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    ioc_service: IOCService = Depends(get_ioc_service),
) -> CaseIOCListResponse:
    """Extracts, normalizes, deduplicates, and persists IOCs for a case."""
    records = ioc_service.extract_case_iocs(case_id=case_id, db=db)
    ioc_schemas = [IOCRecordSchema.model_validate(r) for r in records]

    by_type: dict[str, int] = {}
    for r in records:
        by_type[r.ioc_type] = by_type.get(r.ioc_type, 0) + 1

    return CaseIOCListResponse(
        case_id=case_id,
        total_count=len(records),
        by_type=by_type,
        iocs=ioc_schemas,
    )


@router.get(
    "/{case_id}/iocs",
    response_model=CaseIOCListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Case IOCs",
    description="Retrieves existing extracted IOCs for a case or extracts on demand.",
    responses={
        200: {"description": "Extracted IOC list data"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def get_case_iocs(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    ioc_service: IOCService = Depends(get_ioc_service),
) -> CaseIOCListResponse:
    """Retrieves or extracts on demand IOCs for a case."""
    records = ioc_service.get_case_iocs(case_id=case_id, db=db)
    ioc_schemas = [IOCRecordSchema.model_validate(r) for r in records]

    by_type: dict[str, int] = {}
    for r in records:
        by_type[r.ioc_type] = by_type.get(r.ioc_type, 0) + 1

    return CaseIOCListResponse(
        case_id=case_id,
        total_count=len(records),
        by_type=by_type,
        iocs=ioc_schemas,
    )


@router.post(
    "/{case_id}/threat-intel",
    response_model=CaseThreatIntelResponse,
    status_code=status.HTTP_200_OK,
    summary="Query Threat Intelligence for Case Indicators",
    description="Queries IP and Domain reputation providers (AbuseIPDB, VirusTotal, or Mock adapters) for all unique case IOCs with caching and graceful error resilience.",
    responses={
        200: {"description": "Threat intelligence lookup complete"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
async def query_case_threat_intel(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    intel_service: ThreatIntelService = Depends(get_intel_service),
) -> CaseThreatIntelResponse:
    """Queries threat intelligence providers for all case IPs and domains."""
    result = await intel_service.analyze_case_indicators(case_id=case_id, db=db)

    ip_schemas = [ReputationResultSchema.model_validate(r) for r in result["ip_results"]]
    domain_schemas = [ReputationResultSchema.model_validate(r) for r in result["domain_results"]]

    return CaseThreatIntelResponse(
        case_id=result["case_id"],
        ip_provider=result["ip_provider"],
        domain_provider=result["domain_provider"],
        ip_lookups_count=result["ip_lookups_count"],
        domain_lookups_count=result["domain_lookups_count"],
        max_ip_score=result["max_ip_score"],
        max_domain_score=result["max_domain_score"],
        avg_ip_score=result["avg_ip_score"],
        avg_domain_score=result["avg_domain_score"],
        malicious_ips=result["malicious_ips"],
        malicious_domains=result["malicious_domains"],
        ip_results=ip_schemas,
        domain_results=domain_schemas,
    )


@router.get(
    "/{case_id}/threat-intel",
    response_model=CaseThreatIntelResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Case Threat Intelligence",
    description="Retrieves threat intelligence reputation assessments for case indicators.",
    responses={
        200: {"description": "Threat intelligence data"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
async def get_case_threat_intel(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    intel_service: ThreatIntelService = Depends(get_intel_service),
) -> CaseThreatIntelResponse:
    """Retrieves threat intelligence for a case."""
    return await query_case_threat_intel(
        case_id=case_id, current_user=current_user, db=db, intel_service=intel_service
    )


@router.post(
    "/{case_id}/geo-infrastructure",
    response_model=CaseGeoInfrastructureResponse,
    status_code=status.HTTP_200_OK,
    summary="Enrich Case IP Infrastructure & Geolocation",
    description="Enriches candidate origin IPs and relay infrastructure with geographic and ASN information (Probable Infrastructure Origin).",
    responses={
        200: {"description": "GeoIP infrastructure enrichment completed"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def enrich_case_geo_infrastructure(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    geoip_service: GeoIPService = Depends(get_geoip_service),
) -> CaseGeoInfrastructureResponse:
    """Enriches all case IP infrastructure with GeoIP and ASN intelligence."""
    result = geoip_service.analyze_case_infrastructure(case_id=case_id, db=db)
    ip_schemas = [GeoLocationResultSchema.model_validate(r) for r in result["ip_infrastructure"]]

    return CaseGeoInfrastructureResponse(
        case_id=result["case_id"],
        provider_name=result["provider_name"],
        candidate_origin_ip=result["candidate_origin_ip"],
        probable_infrastructure_origin=result["probable_infrastructure_origin"],
        origin_country=result["origin_country"],
        origin_country_code=result["origin_country_code"],
        origin_asn=result["origin_asn"],
        origin_isp=result["origin_isp"],
        disclaimer=result["disclaimer"],
        total_ips_analyzed=result["total_ips_analyzed"],
        ip_infrastructure=ip_schemas,
    )


@router.get(
    "/{case_id}/geo-infrastructure",
    response_model=CaseGeoInfrastructureResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Case GeoIP Infrastructure Result",
    description="Retrieves enriched GeoIP network infrastructure and probable origin for a case.",
    responses={
        200: {"description": "GeoIP infrastructure data"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def get_case_geo_infrastructure(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    geoip_service: GeoIPService = Depends(get_geoip_service),
) -> CaseGeoInfrastructureResponse:
    """Retrieves GeoIP infrastructure for a case."""
    return enrich_case_geo_infrastructure(
        case_id=case_id, current_user=current_user, db=db, geoip_service=geoip_service
    )


@router.post(
    "/{case_id}/risk-assessment",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Calculate Deterministic Risk Score",
    description="Calculates normalized 0-100 risk score using exact MVP weights: AI (40%), Headers (25%), Domain (15%), IP (10%), URL (10%).",
    responses={
        200: {"description": "Risk score computed and persisted"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def compute_case_risk(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    risk_service: RiskScoringService = Depends(get_risk_service),
) -> RiskAssessmentResponse:
    """Calculates and persists deterministic risk score for a case."""
    assessment = risk_service.calculate_case_risk(case_id=case_id, db=db)
    return RiskAssessmentResponse.model_validate(assessment)


@router.get(
    "/{case_id}/risk-assessment",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Risk Assessment Result",
    description="Retrieves or calculates on-demand the deterministic risk score for a case.",
    responses={
        200: {"description": "Risk assessment data"},
        400: {"description": "Case processing failed"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def get_case_risk(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    risk_service: RiskScoringService = Depends(get_risk_service),
) -> RiskAssessmentResponse:
    """Retrieves or generates on-demand the risk assessment."""
    assessment = risk_service.get_case_risk(case_id=case_id, db=db)
    return RiskAssessmentResponse.model_validate(assessment)


@router.get(
    "/{case_id}/timeline",
    response_model=ForensicTimelineResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Chronological Forensic Timeline",
    description="Constructs and returns an accurate chronological evidence timeline from email transmission headers, authentication results, and analysis events.",
    responses={
        200: {"description": "Chronological forensic timeline results"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def get_case_timeline(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    timeline_service: ForensicTimelineService = Depends(get_timeline_service),
) -> ForensicTimelineResponse:
    """Retrieves chronological investigation timeline for a case."""
    timeline = timeline_service.build_case_timeline(case_id=case_id, db=db)
    return ForensicTimelineResponse.model_validate(timeline.to_dict())


@router.get(
    "/{case_id}/report/pdf",
    status_code=status.HTTP_200_OK,
    summary="Download Investigation PDF Report",
    description="Compiles and streams a complete 18-section SOC investigation report in PDF format.",
    responses={
        200: {
            "content": {"application/pdf": {}},
            "description": "Binary PDF investigation report stream",
        },
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def download_case_pdf_report(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    storage: EvidenceStorage = Depends(get_evidence_storage),
    report_service: InvestigationReportService = Depends(get_report_service),
    evidence_service: EvidenceIntegrityService = Depends(get_evidence_integrity_service),
) -> Response:
    """Streams a generated PDF investigation report and records its cryptographic SHA-256 hash."""
    pdf_bytes, filename = report_service.generate_case_pdf(case_id=case_id, db=db)

    # Persist report file bytes in storage vault
    storage_key, _ = storage.save(pdf_bytes, filename)

    # Persist cryptographic report hash record for integrity verification
    evidence_service.record_evidence_hash(
        case_id=case_id,
        evidence_type=EvidenceType.INVESTIGATION_REPORT,
        data=pdf_bytes,
        file_name=filename,
        metadata={"report_version": "1.0.0", "storage_key": storage_key},
        db=db,
    )
    db.commit()

    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": "application/pdf",
        "X-Report-Case-ID": case_id,
    }
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)


@router.get(
    "/{case_id}/report/data",
    response_model=InvestigationReportDataResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Investigation Report Data Structure",
    description="Returns the aggregated 18-section structured investigation data model in JSON format.",
    responses={
        200: {"description": "Structured investigation report payload"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def get_case_report_data(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    report_service: InvestigationReportService = Depends(get_report_service),
) -> InvestigationReportDataResponse:
    """Retrieves structured report data for a case."""
    report_data = report_service.build_report_data(case_id=case_id, db=db)
    return InvestigationReportDataResponse.model_validate(report_data.to_dict())


@router.get(
    "/{case_id}/evidence",
    response_model=CaseEvidenceListResponse,
    status_code=status.HTTP_200_OK,
    summary="Get Case Evidence Integrity Records",
    description="Retrieves all registered cryptographic SHA-256 evidence records for an investigation case.",
    responses={
        200: {"description": "List of cryptographic evidence records"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def get_case_evidence_records(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    evidence_service: EvidenceIntegrityService = Depends(get_evidence_integrity_service),
) -> CaseEvidenceListResponse:
    """Retrieves all stored evidence records for a case."""
    records = evidence_service.get_case_evidence_records(case_id=case_id, db=db)
    return CaseEvidenceListResponse(
        case_id=case_id,
        total_evidence_records=len(records),
        records=[EvidenceRecordSchema.model_validate(r.to_dict()) for r in records],
    )


@router.post(
    "/{case_id}/evidence/verify",
    response_model=CaseEvidenceVerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify Case Evidence Cryptographic Integrity",
    description="Performs real-time SHA-256 verification across all registered evidence artifacts (original email, reports) against baseline records.",
    responses={
        200: {"description": "Cryptographic verification results"},
        401: {"description": "Authentication required"},
        404: {"description": "Case not found"},
    },
)
def verify_case_evidence(
    case_id: str,
    current_user: User = Depends(get_current_active_user),
    db: Session = Depends(get_db),
    evidence_service: EvidenceIntegrityService = Depends(get_evidence_integrity_service),
) -> CaseEvidenceVerificationResponse:
    """Cryptographically verifies all case evidence."""
    results = evidence_service.verify_all_case_evidence(case_id=case_id, db=db)
    all_valid = all(r.is_valid for r in results) if results else False
    return CaseEvidenceVerificationResponse(
        case_id=case_id,
        total_verified=len(results),
        all_valid=all_valid,
        results=[EvidenceVerificationResultSchema.model_validate(r.to_dict()) for r in results],
    )
