from pathlib import Path

from fastapi import APIRouter, Depends, File, UploadFile, status
from sqlalchemy.orm import Session

from src.api.deps import get_current_active_user, get_db
from src.core.config import settings
from src.core.errors import AppException
from src.models.case import Case, CaseStatus
from src.models.user import User
from src.schemas.email import ParsedEmailResponse
from src.schemas.risk import RiskAssessmentResponse
from src.schemas.threat import ThreatAssessmentResponse
from src.schemas.upload import EmailUploadResponse
from src.services.detection_service import DetectionService, get_detection_service
from src.services.parser_service import ParserService, get_parser_service
from src.services.risk.service import RiskScoringService, get_risk_service
from src.services.storage import EvidenceStorage, get_evidence_storage

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

    # 5. Automatically trigger transactional parsing into PostgreSQL
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
