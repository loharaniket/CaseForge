from pathlib import Path

from fastapi import APIRouter, Depends, File, UploadFile, status
from sqlalchemy.orm import Session

from src.api.deps import get_current_active_user, get_db
from src.core.config import settings
from src.core.errors import AppException
from src.models.case import Case
from src.models.user import User
from src.schemas.email import ParsedEmailResponse
from src.schemas.upload import EmailUploadResponse
from src.services.parser_service import ParserService, get_parser_service
from src.services.storage import EvidenceStorage, get_evidence_storage

router = APIRouter()


@router.post(
    "/upload",
    response_model=EmailUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Secure EML Email Ingestion",
    description="Accepts an untrusted .eml email file from an authenticated analyst, calculates cryptographic evidence SHA-256, safely persists the raw file, and returns a new Case ID.",
    responses={
        201: {"description": "Evidence ingested and case created"},
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
) -> EmailUploadResponse:
    """Safely ingests and stores a raw .eml file."""
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

    # 4. Create case record in PostgreSQL
    new_case = Case(
        user_id=current_user.id,
        file_name=sanitized_filename,
        file_size_bytes=len(raw_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status="received",
    )
    db.add(new_case)
    db.commit()
    db.refresh(new_case)

    return EmailUploadResponse(
        case_id=new_case.id,
        status=new_case.status,
        file_name=new_case.file_name,
        file_size_bytes=new_case.file_size_bytes,
        sha256=new_case.sha256_hash,
        created_at=new_case.created_at,
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
