from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.security import hash_password
from src.models.case import Case, CaseStatus
from src.models.ioc import CaseIOC
from src.models.user import User, UserRole
from src.services.ioc.extractor import IOCExtractor
from src.services.ioc.service import IOCService
from src.services.ioc.types import IOCType
from src.services.parser.eml_parser import EMLParser
from src.services.parser_service import ParserService
from src.services.storage import LocalEvidenceStorage

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def extractor() -> IOCExtractor:
    return IOCExtractor()


def test_extract_all_supported_ioc_types(extractor: IOCExtractor):
    """Verify extraction of all 6 IOC types: ipv4, ipv6, domain, url, email, sha256."""
    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = extractor.extract_from_email_data(parsed)

    assert result.total_count > 0
    types_found = {ioc.type for ioc in result.iocs}

    assert IOCType.IPV4 in types_found
    assert IOCType.IPV6 in types_found
    assert IOCType.DOMAIN in types_found
    assert IOCType.URL in types_found
    assert IOCType.EMAIL in types_found
    assert IOCType.SHA256 in types_found

    # Verify specific indicators
    values = {ioc.value for ioc in result.iocs}
    assert "198.51.100.200" in values
    assert "203.0.113.88" in values
    assert "2001:db8::1" in values
    assert "2001:db8:85a3::8a2e:370:7334" in values
    assert "admin@security-ops.com" in values
    assert "phisher-drop@dark-web.org" in values
    assert "mail.attacker-infra.com" in values
    assert "phish-login.attacker-infra.com" in values
    assert "security-ops.com" in values
    assert "https://phish-login.attacker-infra.com/login?session=123" in values
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in values


def test_ioc_deduplication(extractor: IOCExtractor):
    """Verify identical indicators mentioned repeatedly in headers and body are deduplicated."""
    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = extractor.extract_from_email_data(parsed)

    # Check for duplicate values per type
    pairs = [(ioc.type, ioc.value) for ioc in result.iocs]
    assert len(pairs) == len(set(pairs))

    # admin@security-ops.com is in From and body text, must appear only once as EMAIL
    admin_emails = [
        i for i in result.iocs if i.type == IOCType.EMAIL and i.value == "admin@security-ops.com"
    ]
    assert len(admin_emails) == 1

    # 198.51.100.200 is in Received header and body, must appear only once as IPV4
    ip_matches = [i for i in result.iocs if i.type == IOCType.IPV4 and i.value == "198.51.100.200"]
    assert len(ip_matches) == 1


def test_ioc_normalization(extractor: IOCExtractor):
    """Verify values are normalized to lowercase canonical formats."""
    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = extractor.extract_from_email_data(parsed)

    for ioc in result.iocs:
        # Lowercase check
        if ioc.type in (IOCType.EMAIL, IOCType.DOMAIN, IOCType.SHA256):
            assert ioc.value == ioc.value.lower()
        # No angle brackets or quotes
        assert "<" not in ioc.value and ">" not in ioc.value
        assert '"' not in ioc.value and "'" not in ioc.value
        # No trailing punctuation
        if ioc.type == IOCType.IPV6:
            assert not ioc.value.endswith((".", ",", ";"))
        else:
            assert not ioc.value.endswith((".", ",", ";", ":"))


def test_malformed_indicators_ignored(extractor: IOCExtractor):
    """Verify malformed IPs, broken emails, invalid URLs, and short hashes are ignored."""
    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = extractor.extract_from_email_data(parsed)
    values = {ioc.value for ioc in result.iocs}

    assert "999.999.999.999" not in values
    assert "broken_email@" not in values
    assert "http://" not in values
    assert "short_hash_1234567890abcdef" not in values


def test_attachment_sha256_extraction(extractor: IOCExtractor):
    """Verify attachment sha256 hash is extracted with confidence 1.0."""
    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = extractor.extract_from_email_data(parsed)

    assert len(parsed.attachments) == 1
    att_sha = parsed.attachments[0].sha256

    sha_iocs = [i for i in result.iocs if i.type == IOCType.SHA256 and i.value == att_sha]
    assert len(sha_iocs) == 1
    assert sha_iocs[0].confidence == 1.0
    assert "attachment" in sha_iocs[0].source


def test_ioc_db_persistence_and_idempotency(db_session: Session, tmp_path: Path):
    """Verify IOCs are persisted in PostgreSQL and idempotent on repeated requests."""
    user = User(
        email="ioc.analyst@threattrace.io",
        hashed_password=hash_password("IocPass123!"),
        full_name="IOC Analyst",
        role=UserRole.ANALYST,
        is_active=True,
    )
    db_session.add(user)
    db_session.commit()

    storage = LocalEvidenceStorage(base_dir=str(tmp_path / "evidence"))
    eml_bytes = (FIXTURES_DIR / "ioc_comprehensive.eml").read_bytes()
    storage_key, sha256_hash = storage.save(eml_bytes, "ioc_test.eml")

    case = Case(
        user_id=user.id,
        file_name="ioc_test.eml",
        file_size_bytes=len(eml_bytes),
        sha256_hash=sha256_hash,
        storage_key=storage_key,
        status=CaseStatus.UPLOADED,
    )
    db_session.add(case)
    db_session.commit()

    parser_service = ParserService(parser=EMLParser(), storage=storage)
    ioc_service = IOCService(extractor=IOCExtractor(), parser_service=parser_service)

    # First run
    records = ioc_service.extract_case_iocs(case.id, db_session)
    assert len(records) > 0
    first_ids = [r.id for r in records]

    # Second run (idempotent)
    second_records = ioc_service.get_case_iocs(case.id, db_session)
    assert [r.id for r in second_records] == first_ids

    # Query DB directly
    db_records = (
        db_session.execute(select(CaseIOC).where(CaseIOC.case_id == case.id)).scalars().all()
    )
    assert len(db_records) == len(records)
