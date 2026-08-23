import hashlib
from pathlib import Path

from src.services.parser.eml_parser import EMLParser

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


def test_parse_normal_email():
    """Verify clean plain-text corporate email parsing."""
    eml_bytes = (FIXTURES_DIR / "normal_email.eml").read_bytes()
    parser = EMLParser()
    result = parser.parse(eml_bytes)

    assert result.from_name == "John Doe"
    assert result.from_address == "john.doe@example.com"
    assert "Jane Smith <jane.smith@example.com>" in result.recipients
    assert "Audit <audit@example.com>" in result.cc
    assert result.subject == "Q3 Security Review and Roadmap"
    assert result.message_id == "q3-security-20260824@example.com"
    assert result.date_parsed is not None
    assert "Attached is our schedule" in (result.body_plain or "")
    assert "https://internal.example.com/sec-roadmap" in result.extracted_urls
    assert len(result.attachments) == 0


def test_parse_phishing_email():
    """Verify phishing email with multiple C2 URLs and urgency headers."""
    eml_bytes = (FIXTURES_DIR / "phishing_email.eml").read_bytes()
    parser = EMLParser()
    result = parser.parse(eml_bytes)

    assert "IT Support Helpdesk" in (result.from_name or "")
    assert "security-alerts@suspicious-domain-phish.com" in (result.from_address or "")
    assert "harvest@attacker-c2.net" in result.reply_to
    assert "URGENT" in (result.subject or "")
    assert (
        "http://login.suspicious-domain-phish.com/auth/verify?session=99a8b7c6"
        in result.extracted_urls
    )
    assert "http://backup-c2.attacker-c2.net/portal" in result.extracted_urls


def test_parse_html_email():
    """Verify HTML email parsing and href URL extraction."""
    eml_bytes = (FIXTURES_DIR / "html_email.eml").read_bytes()
    parser = EMLParser()
    result = parser.parse(eml_bytes)

    assert result.subject == "Exclusive 50% Off Flash Sale for Cybersecurity Professionals!"
    assert result.body_html is not None
    assert "<h1" in result.body_html
    assert (
        "https://promotions.retail-deals.org/claim-discount?ref=summer2026" in result.extracted_urls
    )
    assert "https://store.retail-deals.org" in result.extracted_urls


def test_parse_multipart_email():
    """Verify multipart alternative with plain text and HTML bodies."""
    eml_bytes = (FIXTURES_DIR / "multipart_email.eml").read_bytes()
    parser = EMLParser()
    result = parser.parse(eml_bytes)

    assert result.body_plain is not None
    assert result.body_html is not None
    assert "Production Cluster Status: OPTIMAL" in result.body_plain
    assert "https://metrics.cloud-infra.io/grafana/d/k8s-overview" in result.extracted_urls


def test_parse_attachment_email_and_sha256_hash():
    """Verify attachment metadata extraction and SHA-256 calculation without file execution."""
    eml_bytes = (FIXTURES_DIR / "attachment_email.eml").read_bytes()
    parser = EMLParser()
    result = parser.parse(eml_bytes)

    assert len(result.attachments) == 1
    att = result.attachments[0]
    assert att.filename == "invoice_august_2026.pdf"
    assert att.extension == ".pdf"
    assert att.content_type == "application/pdf"
    assert att.file_size_bytes > 0

    # Expected payload: b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    expected_payload = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n<<>>\n%%EOF"
    assert att.sha256 == hashlib.sha256(expected_payload).hexdigest()


def test_parse_malformed_email_resilience():
    """Verify that corrupt bytes and broken boundaries never raise uncaught exceptions."""
    eml_bytes = (FIXTURES_DIR / "malformed_email.eml").read_bytes()
    parser = EMLParser()
    result = parser.parse(eml_bytes)

    # Should safely return ParsedEmailData without crashing
    assert isinstance(result.extracted_urls, list)
    assert "http://malformed-embedded-link.com/payload" in result.extracted_urls


def test_parse_encoded_rfc2047_headers():
    """Verify RFC 2047 Base64 and Quoted-Printable multilingual header decoding."""
    eml_bytes = (FIXTURES_DIR / "encoded_headers.eml").read_bytes()
    parser = EMLParser()
    result = parser.parse(eml_bytes)

    # Decoded subject: "Alerta de Seguridad: Acceso no autorizado detectado"
    assert result.subject == "Alerta de Seguridad: Acceso no autorizado detectado"
    # Decoded display name: "Departamento de Seguridad"
    assert result.from_name == "Departamento de Seguridad"
    assert result.from_address == "seguridad@banco-verificacion.es"
    assert "https://banco-verificacion.es/portal/seguridad?token=es883910" in result.extracted_urls
