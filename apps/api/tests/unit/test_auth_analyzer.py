from pathlib import Path

import pytest

from src.services.forensics.auth_analyzer import (
    AuthStatus,
    EmailAuthenticationAnalyzer,
    normalize_auth_status,
)
from src.services.parser.eml_parser import EMLParser

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


@pytest.fixture
def analyzer() -> EmailAuthenticationAnalyzer:
    return EmailAuthenticationAnalyzer()


def test_auth_status_normalization_mapping():
    """Verify all granular RFC states map to standard 5-tier classification."""
    assert normalize_auth_status(AuthStatus.PASS) == "pass"
    assert normalize_auth_status(AuthStatus.FAIL) == "fail"
    assert normalize_auth_status(AuthStatus.SOFTFAIL) == "fail"
    assert normalize_auth_status(AuthStatus.PERMERROR) == "fail"
    assert normalize_auth_status(AuthStatus.TEMPERROR) == "fail"
    assert normalize_auth_status(AuthStatus.NEUTRAL) == "neutral"
    assert normalize_auth_status(AuthStatus.NONE) == "none"
    assert normalize_auth_status(AuthStatus.UNKNOWN) == "unknown"


def test_auth_analyzer_all_supported_pass_states(analyzer: EmailAuthenticationAnalyzer):
    """Verify valid pass states for SPF, DKIM, and DMARC."""
    eml_bytes = (FIXTURES_DIR / "multi_hop_relay.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = analyzer.analyze_authentication(parsed.raw_headers)

    assert result.spf.status == AuthStatus.PASS
    assert result.spf.normalized_status == "pass"
    assert result.dkim.status == AuthStatus.PASS
    assert result.dkim.normalized_status == "pass"
    assert result.dmarc.status == AuthStatus.PASS
    assert result.dmarc.normalized_status == "pass"
    assert result.overall_posture == "VALIDATED"


def test_auth_analyzer_all_supported_fail_states(analyzer: EmailAuthenticationAnalyzer):
    """Verify fail states for SPF, DKIM, and DMARC."""
    eml_bytes = (FIXTURES_DIR / "auth_failures_spf_dkim_dmarc.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = analyzer.analyze_authentication(parsed.raw_headers)

    assert result.spf.status == AuthStatus.FAIL
    assert result.spf.normalized_status == "fail"
    assert result.dkim.status == AuthStatus.FAIL
    assert result.dkim.normalized_status == "fail"
    assert result.dmarc.status == AuthStatus.FAIL
    assert result.dmarc.normalized_status == "fail"
    assert result.overall_posture == "FAILED"


def test_auth_analyzer_neutral_and_none_states(analyzer: EmailAuthenticationAnalyzer):
    """Verify neutral and none states."""
    eml_bytes = (FIXTURES_DIR / "auth_spf_neutral.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = analyzer.analyze_authentication(parsed.raw_headers)

    assert result.spf.status == AuthStatus.NEUTRAL
    assert result.spf.normalized_status == "neutral"
    assert result.dkim.status == AuthStatus.NONE
    assert result.dkim.normalized_status == "none"
    assert result.dmarc.status == AuthStatus.NONE
    assert result.dmarc.normalized_status == "none"


def test_auth_analyzer_evidence_and_provenance_extraction(analyzer: EmailAuthenticationAnalyzer):
    """Verify extracted domain, selector, sender IP, source header, and evidence string."""
    eml_bytes = (FIXTURES_DIR / "auth_multi_auth_results.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = analyzer.analyze_authentication(parsed.raw_headers)

    # SPF evidence
    assert result.spf.domain == "trusted-vendor.com"
    assert result.spf.sender_ip == "192.0.2.88"
    assert result.spf.source_header == "authentication-results"
    assert "spf=pass" in (result.spf.evidence or "")

    # DKIM evidence
    assert result.dkim.domain == "trusted-vendor.com"
    assert result.dkim.selector == "s2026"
    assert "dkim=pass" in (result.dkim.evidence or "")

    # DMARC evidence
    assert result.dmarc.domain == "trusted-vendor.com"
    assert "dmarc=pass" in (result.dmarc.evidence or "")


def test_auth_analyzer_multiple_headers_resolution(analyzer: EmailAuthenticationAnalyzer):
    """Verify multiple Authentication-Results headers are resolved deterministically."""
    eml_bytes = (FIXTURES_DIR / "auth_multi_auth_results.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = analyzer.analyze_authentication(parsed.raw_headers)

    assert len(result.source_headers_found) >= 2
    assert result.spf.status == AuthStatus.PASS
    assert result.dkim.status == AuthStatus.PASS
    assert result.dmarc.status == AuthStatus.PASS


def test_auth_analyzer_malformed_headers_resilience(analyzer: EmailAuthenticationAnalyzer):
    """Verify malformed headers safely return unknown without throwing uncaught exceptions."""
    eml_bytes = (FIXTURES_DIR / "auth_malformed_headers.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = analyzer.analyze_authentication(parsed.raw_headers)

    assert result.spf.status == AuthStatus.UNKNOWN
    assert result.spf.normalized_status == "unknown"
    assert result.dkim.status in (AuthStatus.UNKNOWN, AuthStatus.NONE)
    assert result.dmarc.status == AuthStatus.UNKNOWN


def test_auth_analyzer_missing_all_headers(analyzer: EmailAuthenticationAnalyzer):
    """Verify email with zero auth headers deterministically reports unauthenticated/none."""
    eml_bytes = (FIXTURES_DIR / "auth_missing_all.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = analyzer.analyze_authentication(parsed.raw_headers)

    assert result.spf.status == AuthStatus.UNKNOWN
    assert result.dkim.status == AuthStatus.NONE
    assert result.dmarc.status == AuthStatus.UNKNOWN
    assert result.overall_posture == "UNAUTHENTICATED"
    assert len(result.source_headers_found) == 0


def test_auth_analyzer_human_explanations_populated(analyzer: EmailAuthenticationAnalyzer):
    """Verify clear, human-auditable explanations are produced for all protocols."""
    eml_bytes = (FIXTURES_DIR / "spoofed_return_path.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    result = analyzer.analyze_authentication(parsed.raw_headers)

    assert len(result.explanations) == 3
    assert any("SPF" in exp for exp in result.explanations)
    assert any("DKIM" in exp for exp in result.explanations)
    assert any("DMARC" in exp for exp in result.explanations)
