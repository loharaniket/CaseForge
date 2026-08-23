from pathlib import Path

from src.services.detector.rule_based import RuleBasedThreatDetector
from src.services.detector.types import ThreatCategory
from src.services.parser.eml_parser import EMLParser

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "emails"


def test_detect_normal_email():
    """Verify normal internal business email is categorized as NORMAL."""
    eml_bytes = (FIXTURES_DIR / "normal_email.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    detector = RuleBasedThreatDetector()
    result = detector.detect(parsed)

    assert result.classification == ThreatCategory.NORMAL
    assert result.confidence >= 0.85
    assert result.model_version == "rule-based-heuristic-v1.0.0-dev"
    assert len(result.reasons) >= 1
    assert "No active phishing" in result.reasons[0]


def test_detect_spam_email():
    """Verify sweepstakes/lottery email is categorized as SPAM."""
    eml_bytes = (FIXTURES_DIR / "spam_lottery_prize.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    detector = RuleBasedThreatDetector()
    result = detector.detect(parsed)

    assert result.classification == ThreatCategory.SPAM
    assert result.confidence >= 0.75
    assert any("sweepstakes" in r.lower() or "prize" in r.lower() for r in result.reasons)


def test_detect_phishing_email():
    """Verify urgent account suspension email is categorized as PHISHING."""
    eml_bytes = (FIXTURES_DIR / "phishing_email.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    detector = RuleBasedThreatDetector()
    result = detector.detect(parsed)

    assert result.classification == ThreatCategory.PHISHING
    assert result.confidence >= 0.80
    assert any(
        "suspension" in r.lower() or "threat" in r.lower() or "urgency" in r.lower()
        for r in result.reasons
    )


def test_detect_credential_phishing():
    """Verify password expiration credential harvesting email is categorized as PHISHING."""
    eml_bytes = (FIXTURES_DIR / "credential_phishing.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    detector = RuleBasedThreatDetector()
    result = detector.detect(parsed)

    assert result.classification == ThreatCategory.PHISHING
    assert result.confidence >= 0.85
    assert any(
        "credential harvesting" in r.lower() or "password" in r.lower() for r in result.reasons
    )
    assert any("Direct IP target" in r or "Suspicious URL" in r for r in result.reasons)


def test_detect_bec_email():
    """Verify executive wire transfer email is categorized as BEC."""
    eml_bytes = (FIXTURES_DIR / "bec_executive_wire.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    detector = RuleBasedThreatDetector()
    result = detector.detect(parsed)

    assert result.classification == ThreatCategory.BEC
    assert result.confidence >= 0.80
    assert any("remittance" in r.lower() or "wire" in r.lower() for r in result.reasons)
    assert any("executive" in r.lower() or "authority" in r.lower() for r in result.reasons)


def test_explainability_reasons_and_model_version():
    """Verify detector never returns empty reasons or missing model version."""
    eml_bytes = (FIXTURES_DIR / "html_email.eml").read_bytes()
    parsed = EMLParser().parse(eml_bytes)

    detector = RuleBasedThreatDetector()
    result = detector.detect(parsed)

    assert isinstance(result.reasons, list)
    assert len(result.reasons) > 0
    assert result.model_version.startswith("rule-based-heuristic")
    assert 0.0 <= result.confidence <= 1.0
