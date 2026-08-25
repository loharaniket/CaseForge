import pytest
from src.services.detector.types import ThreatCategory
from src.services.detector.extended import extended_detector
from types import SimpleNamespace
from src.models.email import ParsedEmail

def test_legitimate_email():
    email = SimpleNamespace(
        subject="Weekly Project Update",
        body_plain="Here is the status report for this week.",
        sender="bob@legit.com",
        from_name="Bob Smith",
        reply_to=["bob@legit.com"],
        auth_details={"spf_status": "pass", "dkim_status": "pass"},
        url_intel=[],
        extracted_urls=[]
    )
    result = extended_detector.detect(email)
    assert result.classification == ThreatCategory.NORMAL
    assert not any(s.get("severity") in ("CRITICAL", "HIGH") for s in result.signals_detected.get("structured_signals", []))

def test_phishing_email():
    email = SimpleNamespace(
        subject="Account Suspended",
        body_plain="Your account will be suspended. Verify your identity immediately.",
        sender="admin@spoofer.com",
        from_name="Support",
        reply_to=["admin@spoofer.com"],
        auth_details={"spf_status": "fail", "dkim_status": "fail"},
        url_intel=[],
        extracted_urls=[]
    )
    result = extended_detector.detect(email)
    assert result.classification == ThreatCategory.PHISHING
    signals = result.signals_detected.get("structured_signals", [])
    assert any(s.get("signal") == "AUTH_FAILURE" for s in signals)
    assert any(s.get("signal") == "CREDENTIAL_THEFT_LURE" for s in signals)

def test_executive_impersonation():
    email = SimpleNamespace(
        subject="Urgent Favor",
        body_plain="I am in a meeting, need you to handle a confidential request.",
        sender="ceo@external-mail.com",
        from_name="CEO John Doe",
        reply_to=["ceo@external-mail.com"],
        auth_details={},
        url_intel=[],
        extracted_urls=[]
    )
    result = extended_detector.detect(email)
    signals = result.signals_detected.get("structured_signals", [])
    assert any(s.get("signal") == "BEC_INDICATORS_PRESENT" for s in signals)
    assert result.classification == ThreatCategory.BEC

def test_bec_payment_request():
    email = SimpleNamespace(
        subject="Overdue Invoice Transfer",
        body_plain="Please process a wire transfer to our new bank account today.",
        sender="vendor@partner.com",
        from_name="Vendor Finance",
        reply_to=["vendor-fraud@attacker.com"],
        auth_details={},
        url_intel=[],
        extracted_urls=[]
    )
    result = extended_detector.detect(email)
    assert result.classification == ThreatCategory.BEC
    signals = result.signals_detected.get("structured_signals", [])
    assert any(s.get("signal") == "BEC_INDICATORS_PRESENT" for s in signals)
    assert any(s.get("signal") == "REPLY_TO_MISMATCH" for s in signals)

def test_credential_harvesting():
    url_mock = SimpleNamespace(raw_url="http://lookalike-microsoft.com/login", has_credential_path=True, is_lookalike=True)
    email = SimpleNamespace(
        subject="Confirm login",
        body_plain="Reset your credentials here.",
        sender="no-reply@lookalike.com",
        from_name="Security",
        reply_to=["no-reply@lookalike.com"],
        auth_details={},
        url_intel=[url_mock],
        extracted_urls=["http://lookalike-microsoft.com/login"]
    )
    result = extended_detector.detect(email)
    assert result.classification == ThreatCategory.PHISHING
    signals = result.signals_detected.get("structured_signals", [])
    assert any(s.get("signal") == "CREDENTIAL_PATH_URL" for s in signals)

def test_false_positive_legitimate_financial_email():
    email = SimpleNamespace(
        subject="Invoice #1234 Attached",
        body_plain="Please see the attached invoice for this month's software subscription. The swift code is XYZ.",
        sender="billing@saas.com",
        from_name="SaaS Billing",
        reply_to=["billing@saas.com"],
        auth_details={"spf_status": "pass", "dkim_status": "pass"},
        url_intel=[],
        extracted_urls=[]
    )
    result = extended_detector.detect(email)
    # The heuristic might flag FINANCIAL_FRAUD_TERMS (Medium severity)
    # But classification should remain NORMAL because no CRITICAL/HIGH signals are present 
    # to elevate it if the base heuristic didn't trigger an upgrade.
    signals = result.signals_detected.get("structured_signals", [])
    assert any(s.get("signal") == "FINANCIAL_FRAUD_TERMS" for s in signals)
    assert result.classification == ThreatCategory.NORMAL
