import pytest
from unittest.mock import MagicMock

from src.models.case import Case
from src.models.conclusion import InvestigationConclusion
from src.models.threat import ThreatAssessment
from src.models.risk import RiskAssessment
from src.models.forensics import HeaderForensics
from src.services.conclusion.engine import ConclusionEngineService

@pytest.fixture
def mock_db():
    return MagicMock()

@pytest.fixture
def engine():
    intel_mock = MagicMock()
    geo_mock = MagicMock()
    return ConclusionEngineService(intel_service=intel_mock, geoip_service=geo_mock)

def _setup_mock_db(mock_db, threat_class, score, spf="pass", dmarc="pass"):
    case = Case(id="test_case")
    threat = ThreatAssessment(case_id="test_case", classification=threat_class, confidence=0.9, reasons=["Reason 1"])
    risk = RiskAssessment(case_id="test_case", total_score=score, severity="HIGH")
    forensics = HeaderForensics(case_id="test_case", spf_status=spf, dmarc_status=dmarc, probable_origin_ip="1.2.3.4")

    def execute_side_effect(stmt):
        mock_result = MagicMock()
        # Very simple mock matching for this test context based on model class name strings inside stmt.
        stmt_str = str(stmt).lower()
        if "investigation_conclusions" in stmt_str:
            mock_result.scalar_one_or_none.return_value = None
        elif "cases" in stmt_str:
            mock_result.scalar_one_or_none.return_value = case
        elif "threat_assessments" in stmt_str:
            mock_result.scalar_one_or_none.return_value = threat
        elif "risk_assessments" in stmt_str:
            mock_result.scalar_one_or_none.return_value = risk
        elif "header_forensics" in stmt_str:
            mock_result.scalar_one_or_none.return_value = forensics
        else:
            mock_result.scalars().all.return_value = []
        return mock_result

    mock_db.execute.side_effect = execute_side_effect


def test_conclusion_engine_legitimate(mock_db, engine):
    _setup_mock_db(mock_db, "NORMAL", 10.0)
    conclusion = engine.generate_conclusion("test_case", mock_db)
    
    assert conclusion.classification == "LEGITIMATE"
    assert conclusion.risk_score == 10.0
    assert conclusion.confidence == 0.9

def test_conclusion_engine_phishing(mock_db, engine):
    _setup_mock_db(mock_db, "PHISHING", 85.0, spf="fail", dmarc="fail")
    conclusion = engine.generate_conclusion("test_case", mock_db)
    
    assert conclusion.classification == "PHISHING"
    assert conclusion.risk_score == 85.0
    assert any("fail" in f.lower() for f in conclusion.primary_findings)

def test_conclusion_engine_bec(mock_db, engine):
    _setup_mock_db(mock_db, "BEC", 90.0)
    conclusion = engine.generate_conclusion("test_case", mock_db)
    
    assert conclusion.classification == "BUSINESS_EMAIL_COMPROMISE"
    assert conclusion.risk_score == 90.0
    assert conclusion.probable_infrastructure == "IP 1.2.3.4" # Default fallback when geo fails or empty
    assert "Origin cannot be conclusively attributed to a human actor." in conclusion.attribution_assessment
