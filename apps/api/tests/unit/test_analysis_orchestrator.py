import pytest
import asyncio
from unittest.mock import patch, MagicMock, AsyncMock

from src.models.case import Case, AnalysisStatus
from src.services.analysis_orchestrator import run_background_analysis

@pytest.mark.asyncio
async def test_run_background_analysis_success(db_session):
    # Setup test case
    case = Case(
        id="test-case-123",
        user_id=1,
        file_name="test.eml",
        file_size_bytes=100,
        sha256_hash="test-hash",
        storage_key="test/key",
        status="UPLOADED",
        analysis_status=AnalysisStatus.QUEUED,
        analysis_step="Pending"
    )
    db_session.add(case)
    db_session.commit()

    with patch("src.services.analysis_orchestrator.SessionLocal", return_value=db_session), \
         patch("src.services.analysis_orchestrator.get_parser_service") as mock_parser, \
         patch("src.services.analysis_orchestrator.get_forensics_service") as mock_forensics, \
         patch("src.services.analysis_orchestrator.get_ioc_service") as mock_ioc, \
         patch("src.services.analysis_orchestrator.get_intel_service") as mock_intel, \
         patch("src.services.analysis_orchestrator.get_geoip_service") as mock_geoip, \
         patch("src.services.analysis_orchestrator.get_detection_service") as mock_detection, \
         patch("src.services.analysis_orchestrator.get_risk_service") as mock_risk, \
         patch("src.services.analysis_orchestrator.get_timeline_service") as mock_timeline, \
         patch("src.services.analysis_orchestrator.get_graph_service") as mock_graph, \
         patch("src.services.analysis_orchestrator.get_conclusion_engine") as mock_conclusion, \
         patch.object(db_session, "close"):
        
        mock_intel.return_value.analyze_case_indicators = AsyncMock()
        await run_background_analysis(case.id)

        # Ensure all services were called
        assert mock_parser.called
        assert mock_forensics.called
        assert mock_ioc.called
        assert mock_intel.called
        assert mock_geoip.called
        assert mock_detection.called
        assert mock_risk.called
        assert mock_timeline.called
        assert mock_graph.called
        assert mock_conclusion.called

        # Ensure status is COMPLETED
        db_session.refresh(case)
        assert case.analysis_status == AnalysisStatus.COMPLETED
        assert case.analysis_step == "Ready"


@pytest.mark.asyncio
async def test_run_background_analysis_partial_on_intel_failure(db_session):
    # Setup test case
    case = Case(
        id="test-case-456",
        user_id=1,
        file_name="test.eml",
        file_size_bytes=100,
        sha256_hash="test-hash",
        storage_key="test/key",
        status="UPLOADED",
        analysis_status=AnalysisStatus.QUEUED,
        analysis_step="Pending"
    )
    db_session.add(case)
    db_session.commit()

    with patch("src.services.analysis_orchestrator.SessionLocal", return_value=db_session), \
         patch("src.services.analysis_orchestrator.get_parser_service"), \
         patch("src.services.analysis_orchestrator.get_forensics_service"), \
         patch("src.services.analysis_orchestrator.get_ioc_service"), \
         patch("src.services.analysis_orchestrator.get_intel_service") as mock_intel, \
         patch("src.services.analysis_orchestrator.get_geoip_service"), \
         patch("src.services.analysis_orchestrator.get_detection_service"), \
         patch("src.services.analysis_orchestrator.get_risk_service"), \
         patch("src.services.analysis_orchestrator.get_timeline_service"), \
         patch("src.services.analysis_orchestrator.get_graph_service"), \
         patch("src.services.analysis_orchestrator.get_conclusion_engine"), \
         patch.object(db_session, "close"):
        
        # Simulate Intel Service Failure
        mock_intel.return_value.analyze_case_indicators.side_effect = Exception("API Timeout")

        await run_background_analysis(case.id)

        db_session.refresh(case)
        assert case.analysis_status == AnalysisStatus.PARTIAL
        assert case.analysis_step == "Ready"


@pytest.mark.asyncio
async def test_run_background_analysis_failed_on_critical_failure(db_session):
    # Setup test case
    case = Case(
        id="test-case-789",
        user_id=1,
        file_name="test.eml",
        file_size_bytes=100,
        sha256_hash="test-hash",
        storage_key="test/key",
        status="UPLOADED",
        analysis_status=AnalysisStatus.QUEUED,
        analysis_step="Pending"
    )
    db_session.add(case)
    db_session.commit()

    with patch("src.services.analysis_orchestrator.SessionLocal", return_value=db_session), \
         patch("src.services.analysis_orchestrator.get_parser_service") as mock_parser, \
         patch.object(db_session, "close"):
        
        # Simulate Critical Parsing Failure
        mock_parser.return_value.parse_case.side_effect = Exception("Critical Error")

        await run_background_analysis(case.id)

        db_session.refresh(case)
        assert case.analysis_status == AnalysisStatus.FAILED
        assert case.analysis_step == "Analysis failed"
        assert "Critical Error" in case.error_message
