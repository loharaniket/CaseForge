import logging
import asyncio
from sqlalchemy.orm import Session

from src.db.session import SessionLocal
from src.models.case import Case, AnalysisStatus

from src.services.parser_service import get_parser_service
from src.services.forensics.service import get_forensics_service
from src.services.ioc.service import get_ioc_service
from src.services.intel.service import get_intel_service
from src.services.geo.service import get_geoip_service
from src.services.detection_service import get_detection_service
from src.services.risk.service import get_risk_service
from src.services.timeline.service import get_timeline_service
from src.services.graph.service import get_graph_service
from src.services.conclusion.engine import get_conclusion_engine

logger = logging.getLogger(__name__)

async def run_background_analysis(case_id: str) -> None:
    """Orchestrates the entire investigation workflow sequentially in the background."""
    db: Session = SessionLocal()
    try:
        case = db.query(Case).filter(Case.id == case_id).first()
        if not case:
            return

        def update_status(status: str, step: str):
            case.analysis_status = status
            case.analysis_step = step
            db.commit()

        # Phase 1: Parsing
        update_status(AnalysisStatus.PROCESSING, "Parsing evidence")
        parser_service = get_parser_service()
        parser_service.parse_case(case_id=case_id, db=db)
        
        # Phase 2: Authentication & Forensics
        update_status(AnalysisStatus.PROCESSING, "Checking authentication")
        forensics_service = get_forensics_service()
        forensics_service.analyze_case(case_id=case_id, db=db)
        
        # Phase 3: Extraction
        update_status(AnalysisStatus.PROCESSING, "Extracting indicators")
        ioc_service = get_ioc_service()
        ioc_service.extract_case_iocs(case_id=case_id, db=db)
        
        # Phase 4: Intelligence & Geo (These can safely fail resulting in PARTIAL)
        update_status(AnalysisStatus.PROCESSING, "Checking infrastructure")
        intel_service = get_intel_service()
        geoip_service = get_geoip_service()
        
        partial = False
        try:
            await intel_service.analyze_case_indicators(case_id=case_id, db=db)
        except Exception as e:
            logger.warning(f"Threat Intel service failed for {case_id}: {e}")
            partial = True
            
        try:
            geoip_service.analyze_case_infrastructure(case_id=case_id, db=db)
        except Exception as e:
            logger.warning(f"GeoIP service failed for {case_id}: {e}")
            partial = True
            
        # Phase 5: Detection, Risk, Timeline, and Graph
        update_status(AnalysisStatus.PROCESSING, "Building investigation")
        detection_service = get_detection_service()
        detection_service.analyze_case(case_id=case_id, db=db)
        
        risk_service = get_risk_service()
        risk_service.calculate_case_risk(case_id=case_id, db=db)
        
        timeline_service = get_timeline_service()
        timeline_service.build_case_timeline(case_id=case_id, db=db)
        
        graph_service = get_graph_service()
        graph_service.get_case_graph(case_id=case_id, db=db)
        
        # Phase 6: Conclusion
        update_status(AnalysisStatus.PROCESSING, "Generating conclusion")
        conclusion_engine = get_conclusion_engine()
        conclusion_engine.generate_conclusion(case_id=case_id, db=db)
        
        # Finish
        final_status = AnalysisStatus.PARTIAL if partial else AnalysisStatus.COMPLETED
        update_status(final_status, "Ready")
        
    except Exception as e:
        logger.error(f"Background analysis failed for case {case_id}: {e}", exc_info=True)
        try:
            case = db.query(Case).filter(Case.id == case_id).first()
            if case:
                case.analysis_status = AnalysisStatus.FAILED
                case.analysis_step = "Analysis failed"
                case.error_message = str(e)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()
