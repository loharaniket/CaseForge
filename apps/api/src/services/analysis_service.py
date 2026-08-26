from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.models.analysis import AnalysisHistory


class AnalysisHistoryService:
    """Service for appending to the analysis event history."""

    def record_analysis(
        self,
        case_id: str,
        result_status: str,
        parser_version: str | None = None,
        detector_version: str | None = None,
        intel_provider: str | None = None,
        provider_lookup_timestamp: datetime | None = None,
        db: Session | None = None,
    ) -> None:
        """Appends a new analysis event to the history."""
        if db is None:
            return

        now = datetime.now(UTC)
        record = AnalysisHistory(
            case_id=case_id,
            analysis_timestamp=now,
            parser_version=parser_version,
            detector_version=detector_version,
            intel_provider=intel_provider,
            provider_lookup_timestamp=provider_lookup_timestamp,
            result_status=result_status,
        )
        db.add(record)
        # Assuming calling services handle the main commit, but we commit if needed, 
        # or we just flush/add to session so it commits with the transaction.
        # It's better to just db.add(record) and rely on the caller's db.commit().
        # However, to be safe:
        db.flush()

    def get_case_analysis_history(self, case_id: str, db: Session) -> list[AnalysisHistory]:
        """Retrieves all analysis history records for a case."""
        return list(
            db.execute(
                select(AnalysisHistory)
                .where(AnalysisHistory.case_id == case_id)
                .order_by(AnalysisHistory.analysis_timestamp.desc())
            )
            .scalars()
            .all()
        )


default_analysis_service = AnalysisHistoryService()


def get_analysis_history_service() -> AnalysisHistoryService:
    """FastAPI dependency injector for AnalysisHistoryService."""
    return default_analysis_service
