import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import NotFoundError
from src.models.case import Case
from src.models.user import User, UserRole

logger = logging.getLogger("threattrace")


class CaseAccessService:
    """Centralized authorization service for investigation cases.

    Analyst Authorization Rule:
    - An analyst can view, analyze, extract, generate reports for, and verify evidence for their own cases.
    - An analyst CANNOT view or modify cases owned by another analyst.

    Administrator Authorization Rule:
    - Administrators (UserRole.ADMIN) have SOC-wide visibility and can access any case across users.

    Security & Privacy Policy:
    - Unauthorized access attempts consistently return 404 (Not Found) rather than 403 to prevent
      malicious callers from discovering or enumerating case IDs owned by other analysts.
    """

    @classmethod
    def get_case_for_user(cls, case_id: str, user: User, db: Session) -> Case:
        """Retrieves a case verifying user authorization.

        Raises NotFoundError if the case does not exist or if the requesting user
        is not authorized to view it.
        """
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        if user.role != UserRole.ADMIN and case.user_id != user.id:
            logger.warning(
                f"Unauthorized case access attempt: User '{user.email}' (id={user.id}, role={user.role}) "
                f"attempted to access case '{case_id}' owned by user_id={case.user_id}."
            )
            # Consistent 404 Not Found prevents case ID enumeration
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        return case

    @classmethod
    def assert_can_view_case(cls, case_id: str, user: User, db: Session) -> Case:
        """Asserts that the user has read authorization for the case."""
        return cls.get_case_for_user(case_id=case_id, user=user, db=db)

    @classmethod
    def assert_can_modify_case(cls, case_id: str, user: User, db: Session) -> Case:
        """Asserts that the user has write/mutation authorization for the case."""
        return cls.get_case_for_user(case_id=case_id, user=user, db=db)


default_case_access_service = CaseAccessService()


def get_case_access_service() -> CaseAccessService:
    """Dependency provider for CaseAccessService."""
    return default_case_access_service
