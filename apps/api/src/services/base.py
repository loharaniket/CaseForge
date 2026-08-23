from sqlalchemy.orm import Session

from src.core.logging import logger


class BaseService:
    """Base service class providing database session lifecycle and logging."""

    def __init__(self, db: Session | None = None) -> None:
        self.db = db
        self.logger = logger
