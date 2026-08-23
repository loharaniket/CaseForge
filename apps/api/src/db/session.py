from collections.abc import Generator

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from src.core.config import settings
from src.core.logging import logger

connect_args = {}
engine_kwargs = {
    "pool_pre_ping": True,
}

if settings.DATABASE_URL.startswith("sqlite"):
    connect_args["check_same_thread"] = False
else:
    connect_args["connect_timeout"] = settings.POSTGRES_CONNECT_TIMEOUT
    engine_kwargs.update(
        {
            "pool_size": settings.POSTGRES_POOL_SIZE,
            "max_overflow": settings.POSTGRES_MAX_OVERFLOW,
            "pool_timeout": settings.POSTGRES_POOL_TIMEOUT,
        }
    )

engine = create_engine(
    settings.DATABASE_URL,
    connect_args=connect_args,
    **engine_kwargs,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency for database session lifecycle."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_db_connection(session: Session | None = None) -> bool:
    """Verifies active connectivity to the configured database."""
    try:
        if session is not None:
            session.execute(text("SELECT 1"))
            return True
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.warning(f"Database connectivity check failed: {exc}")
        return False
