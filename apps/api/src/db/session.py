from collections.abc import Generator
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from src.core.config import settings
from src.core.logging import logger


def build_engine(database_url: str) -> tuple[Engine, dict[str, Any]]:
    """Constructs a SQLAlchemy engine configured for the database dialect."""
    connect_args = {}
    engine_kwargs: dict[str, Any] = {
        "pool_pre_ping": True,
    }

    if database_url.startswith("sqlite"):
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

    eng = create_engine(
        database_url,
        connect_args=connect_args,
        **engine_kwargs,
    )
    return eng, connect_args


def initialize_engine() -> Engine:
    """Initializes the primary database engine with graceful fallback in development."""
    target_url = settings.DATABASE_URL

    # In development mode, check PostgreSQL connectivity and fall back to SQLite if unreachable
    if settings.ENVIRONMENT == "development" and not target_url.startswith("sqlite"):
        try:
            eng, _ = build_engine(target_url)
            with eng.connect() as conn:
                conn.execute(text("SELECT 1"))
            logger.info(
                f"Connected to PostgreSQL database [{settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT}]"
            )
            return eng
        except Exception as exc:
            dev_db_dir = Path("storage")
            dev_db_dir.mkdir(parents=True, exist_ok=True)
            fallback_url = "sqlite:///storage/threattrace_dev.db"
            logger.warning(
                f"PostgreSQL connection to {settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT} failed ({exc}). "
                f"Falling back to local development database ({fallback_url}). "
                "Start PostgreSQL service for production parity."
            )
            fallback_eng, _ = build_engine(fallback_url)
            return fallback_eng

    eng, _ = build_engine(target_url)
    return eng


engine = initialize_engine()
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
