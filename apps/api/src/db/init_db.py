"""Database initialization and development seeding routine."""

from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.logging import logger
from src.core.security import hash_password
from src.db.base import Base
from src.db.session import SessionLocal, engine
import src.models  # Ensure all models are registered on Base.metadata
from src.models.user import User, UserRole


def init_db() -> None:
    """Ensures database schema exists and seeds initial administrative/analyst users."""
    try:
        # Ensure storage directory exists
        Path("storage").mkdir(parents=True, exist_ok=True)
        Path("storage/evidence").mkdir(parents=True, exist_ok=True)

        # Create all model tables if they do not exist
        Base.metadata.create_all(bind=engine)

        db: Session = SessionLocal()
        try:
            # Check if default analyst exists
            analyst_query = select(User).where(User.email == "analyst@threattrace.io")
            analyst = db.execute(analyst_query).scalar_one_or_none()
            if not analyst:
                analyst = User(
                    email="analyst@threattrace.io",
                    full_name="SOC Analyst",
                    hashed_password=hash_password("Password123!"),
                    role=UserRole.ANALYST,
                    is_active=True,
                )
                db.add(analyst)
                logger.info(
                    "Seeded default development analyst user: analyst@threattrace.io (Password123!)"
                )

            # Check if default admin exists
            admin_query = select(User).where(User.email == "admin@threattrace.io")
            admin = db.execute(admin_query).scalar_one_or_none()
            if not admin:
                admin = User(
                    email="admin@threattrace.io",
                    full_name="System Administrator",
                    hashed_password=hash_password("AdminPass123!"),
                    role=UserRole.ADMIN,
                    is_active=True,
                )
                db.add(admin)
                logger.info(
                    "Seeded default development admin user: admin@threattrace.io (AdminPass123!)"
                )

            db.commit()
        finally:
            db.close()

    except Exception as exc:
        logger.warning(f"Database schema initialization notice: {exc}")
