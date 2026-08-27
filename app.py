"""ThreatTrace AI — Single-Command Server Launcher & Database Initializer.

Usage:
    python app.py
"""
import os
import sys
from pathlib import Path

# Add apps/api to python path
root_dir = Path(__file__).resolve().parent
api_dir = root_dir / "apps" / "api"
sys.path.insert(0, str(api_dir))

# Import application components
from src.core.config import settings
from src.core.security import hash_password
from src.db.base import Base
from src.db.session import SessionLocal, check_db_connection, engine
import src.models  # Ensure all models are registered on Base.metadata
from src.models.user import User, UserRole


def setup_database():
    """Initializes database schema and seeds default credentials if necessary."""
    global engine, SessionLocal

    print("\n" + "=" * 60)
    print(" [ThreatTrace AI] Database Initialization & Pre-flight")
    print("=" * 60)

    # Check connection to configured database
    is_connected = check_db_connection()

    if not is_connected and "sqlite" not in settings.DATABASE_URL:
        sqlite_db_path = root_dir / "threattrace.db"
        sqlite_url = f"sqlite:///{sqlite_db_path}"
        print(f"\n[!] PostgreSQL is not running on {settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT}.")
        print(f"[+] Switching automatically to local SQLite database: {sqlite_db_path.name}")

        os.environ["DATABASE_URL"] = sqlite_url
        settings.DATABASE_URL = sqlite_url

        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker

        engine = create_engine(sqlite_url, connect_args={"check_same_thread": False})
        SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

        # Update db.session engine and SessionLocal as well
        import src.db.session as db_session_module
        db_session_module.engine = engine
        db_session_module.SessionLocal = SessionLocal

    # Create all tables if they don't already exist
    print("[*] Creating database tables (users, cases)...")
    Base.metadata.create_all(bind=engine)
    print("[+] Database schema initialized successfully.")

    # Seed default analyst and admin accounts
    db = SessionLocal()
    try:
        analyst = db.query(User).filter(User.email == "analyst@threattrace.io").first()
        if not analyst:
            analyst = User(
                email="analyst@threattrace.io",
                hashed_password=hash_password("Password123!"),
                full_name="SOC Lead Analyst",
                role=UserRole.ANALYST,
                is_active=True,
            )
            db.add(analyst)
            print("[+] Seeded default analyst account:")
            print("    Email:    analyst@threattrace.io")
            print("    Password: Password123!")

        admin = db.query(User).filter(User.email == "admin@threattrace.io").first()
        if not admin:
            admin = User(
                email="admin@threattrace.io",
                hashed_password=hash_password("AdminPass123!"),
                full_name="SOC System Administrator",
                role=UserRole.ADMIN,
                is_active=True,
            )
            db.add(admin)
            print("[+] Seeded default admin account:")
            print("    Email:    admin@threattrace.io")
            print("    Password: AdminPass123!")

        db.commit()
    except Exception as exc:
        db.rollback()
        print(f"[!] Note on seeding: {exc}")
    finally:
        db.close()

    print("\n" + "=" * 60)
    print(" [ThreatTrace AI] API Server Ready")
    print("=" * 60)
    print(" -> Swagger API Docs: http://127.0.0.1:8000/api/v1/docs")
    print(" -> Health Probe:     http://127.0.0.1:8000/api/health")
    print(" -> Upload Endpoint:  http://127.0.0.1:8000/api/email/upload")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    import uvicorn

    setup_database()

    uvicorn.run(
        "src.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
        app_dir=str(api_dir),
    )
