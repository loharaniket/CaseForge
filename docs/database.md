# ThreatTrace AI — Database Architecture & Migrations

## Database Engine
* **Production / Staging**: PostgreSQL 17
* **Testing / CI**: Isolated transactional SQLite in-memory or ephemeral PostgreSQL test container

## Migration Management with Alembic
All schema changes must be versioned via Alembic migrations located in `apps/api/alembic/versions/`.

### Migration Commands
From `apps/api/`:
```bash
# Generate a new migration based on ORM models
alembic revision --autogenerate -m "describe_schema_change"

# Apply all pending migrations
alembic upgrade head

# Rollback latest migration
alembic downgrade -1
```

## Base Model Guidelines
All database entities inherit from `Base` (`apps/api/src/db/base.py`), which provides standard UTC audit timestamps:
* `created_at`: DateTime(timezone=True)
* `updated_at`: DateTime(timezone=True)
