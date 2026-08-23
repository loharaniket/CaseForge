# ThreatTrace AI — API Specification

## Conventions
* API Versioning: `/api/v1`
* Interactive Documentation:
  * Swagger UI: `http://localhost:8000/api/v1/docs`
  * OpenAPI JSON: `http://localhost:8000/api/v1/openapi.json`
  * ReDoc: `http://localhost:8000/api/v1/redoc`

## Base Endpoints

### 1. Health Diagnostic
* **Route**: `GET /api/v1/health` (alias `GET /health`)
* **Description**: Returns operational readiness, active service version, environment, and database connectivity.
* **Response Schema**:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "environment": "development",
  "database": "connected",
  "timestamp": "2026-08-23T00:00:00Z"
}
```

### 2. Service Root
* **Route**: `GET /`
* **Description**: Service identification and documentation locator.
