# ThreatTrace AI — API Specification

## Conventions
* API Versioning: `/api/v1`
* Interactive Documentation:
  * Swagger UI: `http://localhost:8000/api/v1/docs`
  * OpenAPI JSON: `http://localhost:8000/api/v1/openapi.json`
  * ReDoc: `http://localhost:8000/api/v1/redoc`

## Standard Request & Response Headers
* `X-Request-ID`: Unique correlation UUID injected or propagated across every request.
* `X-Response-Time`: Latency of the request processing in milliseconds (e.g. `12.45ms`).

---

## Foundation Diagnostic Endpoints

### 1. Application Liveness Probe
* **Route**: `GET /api/health`
* **Description**: Confirms that the FastAPI process is running and able to serve HTTP requests.
* **Success Response (200 OK)**:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "environment": "development",
  "timestamp": "2026-08-23T00:00:00Z"
}
```

### 2. Dependency Readiness Probe
* **Route**: `GET /api/ready`
* **Description**: Verifies that critical backend dependencies (PostgreSQL database) are operational.
* **Success Response (200 OK)**:
```json
{
  "status": "ready",
  "database": "connected",
  "version": "0.1.0",
  "timestamp": "2026-08-23T00:00:00Z",
  "details": {
    "database": "operational"
  }
}
```
* **Degraded Response (503 Service Unavailable)**:
```json
{
  "status": "not_ready",
  "database": "disconnected",
  "version": "0.1.0",
  "timestamp": "2026-08-23T00:00:00Z",
  "details": {
    "database": "unreachable"
  }
}
```

### 3. Comprehensive Health Diagnostic
* **Route**: `GET /api/v1/health` (alias `GET /health`)
* **Description**: Full telemetry check including service version, execution environment, and database state.
* **Response (200 OK)**:
```json
{
  "status": "healthy",
  "version": "0.1.0",
  "environment": "development",
  "database": "connected",
  "timestamp": "2026-08-23T00:00:00Z"
}
```

---

## Structured Error Responses

All API errors return a standardized envelope without exposing internal credentials, connection strings, or system paths:

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Request validation failed.",
    "details": [
      {
        "location": "body -> subject",
        "message": "Field required",
        "type": "missing"
      }
    ]
  }
}
```

### Common Error Codes
* `NOT_FOUND`: HTTP 404
* `VALIDATION_ERROR`: HTTP 422
* `UNAUTHORIZED`: HTTP 401
* `FORBIDDEN`: HTTP 403
* `SERVICE_UNAVAILABLE`: HTTP 503
* `INTERNAL_SERVER_ERROR`: HTTP 500
