from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.core.errors import (
    DatabaseError,
    NotFoundError,
    ServiceUnavailableError,
    ValidationError,
    setup_exception_handlers,
)


def test_custom_exception_hierarchy():
    """Verify default properties of custom exception classes."""
    not_found = NotFoundError("Email sample not found", details={"id": "eml-123"})
    assert not_found.status_code == 404
    assert not_found.code == "NOT_FOUND"
    assert not_found.message == "Email sample not found"
    assert not_found.details == {"id": "eml-123"}

    val_err = ValidationError("Bad input parameter")
    assert val_err.status_code == 422
    assert val_err.code == "VALIDATION_ERROR"

    db_err = DatabaseError("Connection timed out")
    assert db_err.status_code == 500
    assert db_err.code == "DATABASE_ERROR"

    svc_err = ServiceUnavailableError("Queue offline")
    assert svc_err.status_code == 503
    assert svc_err.code == "SERVICE_UNAVAILABLE"


def test_exception_handler_integration():
    """Verify exception handlers format responses into structured JSON envelopes."""
    app = FastAPI()
    setup_exception_handlers(app)

    @app.get("/trigger-not-found")
    def trigger_not_found():
        raise NotFoundError("Investigation record missing", details={"case_id": "999"})

    @app.get("/trigger-unhandled")
    def trigger_unhandled():
        raise RuntimeError("Unexpected internal crash with secret_key=12345")

    client = TestClient(app, raise_server_exceptions=False)

    # 1. Test custom NotFoundError
    res = client.get("/trigger-not-found")
    assert res.status_code == 404
    data = res.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert data["error"]["message"] == "Investigation record missing"
    assert data["error"]["details"] == {"case_id": "999"}

    # 2. Test unhandled Exception redaction
    res_500 = client.get("/trigger-unhandled")
    assert res_500.status_code == 500
    data_500 = res_500.json()
    assert "error" in data_500
    assert data_500["error"]["code"] == "INTERNAL_SERVER_ERROR"
    # Ensure internal exception string is not leaked to client
    assert "secret_key" not in data_500["error"]["message"]


def test_http_404_handling():
    """Verify that routing 404s return structured error format."""
    app = FastAPI()
    setup_exception_handlers(app)
    client = TestClient(app)

    res = client.get("/non-existent-path")
    assert res.status_code == 404
    data = res.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert "Not Found" in data["error"]["message"]
