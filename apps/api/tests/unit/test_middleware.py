from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.core.middleware import mask_sensitive_headers, setup_middleware


def test_mask_sensitive_headers():
    """Verify that sensitive header values are masked."""
    headers = {
        "Authorization": "Bearer super-secret-jwt-token",
        "Cookie": "session_id=abcdef123456",
        "X-API-Key": "secret-api-key-9999",
        "Host": "localhost:8000",
        "Content-Type": "application/json",
        "Accept": "*/*",
    }
    masked = mask_sensitive_headers(headers)

    assert masked["Authorization"] == "********"
    assert masked["Cookie"] == "********"
    assert masked["X-API-Key"] == "********"
    assert masked["Host"] == "localhost:8000"
    assert masked["Content-Type"] == "application/json"


def test_middleware_request_id_and_response_time():
    """Verify middleware injects X-Request-ID and X-Response-Time headers."""
    app = FastAPI()
    setup_middleware(app)

    @app.get("/ping")
    def ping():
        return {"status": "pong"}

    client = TestClient(app)

    # 1. Without client request ID -> middleware generates one
    res = client.get("/ping")
    assert res.status_code == 200
    assert "X-Request-ID" in res.headers
    assert "X-Response-Time" in res.headers
    assert res.headers["X-Response-Time"].endswith("ms")

    # 2. With client-provided request ID -> middleware preserves it
    custom_req_id = "threattrace-custom-trace-12345"
    res_custom = client.get("/ping", headers={"X-Request-ID": custom_req_id})
    assert res_custom.status_code == 200
    assert res_custom.headers["X-Request-ID"] == custom_req_id
