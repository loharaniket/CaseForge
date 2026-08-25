import pytest
import httpx
from src.services.intelligence.redirect_analyzer import SafeRedirectAnalyzer, SSRFVulnerabilityException

def test_safe_ip_check():
    assert not SafeRedirectAnalyzer._is_ip_safe("127.0.0.1")
    assert not SafeRedirectAnalyzer._is_ip_safe("10.0.0.1")
    assert not SafeRedirectAnalyzer._is_ip_safe("192.168.1.1")
    assert not SafeRedirectAnalyzer._is_ip_safe("169.254.169.254")
    assert not SafeRedirectAnalyzer._is_ip_safe("::1")
    assert SafeRedirectAnalyzer._is_ip_safe("8.8.8.8")
    assert SafeRedirectAnalyzer._is_ip_safe("93.184.216.34") # example.com

@pytest.mark.asyncio
async def test_analyze_unsupported_protocol():
    chain = await SafeRedirectAnalyzer.analyze("ftp://example.com/file")
    assert len(chain) == 1
    assert chain[0]["status"] == "BLOCKED_SECURITY_POLICY"
    assert chain[0]["error"] == "UNSUPPORTED_PROTOCOL"

@pytest.mark.asyncio
async def test_analyze_localhost_ssrf():
    chain = await SafeRedirectAnalyzer.analyze("http://127.0.0.1/admin")
    assert len(chain) == 1
    assert chain[0]["status"] == "BLOCKED_SECURITY_POLICY"

@pytest.mark.asyncio
async def test_analyze_metadata_ssrf():
    chain = await SafeRedirectAnalyzer.analyze("http://169.254.169.254/latest/meta-data/")
    assert len(chain) == 1
    assert chain[0]["status"] == "BLOCKED_SECURITY_POLICY"
    
@pytest.mark.asyncio
async def test_analyze_dns_resolution_private():
    # Attempting to use a public DNS record that resolves to private IP (DNS Rebinding/Spoofing)
    # We will mock the resolver
    pass

from unittest.mock import patch, MagicMock

@pytest.mark.asyncio
@patch('socket.gethostbyname')
async def test_analyze_dns_resolution_private(mock_gethostbyname):
    mock_gethostbyname.return_value = "192.168.1.100"
    chain = await SafeRedirectAnalyzer.analyze("http://internal-app.local")
    assert len(chain) == 1
    assert chain[0]["status"] == "BLOCKED_SECURITY_POLICY"

@pytest.mark.asyncio
@patch('socket.gethostbyname')
async def test_dns_failure(mock_gethostbyname):
    import socket
    mock_gethostbyname.side_effect = socket.gaierror("Name or service not known")
    chain = await SafeRedirectAnalyzer.analyze("http://nonexistent-domain-12345.com")
    assert len(chain) == 1
    assert chain[0]["status"] == "DNS_RESOLUTION_FAILED"

@pytest.mark.asyncio
@patch('socket.gethostbyname')
@patch('httpx.AsyncClient.stream')
async def test_normal_redirect(mock_stream, mock_gethostbyname):
    mock_gethostbyname.return_value = "8.8.8.8"
    
    class MockResponse:
        def __init__(self, status_code, location=None, url=""):
            self.status_code = status_code
            self.headers = {"Location": location} if location else {}
            self.url = url
            
        async def __aenter__(self):
            return self
            
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    # First call returns 301 to new location, second call returns 200
    mock_stream.side_effect = [
        MockResponse(301, location="https://example.com/final"),
        MockResponse(200, url="https://example.com/final")
    ]
    
    chain = await SafeRedirectAnalyzer.analyze("http://example.com/start")
    assert len(chain) == 2
    assert chain[0]["status"] == 301
    assert chain[0]["redirect_url"] == "https://example.com/final"
    assert chain[1]["status"] == 200
    assert chain[1]["final_url"] == "https://example.com/final"

@pytest.mark.asyncio
@patch('socket.gethostbyname')
@patch('httpx.AsyncClient.stream')
async def test_too_many_redirects(mock_stream, mock_gethostbyname):
    mock_gethostbyname.return_value = "8.8.8.8"
    
    class MockResponse:
        def __init__(self, status_code, location=None):
            self.status_code = status_code
            self.headers = {"Location": location}
            
        async def __aenter__(self):
            return self
            
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            pass

    mock_stream.return_value = MockResponse(302, location="http://example.com/loop")
    
    chain = await SafeRedirectAnalyzer.analyze("http://example.com/start")
    assert len(chain) == SafeRedirectAnalyzer.MAX_REDIRECTS + 2
    assert chain[-1]["status"] == "TOO_MANY_REDIRECTS"

@pytest.mark.asyncio
@patch('socket.gethostbyname')
@patch('httpx.AsyncClient.stream')
async def test_timeout_handling(mock_stream, mock_gethostbyname):
    mock_gethostbyname.return_value = "8.8.8.8"
    mock_stream.side_effect = httpx.TimeoutException("Timeout")
    
    chain = await SafeRedirectAnalyzer.analyze("http://example.com/start")
    assert len(chain) == 1
    assert chain[0]["status"] == "TIMEOUT"
