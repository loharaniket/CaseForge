import sys
f = 'apps/api/tests/unit/test_redirect_analyzer.py'
with open(f, 'a') as file:
    file.write('''
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
''')
