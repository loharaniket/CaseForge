import socket
from unittest.mock import patch

from src.services.parser.url_extractor import extract_urls


def test_extract_urls_from_text_and_html():
    """Verify URL extraction from mixed text and HTML formatting."""
    text = (
        "Check this alert at https://soc.company.com/incident?id=42 and "
        "http://backup.c2-server.net:8080/path/test. Also visit www.google.com/search."
    )
    html = '<p>Click <a href="https://secure-login.phish.com/verify">here</a> or <img src="http://tracker.ad.org/pixel.gif"></p>'

    urls = extract_urls(text_content=text, html_content=html)

    assert "https://soc.company.com/incident?id=42" in urls
    assert "http://backup.c2-server.net:8080/path/test" in urls
    assert "http://www.google.com/search" in urls
    assert "https://secure-login.phish.com/verify" in urls
    assert "http://tracker.ad.org/pixel.gif" in urls


def test_extract_urls_no_network_requests():
    """Verify that URL extraction never initiates any outgoing network requests."""
    text = "Visit http://never-contacted-domain.xyz/payload and https://another-test-server.cc"

    with patch.object(socket.socket, "connect") as mock_socket:
        urls = extract_urls(text_content=text)
        assert len(urls) == 2
        mock_socket.assert_not_called()
