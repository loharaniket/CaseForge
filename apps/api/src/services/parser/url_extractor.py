import re
from urllib.parse import urlparse

# Strict URL regex matching http and https web schemes
URL_REGEX = re.compile(
    r"""(?i)\b((?:https?://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)(?:[^\s()<>]+|\(([^\s()<>]+|(\([^\s()<>]+\)))*\))+(?:\(([^\s()<>]+|(\([^\s()<>]+\)))*\)|[^\s`!()\[\]{};:'".,<>?«»“”‘’]))""",
    re.IGNORECASE,
)

# HTML attribute href / src extractor regex
HTML_HREF_REGEX = re.compile(
    r"""(?:href|src)\s*=\s*["'](https?://[^"'>\s]+)["']""",
    re.IGNORECASE,
)


def extract_urls(text_content: str | None = None, html_content: str | None = None) -> list[str]:
    """Deterministically extracts and sanitizes all URLs from text and HTML bodies.

    Strict security guarantee: No outgoing socket or HTTP network requests are made.
    """
    extracted_urls: list[str] = []
    seen: set[str] = set()

    def add_url(raw_url: str) -> None:
        clean_url = raw_url.strip().rstrip(".,;:!?)>\"'")
        if not clean_url:
            return

        # Prepend http:// to www domains if missing protocol
        if clean_url.lower().startswith("www."):
            clean_url = f"http://{clean_url}"

        try:
            parsed = urlparse(clean_url)
            if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
                if clean_url not in seen:
                    seen.add(clean_url)
                    extracted_urls.append(clean_url)
        except Exception:
            pass

    # 1. Extract from plain text body
    if text_content:
        for match in URL_REGEX.finditer(text_content):
            add_url(match.group(0))

    # 2. Extract from HTML body
    if html_content:
        for match in HTML_HREF_REGEX.finditer(html_content):
            add_url(match.group(1))

        # Also search remaining text within HTML
        for match in URL_REGEX.finditer(html_content):
            add_url(match.group(0))

    return extracted_urls
