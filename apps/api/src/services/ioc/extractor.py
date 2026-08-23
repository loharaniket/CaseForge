import ipaddress
import re
from typing import Any
from urllib.parse import urlparse

from src.services.ioc.types import IOCExtractionResult, IOCRecord, IOCType
from src.services.parser.url_extractor import extract_urls

# Regex patterns for IOC extraction
RE_IPV4 = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
RE_IPV6_FINDER = re.compile(r"\[([0-9a-fA-F:]+)\]|\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){1,7})\b")
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b")
RE_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# Ignored extensions and header tokens often falsely matching simple domain pattern
IGNORED_FILE_EXTENSIONS = {
    "png",
    "jpg",
    "jpeg",
    "gif",
    "svg",
    "bmp",
    "ico",
    "exe",
    "dll",
    "bin",
    "iso",
    "zip",
    "tar",
    "gz",
    "7z",
    "rar",
    "pdf",
    "doc",
    "docx",
    "xls",
    "xlsx",
    "ppt",
    "pptx",
    "txt",
    "csv",
    "eml",
    "msg",
    "htm",
    "html",
    "css",
    "js",
    "json",
    "xml",
}

IGNORED_DOMAIN_TOKENS = {
    "header.from",
    "header.d",
    "header.s",
    "header.i",
    "header.to",
    "header.cc",
    "header.bcc",
    "header.reply_to",
    "header.return_path",
    "smtp.mailfrom",
    "body.url_domain",
}


class IOCExtractor:
    """Deterministic extractor and normalizer for Indicators of Compromise (IOCs).

    Strict security guarantees:
    - Absolutely NO live DNS lookups or domain resolutions.
    - Absolutely NO outgoing HTTP/socket requests to URLs.
    - Absolutely NO external threat intelligence lookups.
    """

    @classmethod
    def _is_valid_ipv4(cls, ip_str: str) -> bool:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return isinstance(ip_obj, ipaddress.IPv4Address)
        except ValueError:
            return False

    @classmethod
    def _is_valid_ipv6(cls, ip_str: str) -> bool:
        clean = ip_str.strip("[]")
        try:
            ip_obj = ipaddress.ip_address(clean)
            return isinstance(ip_obj, ipaddress.IPv6Address)
        except ValueError:
            return False

    @classmethod
    def _extract_ipv6_addresses(cls, text: str) -> list[str]:
        """Safely extracts all valid IPv6 addresses from a string."""
        results: list[str] = []
        for m in RE_IPV6_FINDER.finditer(text):
            candidate = m.group(1) or m.group(2)
            if candidate and ":" in candidate:
                try:
                    ip_obj = ipaddress.ip_address(candidate.strip("[]"))
                    if isinstance(ip_obj, ipaddress.IPv6Address):
                        results.append(str(ip_obj))
                except ValueError:
                    pass
        return results

    @classmethod
    def _is_valid_domain(cls, domain_str: str) -> bool:
        domain_clean = domain_str.strip(" .").lower()
        if not domain_clean or "." not in domain_clean:
            return False

        if domain_clean in IGNORED_DOMAIN_TOKENS:
            return False

        # Discard if it is an IP address
        if cls._is_valid_ipv4(domain_clean):
            return False

        parts = domain_clean.split(".")
        tld = parts[-1]

        # Ignore common file attachments or single character labels
        if tld in IGNORED_FILE_EXTENSIONS:
            return False
        if len(tld) < 2 or not tld.isalpha():
            return False

        return True

    def extract_from_email_data(self, email_data: Any) -> IOCExtractionResult:
        """Extracts, normalizes, and deduplicates all IOCs from parsed email data."""
        unique_iocs: dict[tuple[IOCType, str], IOCRecord] = {}

        def add_ioc(
            ioc_type: IOCType,
            raw_value: str | None,
            source: str,
            confidence: float = 1.0,
            context: str | None = None,
        ) -> None:
            if not raw_value:
                return

            val = raw_value.strip().strip("<>\"'()[],;")
            if not val:
                return

            norm_val: str | None = None

            if ioc_type == IOCType.IPV4:
                if self._is_valid_ipv4(val):
                    norm_val = str(ipaddress.IPv4Address(val))
            elif ioc_type == IOCType.IPV6:
                clean_ip = val.strip("[]")
                if self._is_valid_ipv6(clean_ip):
                    norm_val = str(ipaddress.IPv6Address(clean_ip))
            elif ioc_type == IOCType.EMAIL:
                clean_email = val.lower()
                if RE_EMAIL.match(clean_email):
                    norm_val = clean_email
                    # Also extract domain from email
                    domain_part = clean_email.split("@")[-1]
                    add_ioc(
                        IOCType.DOMAIN,
                        domain_part,
                        f"{source}.email_domain",
                        confidence=confidence * 0.95,
                    )
            elif ioc_type == IOCType.DOMAIN:
                clean_domain = val.lower().rstrip(".")
                if self._is_valid_domain(clean_domain):
                    norm_val = clean_domain
            elif ioc_type == IOCType.URL:
                clean_url = val.rstrip(".,;:!?)>\"'")
                try:
                    parsed = urlparse(clean_url)
                    if parsed.scheme.lower() in ("http", "https") and parsed.netloc:
                        norm_val = clean_url
                        # Extract host domain / IP from URL
                        host = parsed.netloc.split(":")[0].strip("[]")
                        if self._is_valid_ipv4(host):
                            add_ioc(IOCType.IPV4, host, f"{source}.url_host", confidence=confidence)
                        elif self._is_valid_ipv6(host):
                            add_ioc(IOCType.IPV6, host, f"{source}.url_host", confidence=confidence)
                        elif self._is_valid_domain(host):
                            add_ioc(
                                IOCType.DOMAIN, host, f"{source}.url_domain", confidence=confidence
                            )
                except Exception:
                    pass
            elif ioc_type == IOCType.SHA256:
                clean_hash = val.lower()
                if len(clean_hash) == 64 and all(c in "0123456789abcdef" for c in clean_hash):
                    norm_val = clean_hash

            if norm_val:
                key = (ioc_type, norm_val)
                if key not in unique_iocs or unique_iocs[key].confidence < confidence:
                    unique_iocs[key] = IOCRecord(
                        value=norm_val,
                        type=ioc_type,
                        source=source,
                        confidence=round(confidence, 2),
                        context=context,
                    )

        # 1. Extract from Structured Email Headers
        from_addr = getattr(email_data, "from_address", None) or getattr(email_data, "sender", None)
        if from_addr:
            add_ioc(IOCType.EMAIL, from_addr, "header.from", confidence=1.0)

        to_addrs = (
            getattr(email_data, "recipients", None) or getattr(email_data, "to_addresses", []) or []
        )
        for recipient in to_addrs:
            add_ioc(IOCType.EMAIL, recipient, "header.to", confidence=1.0)

        cc_addrs = getattr(email_data, "cc", None) or getattr(email_data, "cc_addresses", []) or []
        for cc in cc_addrs:
            add_ioc(IOCType.EMAIL, cc, "header.cc", confidence=1.0)

        bcc_addrs = (
            getattr(email_data, "bcc", None) or getattr(email_data, "bcc_addresses", []) or []
        )
        for bcc in bcc_addrs:
            add_ioc(IOCType.EMAIL, bcc, "header.bcc", confidence=1.0)

        reply_to_addrs = getattr(email_data, "reply_to", []) or []
        for rt in reply_to_addrs:
            add_ioc(IOCType.EMAIL, rt, "header.reply_to", confidence=1.0)

        # 2. Extract from Raw Headers (Received, Return-Path, Authentication-Results)
        raw_headers = getattr(email_data, "raw_headers", {}) or {}
        for k, v in raw_headers.items():
            k_lower = k.lower()
            vals = [str(x) for x in v] if isinstance(v, list) else [str(v)]

            if k_lower == "return-path":
                for val in vals:
                    add_ioc(IOCType.EMAIL, val, "header.return_path", confidence=1.0)

            elif k_lower == "received":
                for val in vals:
                    # Extract IPv4 from Received headers
                    for ipv4_match in RE_IPV4.findall(val):
                        add_ioc(IOCType.IPV4, ipv4_match, "header.received", confidence=0.98)
                    # Extract IPv6 from Received headers
                    for ipv6_match in self._extract_ipv6_addresses(val):
                        add_ioc(IOCType.IPV6, ipv6_match, "header.received", confidence=0.98)
                    # Extract domains from Received headers
                    for dom_match in RE_DOMAIN.findall(val):
                        add_ioc(IOCType.DOMAIN, dom_match, "header.received_host", confidence=0.90)

            elif k_lower in (
                "authentication-results",
                "arc-authentication-results",
                "received-spf",
            ):
                for val in vals:
                    for ipv4_match in RE_IPV4.findall(val):
                        add_ioc(IOCType.IPV4, ipv4_match, f"header.{k_lower}", confidence=0.98)
                    for ipv6_match in self._extract_ipv6_addresses(val):
                        add_ioc(IOCType.IPV6, ipv6_match, f"header.{k_lower}", confidence=0.98)
                    for dom_match in RE_DOMAIN.findall(val):
                        add_ioc(IOCType.DOMAIN, dom_match, f"header.{k_lower}", confidence=0.95)

        # 3. Extract from Attachment Metadata
        attachments = (
            getattr(email_data, "attachments_metadata", None)
            or getattr(email_data, "attachments", None)
            or []
        )
        for att in attachments:
            att_hash = getattr(att, "sha256", None) or (
                att.get("sha256") if isinstance(att, dict) else None
            )
            att_name = getattr(att, "filename", None) or (
                att.get("filename") if isinstance(att, dict) else None
            )
            if att_hash:
                add_ioc(
                    IOCType.SHA256,
                    att_hash,
                    f"attachment.{att_name or 'file'}",
                    confidence=1.0,
                    context=f"SHA-256 evidence hash of attachment '{att_name}'",
                )

        # 4. Extract URLs from Body Content
        body_text = (
            getattr(email_data, "body_plain", None) or getattr(email_data, "body_text", None) or ""
        )
        body_html = getattr(email_data, "body_html", "") or ""

        # Extracted URLs
        extracted_urls = (
            getattr(email_data, "extracted_urls", None) or getattr(email_data, "urls", None) or []
        )
        if not extracted_urls:
            extracted_urls = extract_urls(text_content=body_text, html_content=body_html)

        for u in extracted_urls:
            add_ioc(IOCType.URL, u, "body.url", confidence=0.95)

        # 5. Extract Content Mentions from Text & HTML Bodies
        combined_body = f"{body_text}\n{body_html}"
        if combined_body.strip():
            # IPv4 in body
            for ip in RE_IPV4.findall(combined_body):
                add_ioc(IOCType.IPV4, ip, "body.text", confidence=0.90)

            # IPv6 in body
            for ip6 in self._extract_ipv6_addresses(combined_body):
                add_ioc(IOCType.IPV6, ip6, "body.text", confidence=0.90)

            # Email addresses in body
            for em in RE_EMAIL.findall(combined_body):
                add_ioc(IOCType.EMAIL, em, "body.text", confidence=0.90)

            # SHA-256 hashes in body
            for h in RE_SHA256.findall(combined_body):
                add_ioc(IOCType.SHA256, h, "body.text", confidence=0.90)

            # Domains in body
            for d in RE_DOMAIN.findall(combined_body):
                add_ioc(IOCType.DOMAIN, d, "body.text", confidence=0.85)

        # Build final aggregated result sorted by type and value
        sorted_iocs = sorted(unique_iocs.values(), key=lambda x: (x.type.value, x.value))

        by_type_counts: dict[str, int] = {}
        for item in sorted_iocs:
            by_type_counts[item.type.value] = by_type_counts.get(item.type.value, 0) + 1

        return IOCExtractionResult(
            iocs=sorted_iocs,
            total_count=len(sorted_iocs),
            by_type=by_type_counts,
            unique_types=sorted(by_type_counts.keys()),
        )


# Default singleton instance
default_ioc_extractor = IOCExtractor()
