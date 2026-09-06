import email.utils
import ipaddress
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.core.errors import AppException, NotFoundError
from src.models.case import Case, CaseStatus
from src.models.email import ParsedEmail
from src.models.forensics import HeaderForensics
from src.services.forensics.auth_analyzer import (
    EmailAuthenticationAnalyzer,
    default_auth_analyzer,
)
from src.services.forensics.types import (
    AuthenticationResult,
    AuthenticationStatus,
    HeaderForensicsResult,
    RelayHop,
)
from src.services.parser_service import ParserService, get_parser_service

# Regex matchers for Received headers
RE_FROM_HOST_IP = re.compile(
    r"from\s+([^\s\(\)]+)(?:\s+\([^\)]*?(?:\[)?([0-9a-fA-F:.]+)(?:\])?[^\)]*?\))?",
    re.IGNORECASE,
)
RE_BY_HOST = re.compile(r"by\s+([^\s\(\);]+)", re.IGNORECASE)
RE_WITH_PROTO = re.compile(r"with\s+([^\s\(\);]+)", re.IGNORECASE)
RE_DATE_TAIL = re.compile(r";\s*([A-Za-z0-9,:\s+-]+)$")

# Email address extraction inside display names
RE_EMAIL_IN_NAME = re.compile(r"[\w\.-]+@[\w\.-]+\.\w+")

# Explicit RFC 1918, loopback, and link-local subnets
RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]


class HeaderForensicsService:
    """Forensic email transmission and header authentication analysis engine."""

    def __init__(
        self,
        parser_service: ParserService | None = None,
        auth_analyzer: EmailAuthenticationAnalyzer | None = None,
    ) -> None:
        self.parser_service = parser_service or get_parser_service()
        self.auth_analyzer = auth_analyzer or default_auth_analyzer

    @classmethod
    def _is_ip_private(cls, ip_str: str) -> bool:
        """Determines if an IP address string belongs to a private/loopback/link-local RFC1918 range."""
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            return any(ip_obj in net for net in RFC1918_NETWORKS)
        except ValueError:
            return False

    @classmethod
    def _extract_valid_ips(cls, text: str) -> list[str]:
        """Safely extracts all valid IPv4 and IPv6 addresses from a string in order of appearance."""
        candidates: list[str] = []
        # Bracketed and parenthesized IPs e.g. [198.51.100.1] or (198.51.100.1)
        for m in re.findall(r"\[([0-9a-fA-F:.]+)\]|\(([0-9a-fA-F:.]+)\)", text):
            candidates.extend([x for x in m if x])
        # IPv4
        candidates.extend(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
        # IPv6
        candidates.extend(re.findall(r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?\b", text))

        valid: list[str] = []
        seen: set[str] = set()
        for c in candidates:
            clean = c.strip("[]() ")
            try:
                ip_obj = ipaddress.ip_address(clean)
                norm = str(ip_obj)
                if norm not in seen:
                    seen.add(norm)
                    valid.append(norm)
            except ValueError:
                pass
        return valid

    @classmethod
    def parse_relay_chain(cls, raw_headers: dict[str, Any]) -> list[RelayHop]:
        """Reconstructs the chronological relay chain from Received header hops."""
        received_raw: list[str] = []
        for key, val in raw_headers.items():
            if key.lower() == "received":
                if isinstance(val, list):
                    received_raw.extend([str(v) for v in val])
                else:
                    received_raw.append(str(val))

        chronological_received = received_raw[::-1]
        hops: list[RelayHop] = []
        prev_dt = None
        seen_hops = set()

        for idx, rec_str in enumerate(chronological_received, start=1):
            from_host = None
            ip_addr = None
            by_host = None
            with_proto = None
            date_raw = None
            date_parsed = None
            delay_sec = None
            timezone_str = None
            confidence = 1.0
            issues = []
            untrusted = False

            rec_clean = " ".join(rec_str.split())

            if rec_clean in seen_hops:
                issues.append("Duplicate hop detected.")
            seen_hops.add(rec_clean)

            # Extract from host
            from_match = RE_FROM_HOST_IP.search(rec_clean)
            if from_match:
                from_host = from_match.group(1).strip("()[]")

            # Better IP extraction: isolate the 'from' clause first
            from_clause = rec_clean.split(" by ")[0] if " by " in rec_clean.lower() else rec_clean
            valid_ips = cls._extract_valid_ips(from_clause)
            if not valid_ips:
                # If no IP in from clause, search entire hop text
                valid_ips = cls._extract_valid_ips(rec_clean)

            if valid_ips:
                # The sending MTA usually appends the true IP at the end of the from clause
                ip_addr = valid_ips[-1]
            elif from_match and from_match.group(2):
                confidence -= 0.2
                issues.append("Malformed IP address in hop.")
                untrusted = True

            by_match = RE_BY_HOST.search(rec_clean)
            if by_match:
                by_host = by_match.group(1).strip("()[]")
                if from_host and from_host.lower() == by_host.lower():
                    issues.append("Suspicious loop: from_host equals by_host.")

            proto_match = RE_WITH_PROTO.search(rec_clean)
            if proto_match:
                with_proto = proto_match.group(1)

            date_match = RE_DATE_TAIL.search(rec_clean)
            if date_match:
                date_raw = date_match.group(1).strip()
                try:
                    tz_match = re.search(r'([+-]\d{4}|[A-Z]{3,4})', date_raw)
                    if tz_match:
                        timezone_str = tz_match.group(1)
                    import email.utils
                    date_parsed = email.utils.parsedate_to_datetime(date_raw)
                except Exception:
                    date_parsed = None
                    confidence -= 0.3
                    issues.append("Malformed or unparseable timestamp.")

            if date_parsed and prev_dt:
                try:
                    delta = (date_parsed - prev_dt).total_seconds()
                    if delta < 0:
                        issues.append("Impossible timestamp ordering (time travel).")
                        confidence -= 0.4
                        untrusted = True
                    elif delta > 86400: # gap of > 1 day
                        issues.append("Suspicious chronological gap (>1 day).")
                        confidence -= 0.2
                    delay_sec = max(0.0, round(delta, 2))
                except Exception:
                    delay_sec = None

            if date_parsed:
                prev_dt = date_parsed

            if not from_host and not ip_addr:
                confidence -= 0.3
                issues.append("Missing sending host and IP.")
            
            # If we couldn't parse the date at all, we mark it as malformed
            if not date_match:
                confidence -= 0.5
                issues.append("Malformed header: No valid date tail found.")

            is_private = cls._is_ip_private(ip_addr) if ip_addr else False

            hops.append(
                RelayHop(
                    hop_number=idx,
                    header_order=len(chronological_received) - idx + 1,
                    from_host=from_host,
                    by_host=by_host,
                    with_protocol=with_proto,
                    ip_address=ip_addr,
                    is_private_ip=is_private,
                    timestamp_raw=date_raw,
                    timestamp_parsed=date_parsed,
                    delay_seconds=delay_sec,
                    timezone=timezone_str,
                    parser_confidence=max(0.0, round(confidence, 2)),
                    validation_issues=issues,
                    untrusted_node=untrusted
                )
            )

        return hops

    @classmethod
    def extract_origin_ips(
        cls,
        hops: list[RelayHop],
        raw_headers: dict[str, Any] | None = None,
    ) -> tuple[list[str], str | None]:
        """Extracts candidate origin IPs and identifies the first external/public source MTA IP."""
        candidates: list[str] = []
        for hop in hops:
            if hop.ip_address and hop.ip_address not in candidates:
                candidates.append(hop.ip_address)

        # Also inspect raw headers for explicit origin and authentication IP indicators
        if raw_headers:
            origin_headers = (
                "x-originating-ip",
                "x-sender-ip",
                "client-ip",
                "x-client-ip",
                "x-mailer-ip",
                "x-aol-ip",
            )
            for h_name in origin_headers:
                for k, v in raw_headers.items():
                    if k.lower() == h_name:
                        v_str = " ".join([str(x) for x in v]) if isinstance(v, list) else str(v)
                        for ip in cls._extract_valid_ips(v_str):
                            if ip not in candidates:
                                candidates.append(ip)

            # Check Authentication-Results and Received-SPF for sender/client IP
            for auth_hdr in ("received-spf", "authentication-results", "arc-authentication-results"):
                for k, v in raw_headers.items():
                    if k.lower() == auth_hdr:
                        v_str = " ".join([str(x) for x in v]) if isinstance(v, list) else str(v)
                        for ip in cls._extract_valid_ips(v_str):
                            if ip not in candidates:
                                candidates.append(ip)

        # Probable origin: earliest non-private candidate IP in transmission order
        probable: str | None = None
        for ip in candidates:
            if not cls._is_ip_private(ip):
                probable = ip
                break

        # Fallback to first candidate if all are private
        if not probable and candidates:
            probable = candidates[0]

        return candidates, probable

    def parse_authentication_results(self, raw_headers: dict[str, Any]) -> AuthenticationResult:
        """Extracts SPF, DKIM, and DMARC results using EmailAuthenticationAnalyzer."""
        normalized = self.auth_analyzer.analyze_authentication(raw_headers)

        spf_status_val = AuthenticationStatus(normalized.spf.status.value)
        dkim_status_val = AuthenticationStatus(normalized.dkim.status.value)
        dmarc_status_val = AuthenticationStatus(normalized.dmarc.status.value)

        auth_hdr_raw = None
        for k in ("authentication-results", "arc-authentication-results", "received-spf"):
            if k in raw_headers:
                val = raw_headers[k]
                auth_hdr_raw = (
                    val if isinstance(val, str) else (val[0] if isinstance(val, list) else str(val))
                )
                break

        return AuthenticationResult(
            spf_status=spf_status_val,
            spf_details=normalized.spf.explanation,
            dkim_status=dkim_status_val,
            dkim_details=normalized.dkim.explanation,
            dmarc_status=dmarc_status_val,
            dmarc_details=normalized.dmarc.explanation,
            raw_auth_results=auth_hdr_raw,
            details=normalized.to_dict(),
        )

    @staticmethod
    def _extract_domain(email_address: str | None) -> str | None:
        """Extracts domain from email address string."""
        if not email_address or "@" not in email_address:
            return None
        return email_address.split("@")[-1].strip(" >").lower()

    @classmethod
    def evaluate_spoofing(
        cls, email_data: Any, auth_result: AuthenticationResult
    ) -> tuple[list[str], list[str], float]:
        """Evaluates sender authentication discrepancies, Return-Path mismatches, and spoofing signals."""
        spoofing: list[str] = []
        anomalies: list[str] = []
        risk_score: float = 0.0

        from_addr = str(getattr(email_data, "from_address", "") or "")
        from_name = str(getattr(email_data, "from_name", "") or "")
        from_domain = cls._extract_domain(from_addr)

        raw_headers = getattr(email_data, "raw_headers", {}) or {}

        # 1. Return-Path Mismatch Check
        return_path = None
        for k, v in raw_headers.items():
            if k.lower() == "return-path":
                return_path = v if isinstance(v, str) else (v[0] if isinstance(v, list) else str(v))
                break

        if return_path and from_domain:
            rp_domain = cls._extract_domain(return_path)
            if rp_domain and rp_domain != from_domain:
                rp_base = ".".join(rp_domain.lower().split(".")[-2:])
                from_base = ".".join(from_domain.lower().split(".")[-2:])
                if rp_base != from_base:
                    spoofing.append(
                        f"Return-Path domain mismatch: Return-Path ('{rp_domain}') does not match From ('{from_domain}')."
                    )
                    risk_score += 35.0
                else:
                    anomalies.append(
                        f"Subdomain Return-Path variation: Return-Path ('{rp_domain}') is an aligned subdomain of ('{from_domain}')."
                    )

        # 2. Reply-To Mismatch Check
        reply_to_list = list(getattr(email_data, "reply_to", []) or [])
        if reply_to_list and from_domain:
            for rt in reply_to_list:
                rt_domain = cls._extract_domain(rt)
                if rt_domain and rt_domain != from_domain:
                    spoofing.append(
                        f"Reply-To domain mismatch: Reply-To ('{rt_domain}') directs replies to a different domain than From ('{from_domain}')."
                    )
                    risk_score += 25.0
                    break

        # 3. Display Name Impersonation / Deceptive Email in Name
        if from_name:
            emails_in_name = RE_EMAIL_IN_NAME.findall(from_name)
            for embedded_email in emails_in_name:
                if embedded_email.lower() != from_addr.lower():
                    spoofing.append(
                        f"Display name deceptive spoofing: Name contains '{embedded_email}' but actual sender is '{from_addr}'."
                    )
                    risk_score += 30.0
                    break

        # 4. Authentication Verification Failures
        if auth_result.spf_status in (AuthenticationStatus.FAIL, AuthenticationStatus.PERMERROR):
            spoofing.append(f"SPF sender policy check FAILED ({auth_result.spf_status.value}).")
            risk_score += 30.0
        elif auth_result.spf_status == AuthenticationStatus.SOFTFAIL:
            anomalies.append("SPF check resulted in SOFTFAIL (host is not explicitly authorized).")
            risk_score += 15.0

        if auth_result.dkim_status in (AuthenticationStatus.FAIL, AuthenticationStatus.PERMERROR):
            spoofing.append(
                f"DKIM cryptographic signature verification FAILED ({auth_result.dkim_status.value})."
            )
            risk_score += 25.0

        if auth_result.dmarc_status in (AuthenticationStatus.FAIL, AuthenticationStatus.PERMERROR):
            spoofing.append(
                f"DMARC alignment policy check FAILED ({auth_result.dmarc_status.value})."
            )
            risk_score += 35.0

        # Normalized to 0.0 - 100.0
        final_risk = round(min(100.0, max(0.0, risk_score)), 2)
        return spoofing, anomalies, final_risk

    def analyze_headers(self, email_data: Any) -> HeaderForensicsResult:
        """Executes full header forensic inspection."""
        raw_headers = getattr(email_data, "raw_headers", {}) or {}

        relay_hops = self.parse_relay_chain(raw_headers)
        auth_result = self.parse_authentication_results(raw_headers)
        origin_candidates, probable_origin = self.extract_origin_ips(relay_hops, raw_headers)

        # If probable origin not found from hops or headers, check SPF authorized sender IP
        if not probable_origin and auth_result and auth_result.details:
            spf_details = auth_result.details.get("spf", {})
            sender_ip = spf_details.get("sender_ip") if isinstance(spf_details, dict) else None
            if sender_ip and sender_ip not in origin_candidates:
                origin_candidates.append(sender_ip)
                probable_origin = sender_ip

        spoofing, anomalies, risk_score = self.evaluate_spoofing(email_data, auth_result)

        return HeaderForensicsResult(
            relay_hops=relay_hops,
            origin_ip_candidates=origin_candidates,
            probable_origin_ip=probable_origin,
            authentication=auth_result,
            spoofing_indicators=spoofing,
            anomalies=anomalies,
            forensics_risk_score=risk_score,
        )

    def analyze_case(self, case_id: str, db: Session) -> HeaderForensics:
        """Analyzes header forensics for an investigation case and persists results."""
        case = db.execute(select(Case).where(Case.id == case_id)).scalar_one_or_none()
        if not case:
            raise NotFoundError(f"Investigation case '{case_id}' was not found.")

        if case.status == CaseStatus.FAILED:
            raise AppException(
                message=f"Cannot inspect headers on failed case '{case_id}': {case.error_message}",
                code="CASE_PARSING_FAILED",
                status_code=400,
            )

        # Check existing (idempotency)
        existing = db.execute(
            select(HeaderForensics).where(HeaderForensics.case_id == case_id)
        ).scalar_one_or_none()
        if existing:
            return existing

        parsed_email = db.execute(
            select(ParsedEmail).where(ParsedEmail.case_id == case_id)
        ).scalar_one_or_none()

        if not parsed_email:
            parsed_email = self.parser_service.get_parsed_case(case_id=case_id, db=db)

        result = self.analyze_headers(parsed_email)

        serialized_hops = [hop.to_dict() for hop in result.relay_hops]
        auth_dict = result.authentication.to_dict()

        record = HeaderForensics(
            case_id=case.id,
            relay_hops=serialized_hops,
            origin_ip_candidates=result.origin_ip_candidates,
            probable_origin_ip=result.probable_origin_ip,
            spf_status=result.authentication.spf_status.value,
            dkim_status=result.authentication.dkim_status.value,
            dmarc_status=result.authentication.dmarc_status.value,
            authentication_details=auth_dict,
            spoofing_indicators=result.spoofing_indicators,
            anomalies=result.anomalies,
            forensics_risk_score=result.forensics_risk_score,
        )

        db.add(record)
        db.commit()
        db.refresh(record)

        return record

    def get_case_forensics(self, case_id: str, db: Session) -> HeaderForensics:
        """Retrieves or executes on-demand header forensics for a case."""
        existing = db.execute(
            select(HeaderForensics).where(HeaderForensics.case_id == case_id)
        ).scalar_one_or_none()
        if existing:
            return existing

        return self.analyze_case(case_id=case_id, db=db)


# Default singleton instance
default_forensics_service = HeaderForensicsService()


def get_forensics_service() -> HeaderForensicsService:
    """Dependency injector for header forensics service."""
    return default_forensics_service
