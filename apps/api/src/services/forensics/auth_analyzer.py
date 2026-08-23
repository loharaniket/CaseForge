import re
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class AuthStatus(StrEnum):
    """Granular RFC 8601 email authentication result status."""

    PASS = "pass"
    FAIL = "fail"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    UNKNOWN = "unknown"


def normalize_auth_status(status: AuthStatus) -> str:
    """Normalizes granular statuses to standardized 5-tier classification:

    pass, fail, neutral, none, unknown.
    """
    if status == AuthStatus.PASS:
        return "pass"
    elif status in (
        AuthStatus.FAIL,
        AuthStatus.SOFTFAIL,
        AuthStatus.PERMERROR,
        AuthStatus.TEMPERROR,
    ):
        return "fail"
    elif status == AuthStatus.NEUTRAL:
        return "neutral"
    elif status == AuthStatus.NONE:
        return "none"
    else:
        return "unknown"


@dataclass
class ProtocolAuthResult:
    """Forensic authentication evaluation output for a single protocol (SPF, DKIM, DMARC)."""

    protocol: str
    status: AuthStatus
    normalized_status: str
    domain: str | None = None
    selector: str | None = None
    sender_ip: str | None = None
    evidence: str | None = None
    source_header: str | None = None
    explanation: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass
class NormalizedEmailAuthentication:
    """Consolidated and normalized authentication result across SPF, DKIM, and DMARC."""

    spf: ProtocolAuthResult
    dkim: ProtocolAuthResult
    dmarc: ProtocolAuthResult
    overall_posture: str = "UNAUTHENTICATED"
    explanations: list[str] = field(default_factory=list)
    source_headers_found: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "spf": self.spf.to_dict(),
            "dkim": self.dkim.to_dict(),
            "dmarc": self.dmarc.to_dict(),
            "overall_posture": self.overall_posture,
            "explanations": self.explanations,
            "source_headers_found": self.source_headers_found,
        }


# Regex matchers for RFC 8601 Authentication-Results clauses
RE_SPF_CLAUSE = re.compile(
    r"\bspf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)(?:\s+\(([^)]*)\))?(?:\s+([^;]+))?",
    re.IGNORECASE,
)
RE_DKIM_CLAUSE = re.compile(
    r"\bdkim\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)(?:\s+\(([^)]*)\))?(?:\s+([^;]+))?",
    re.IGNORECASE,
)
RE_DMARC_CLAUSE = re.compile(
    r"\bdmarc\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)(?:\s+\(([^)]*)\))?(?:\s+([^;]+))?",
    re.IGNORECASE,
)

# Granular attribute extractors
RE_MAILFROM = re.compile(r"smtp\.mailfrom\s*=\s*([^\s;]+)", re.IGNORECASE)
RE_HEADER_D = re.compile(r"header\.(?:d|i)\s*=\s*(?:@)?([^\s;]+)", re.IGNORECASE)
RE_HEADER_S = re.compile(r"header\.s\s*=\s*([^\s;]+)", re.IGNORECASE)
RE_HEADER_FROM = re.compile(r"header\.from\s*=\s*([^\s;]+)", re.IGNORECASE)
RE_SENDER_IP = re.compile(
    r"(?:sender\s+IP\s+is\s+|client-ip\s*=\s*|ip\s*=\s*)([0-9a-fA-F:.]+)", re.IGNORECASE
)
RE_RECEIVED_SPF_HEADER = re.compile(
    r"^(pass|fail|softfail|neutral|none|temperror|permerror)(?:\s+\(([^)]*)\))?",
    re.IGNORECASE,
)


class EmailAuthenticationAnalyzer:
    """Deterministic header-based SPF, DKIM, and DMARC forensic analyzer."""

    @staticmethod
    def _get_header_values(raw_headers: dict[str, Any], target_name: str) -> list[str]:
        """Case-insensitively retrieves all string values for a header."""
        results: list[str] = []
        target_lower = target_name.lower()
        for k, v in raw_headers.items():
            if k.lower() == target_lower:
                if isinstance(v, list):
                    results.extend([str(item) for item in v])
                else:
                    results.append(str(v))
        return results

    @classmethod
    def _evaluate_spf(cls, raw_headers: dict[str, Any]) -> ProtocolAuthResult:
        """Extracts and normalizes SPF outcome from Authentication-Results or Received-SPF."""
        # 1. Search in Authentication-Results / ARC-Authentication-Results
        for header_name in (
            "authentication-results",
            "arc-authentication-results",
            "x-authentication-results",
        ):
            header_vals = cls._get_header_values(raw_headers, header_name)
            for val in header_vals:
                val_clean = " ".join(val.split())
                match = RE_SPF_CLAUSE.search(val_clean)
                if match:
                    raw_status_str = match.group(1).lower()
                    try:
                        status = AuthStatus(raw_status_str)
                    except ValueError:
                        status = AuthStatus.UNKNOWN

                    # Extract attributes from whole clean header string
                    domain_match = RE_MAILFROM.search(val_clean)
                    domain = domain_match.group(1) if domain_match else None

                    ip_match = RE_SENDER_IP.search(val_clean)
                    sender_ip = ip_match.group(1) if ip_match else None

                    explanation = cls._generate_spf_explanation(status, domain, sender_ip)

                    return ProtocolAuthResult(
                        protocol="spf",
                        status=status,
                        normalized_status=normalize_auth_status(status),
                        domain=domain,
                        sender_ip=sender_ip,
                        evidence=match.group(0).strip(),
                        source_header=header_name,
                        explanation=explanation,
                    )

        # 2. Fallback to Received-SPF header
        spf_headers = cls._get_header_values(raw_headers, "received-spf")
        for spf_val in spf_headers:
            spf_clean = " ".join(spf_val.split())
            match = RE_RECEIVED_SPF_HEADER.search(spf_clean)
            if match:
                raw_status_str = match.group(1).lower()
                try:
                    status = AuthStatus(raw_status_str)
                except ValueError:
                    status = AuthStatus.UNKNOWN

                ip_match = RE_SENDER_IP.search(spf_clean)
                sender_ip = ip_match.group(1) if ip_match else None

                domain_match = RE_MAILFROM.search(spf_clean)
                domain = domain_match.group(1) if domain_match else None

                explanation = cls._generate_spf_explanation(status, domain, sender_ip)

                return ProtocolAuthResult(
                    protocol="spf",
                    status=status,
                    normalized_status=normalize_auth_status(status),
                    domain=domain,
                    sender_ip=sender_ip,
                    evidence=spf_clean.split(";")[0].strip(),
                    source_header="received-spf",
                    explanation=explanation,
                )

        # 3. No SPF information available
        return ProtocolAuthResult(
            protocol="spf",
            status=AuthStatus.UNKNOWN,
            normalized_status="unknown",
            explanation="No SPF authentication information found in email headers.",
        )

    @classmethod
    def _evaluate_dkim(cls, raw_headers: dict[str, Any]) -> ProtocolAuthResult:
        """Extracts and normalizes DKIM outcome from Authentication-Results or DKIM-Signature."""
        # 1. Search in Authentication-Results / ARC-Authentication-Results
        for header_name in (
            "authentication-results",
            "arc-authentication-results",
            "x-authentication-results",
        ):
            header_vals = cls._get_header_values(raw_headers, header_name)
            for val in header_vals:
                val_clean = " ".join(val.split())
                match = RE_DKIM_CLAUSE.search(val_clean)
                if match:
                    raw_status_str = match.group(1).lower()
                    try:
                        status = AuthStatus(raw_status_str)
                    except ValueError:
                        status = AuthStatus.UNKNOWN

                    domain_match = RE_HEADER_D.search(val_clean)
                    domain = domain_match.group(1) if domain_match else None

                    selector_match = RE_HEADER_S.search(val_clean)
                    selector = selector_match.group(1) if selector_match else None

                    explanation = cls._generate_dkim_explanation(status, domain, selector)

                    return ProtocolAuthResult(
                        protocol="dkim",
                        status=status,
                        normalized_status=normalize_auth_status(status),
                        domain=domain,
                        selector=selector,
                        evidence=match.group(0).strip(),
                        source_header=header_name,
                        explanation=explanation,
                    )

        # 2. Check if DKIM-Signature header exists without verification result
        dkim_sigs = cls._get_header_values(raw_headers, "dkim-signature")
        if dkim_sigs:
            return ProtocolAuthResult(
                protocol="dkim",
                status=AuthStatus.NONE,
                normalized_status="none",
                source_header="dkim-signature",
                explanation="DKIM signature is attached but receiving MTA did not record verification result.",
            )

        # 3. No DKIM header present
        return ProtocolAuthResult(
            protocol="dkim",
            status=AuthStatus.NONE,
            normalized_status="none",
            explanation="No DKIM signature or verification record found in headers.",
        )

    @classmethod
    def _evaluate_dmarc(cls, raw_headers: dict[str, Any]) -> ProtocolAuthResult:
        """Extracts and normalizes DMARC outcome from Authentication-Results."""
        for header_name in (
            "authentication-results",
            "arc-authentication-results",
            "x-authentication-results",
        ):
            header_vals = cls._get_header_values(raw_headers, header_name)
            for val in header_vals:
                val_clean = " ".join(val.split())
                match = RE_DMARC_CLAUSE.search(val_clean)
                if match:
                    raw_status_str = match.group(1).lower()
                    try:
                        status = AuthStatus(raw_status_str)
                    except ValueError:
                        status = AuthStatus.UNKNOWN

                    domain_match = RE_HEADER_FROM.search(val_clean)
                    domain = domain_match.group(1) if domain_match else None

                    explanation = cls._generate_dmarc_explanation(status, domain)

                    return ProtocolAuthResult(
                        protocol="dmarc",
                        status=status,
                        normalized_status=normalize_auth_status(status),
                        domain=domain,
                        evidence=match.group(0).strip(),
                        source_header=header_name,
                        explanation=explanation,
                    )

        return ProtocolAuthResult(
            protocol="dmarc",
            status=AuthStatus.UNKNOWN,
            normalized_status="unknown",
            explanation="No DMARC policy evaluation found in authentication headers.",
        )

    @staticmethod
    def _generate_spf_explanation(status: AuthStatus, domain: str | None, ip: str | None) -> str:
        d_str = f" for domain '{domain}'" if domain else ""
        ip_str = f" from IP {ip}" if ip else ""

        if status == AuthStatus.PASS:
            return f"SPF verified successfully: Transmitting host{ip_str} is explicitly authorized{d_str}."
        elif status == AuthStatus.FAIL:
            return f"SPF check FAILED: Host{ip_str} is NOT authorized to send on behalf of{d_str}."
        elif status == AuthStatus.SOFTFAIL:
            return f"SPF SOFTFAIL: Host{ip_str} is discouraged by domain policy{d_str}."
        elif status == AuthStatus.NEUTRAL:
            return f"SPF NEUTRAL: Domain owner{d_str} has not explicitly asserted sending host legitimacy."
        elif status == AuthStatus.NONE:
            return f"SPF NONE: No published SPF record found{d_str}."
        else:
            return f"SPF evaluation returned {status.value}{d_str}."

    @staticmethod
    def _generate_dkim_explanation(
        status: AuthStatus, domain: str | None, selector: str | None
    ) -> str:
        d_str = f" for domain '{domain}'" if domain else ""
        s_str = f" (selector: '{selector}')" if selector else ""

        if status == AuthStatus.PASS:
            return f"DKIM verified successfully: Cryptographic signature{s_str} matches sender identity{d_str}."
        elif status == AuthStatus.FAIL:
            return f"DKIM verification FAILED: Signature is invalid or message body has been tampered with{d_str}."
        elif status == AuthStatus.NEUTRAL:
            return (
                f"DKIM NEUTRAL: Signature exists but verification returned neutral status{d_str}."
            )
        elif status == AuthStatus.NONE:
            return f"DKIM NONE: Message was not cryptographically signed{d_str}."
        else:
            return f"DKIM verification returned {status.value}{d_str}."

    @staticmethod
    def _generate_dmarc_explanation(status: AuthStatus, domain: str | None) -> str:
        d_str = f" for From domain '{domain}'" if domain else ""

        if status == AuthStatus.PASS:
            return f"DMARC policy PASSED: SPF and/or DKIM alignment validated{d_str}."
        elif status == AuthStatus.FAIL:
            return f"DMARC policy check FAILED: Neither SPF nor DKIM alignment passed for sender{d_str}."
        elif status == AuthStatus.NEUTRAL:
            return f"DMARC policy NEUTRAL: Sender domain published a neutral policy{d_str}."
        elif status == AuthStatus.NONE:
            return f"DMARC NONE: No published DMARC policy record found{d_str}."
        else:
            return f"DMARC evaluation returned {status.value}{d_str}."

    def analyze_authentication(self, raw_headers: dict[str, Any]) -> NormalizedEmailAuthentication:
        """Evaluates complete authentication posture across SPF, DKIM, and DMARC."""
        headers_found: list[str] = []
        for k, v in raw_headers.items():
            k_lower = k.lower()
            if k_lower in (
                "authentication-results",
                "arc-authentication-results",
                "x-authentication-results",
                "received-spf",
                "dkim-signature",
            ):
                if isinstance(v, list):
                    headers_found.extend([k] * len(v))
                else:
                    headers_found.append(k)

        spf_result = self._evaluate_spf(raw_headers)
        dkim_result = self._evaluate_dkim(raw_headers)
        dmarc_result = self._evaluate_dmarc(raw_headers)

        explanations: list[str] = [
            spf_result.explanation,
            dkim_result.explanation,
            dmarc_result.explanation,
        ]

        # Determine overall authentication posture
        if (
            dmarc_result.status == AuthStatus.FAIL
            or spf_result.status == AuthStatus.FAIL
            or dkim_result.status == AuthStatus.FAIL
        ):
            overall_posture = "FAILED"
        elif spf_result.status == AuthStatus.SOFTFAIL:
            overall_posture = "SUSPICIOUS"
        elif dmarc_result.status == AuthStatus.PASS or (
            spf_result.status == AuthStatus.PASS and dkim_result.status == AuthStatus.PASS
        ):
            overall_posture = "VALIDATED"
        elif spf_result.status == AuthStatus.PASS or dkim_result.status == AuthStatus.PASS:
            overall_posture = "VALIDATED"
        else:
            overall_posture = "UNAUTHENTICATED"

        return NormalizedEmailAuthentication(
            spf=spf_result,
            dkim=dkim_result,
            dmarc=dmarc_result,
            overall_posture=overall_posture,
            explanations=explanations,
            source_headers_found=headers_found,
        )


# Default singleton instance
default_auth_analyzer = EmailAuthenticationAnalyzer()
