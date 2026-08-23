import re
from typing import Any
from urllib.parse import urlparse

from src.services.detector.interface import ThreatDetector
from src.services.detector.types import ThreatCategory, ThreatDetectionResult

# Compiled Regex Heuristic Matchers
RE_URGENCY = re.compile(
    r"\b(immediate(?:ly)?|urgent|24 hours?|48 hours?|action required|critical alert|deadline|expir(?:es?|ing|ation)|service termination|immediate action|act now)\b",
    re.IGNORECASE,
)

RE_CREDENTIALS = re.compile(
    r"\b(verify(?:ing)? password|confirm (?:your )?login|reset (?:your )?credentials?|account verification|update (?:your )?password|validate (?:your )?identity|sign in to verify|session expired|re-authenticate)\b",
    re.IGNORECASE,
)

RE_PAYMENT_BEC = re.compile(
    r"\b(wire transfer|overdue invoice|remit(?:tance)?|bank details|routing number|swift code|beneficiary account|payment portal|settlement|invoice #|remit payment|wire action|new bank account)\b",
    re.IGNORECASE,
)

RE_AUTHORITY = re.compile(
    r"\b(CEO|Chief Executive|Finance Director|Chief Financial Officer|CFO|Managing Director|IT Helpdesk|IT Support|Security Desk|Security Administrator|System Administrator|Executive Office|President)\b",
    re.IGNORECASE,
)

RE_SUSPENSION = re.compile(
    r"\b(account (?:will be|is|has been) suspended|permanent lockout|mailbox (?:will be )?deactivated|unauthorized access|restricted access|legal collections|prevent legal collections)\b",
    re.IGNORECASE,
)

RE_SPAM = re.compile(
    r"\b(congratulations|sweepstakes|lottery|cash grant|randomly selected|won \$|claim (?:your )?prize|exclusive discount|flash sale|special promotion|50% off|winner-entry|lucky winner)\b",
    re.IGNORECASE,
)

RE_IP_IN_URL = re.compile(r"https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", re.IGNORECASE)


class RuleBasedThreatDetector(ThreatDetector):
    """Deterministic heuristic threat detection engine with full explainability.

    Identifies threat categories (normal, spam, phishing, BEC) and provides
    auditable reason codes and signal breakdowns.
    """

    MODEL_VERSION = "rule-based-heuristic-v1.0.0-dev"

    def detect(self, email_data: Any) -> ThreatDetectionResult:
        """Evaluates email headers, body content, and extracted URLs against heuristic rules."""
        subject = str(getattr(email_data, "subject", "") or "")
        body_plain = str(getattr(email_data, "body_plain", "") or "")
        body_html = str(getattr(email_data, "body_html", "") or "")
        sender = str(getattr(email_data, "sender", "") or "")
        from_name = str(getattr(email_data, "from_name", "") or "")
        urls = list(getattr(email_data, "extracted_urls", []) or [])

        # Combined text corpus for keyword scanning
        corpus = f"{subject} {from_name} {sender} {body_plain} {body_html}"

        # 1. Collect Active Heuristic Signals
        signals: dict[str, list[str]] = {}

        urgency_matches = list({m.group(0).lower() for m in RE_URGENCY.finditer(corpus)})
        if urgency_matches:
            signals["urgency"] = urgency_matches

        credential_matches = list({m.group(0).lower() for m in RE_CREDENTIALS.finditer(corpus)})
        if credential_matches:
            signals["credentials"] = credential_matches

        payment_matches = list({m.group(0).lower() for m in RE_PAYMENT_BEC.finditer(corpus)})
        if payment_matches:
            signals["payment_bec"] = payment_matches

        authority_matches = list({m.group(0).lower() for m in RE_AUTHORITY.finditer(corpus)})
        if authority_matches:
            signals["authority"] = authority_matches

        suspension_matches = list({m.group(0).lower() for m in RE_SUSPENSION.finditer(corpus)})
        if suspension_matches:
            signals["suspension"] = suspension_matches

        spam_matches = list({m.group(0).lower() for m in RE_SPAM.finditer(corpus)})
        if spam_matches:
            signals["spam"] = spam_matches

        # URL Anomalies (Raw IPs, credential keywords in path)
        url_anomalies: list[str] = []
        for url in urls:
            if RE_IP_IN_URL.search(url):
                url_anomalies.append(f"Direct IP target in URL: {url}")
            try:
                parsed_u = urlparse(url)
                if any(
                    kw in parsed_u.path.lower()
                    for kw in ["verify", "login", "auth", "session", "remit"]
                ):
                    url_anomalies.append(f"Suspicious path keyword in URL: {parsed_u.path}")
            except Exception:
                pass
        if url_anomalies:
            signals["url_anomalies"] = url_anomalies

        # 2. Multi-Class Decision Matrix & Explainability
        reasons: list[str] = []
        classification = ThreatCategory.NORMAL
        confidence = 0.90

        # Scenario A: Business Email Compromise (BEC)
        if "payment_bec" in signals and ("authority" in signals or "urgency" in signals):
            classification = ThreatCategory.BEC
            matched_count = len(signals.get("payment_bec", [])) + len(signals.get("authority", []))
            confidence = min(0.95, 0.80 + (matched_count * 0.03))

            reasons.append(
                f"Financial wire/remittance patterns identified: {', '.join(signals['payment_bec'])}"
            )
            if "authority" in signals:
                reasons.append(
                    f"Executive or authority role referenced: {', '.join(signals['authority'])}"
                )
            if "urgency" in signals:
                reasons.append(
                    f"High-urgency language coercing immediate transaction: {', '.join(signals['urgency'])}"
                )

        # Scenario B: Phishing (Credential Harvesting or Account Coercion)
        elif "credentials" in signals or (
            "suspension" in signals and ("urgency" in signals or "url_anomalies" in signals)
        ):
            classification = ThreatCategory.PHISHING
            matched_count = (
                len(signals.get("credentials", []))
                + len(signals.get("suspension", []))
                + len(signals.get("url_anomalies", []))
            )
            confidence = min(0.95, 0.82 + (matched_count * 0.03))

            if "credentials" in signals:
                reasons.append(
                    f"Credential harvesting language detected: {', '.join(signals['credentials'])}"
                )
            if "suspension" in signals:
                reasons.append(
                    f"Account lockout/suspension threat detected: {', '.join(signals['suspension'])}"
                )
            if "url_anomalies" in signals:
                reasons.append(
                    f"Suspicious URL indicators present: {', '.join(signals['url_anomalies'])}"
                )
            if "urgency" in signals:
                reasons.append(
                    f"Urgency pressure to bypass scrutiny: {', '.join(signals['urgency'])}"
                )

        # Scenario C: Spam / Lottery / Sweepstakes Promo
        elif "spam" in signals:
            classification = ThreatCategory.SPAM
            confidence = min(0.90, 0.75 + (len(signals["spam"]) * 0.04))
            reasons.append(
                f"Unsolicited sweepstakes, prize, or promotional marketing language: {', '.join(signals['spam'])}"
            )

        # Scenario D: Normal / Clean
        else:
            classification = ThreatCategory.NORMAL
            confidence = 0.92
            reasons.append(
                "No active phishing, credential harvesting, wire fraud, or spam patterns detected."
            )

        return ThreatDetectionResult(
            classification=classification,
            confidence=round(confidence, 2),
            reasons=reasons,
            model_version=self.MODEL_VERSION,
            signals_detected=signals,
        )


# Default singleton instance
default_rule_detector = RuleBasedThreatDetector()
