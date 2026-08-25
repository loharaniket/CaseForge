import re
from typing import Any, List, Dict
from dataclasses import dataclass, field, asdict

from src.services.detector.interface import ThreatDetector
from src.services.detector.types import ThreatCategory, ThreatDetectionResult
from src.services.detector.rule_based import default_rule_detector

@dataclass
class StructuredSignal:
    signal: str
    severity: str
    evidence: str
    confidence: float

class BaseExtendedDetector:
    def detect_signals(self, context: Any) -> List[StructuredSignal]:
        return []

class PhishingDetector(BaseExtendedDetector):
    def detect_signals(self, context: Any) -> List[StructuredSignal]:
        signals = []
        body_text = str(getattr(context, "body_plain", "") or "").lower()
        if "update your account" in body_text or "verify your identity" in body_text:
            signals.append(StructuredSignal(
                signal="CREDENTIAL_THEFT_LURE",
                severity="HIGH",
                evidence="Language indicating account verification or update coercion.",
                confidence=0.85
            ))
        return signals

class ImpersonationDetector(BaseExtendedDetector):
    def detect_signals(self, context: Any) -> List[StructuredSignal]:
        signals = []
        sender = str(getattr(context, "sender", "") or "")
        from_name = str(getattr(context, "from_name", "") or "")
        reply_to_list = getattr(context, "reply_to", []) or []
        
        # Check Reply-To Mismatch
        if reply_to_list and sender:
            # Simple check if sender domain differs from reply-to domain
            try:
                sender_domain = sender.split("@")[-1].lower() if "@" in sender else ""
                reply_to = reply_to_list[0] if reply_to_list else ""
                reply_domain = reply_to.split("@")[-1].lower() if "@" in reply_to else ""
                
                if sender_domain and reply_domain and sender_domain != reply_domain:
                    signals.append(StructuredSignal(
                        signal="REPLY_TO_MISMATCH",
                        severity="HIGH",
                        evidence=f"Sender domain ({sender_domain}) differs from Reply-To domain ({reply_domain}).",
                        confidence=0.91
                    ))
            except Exception:
                pass
                
        # Check authentication results
        auth_details = getattr(context, "auth_details", {})
        if auth_details:
            if auth_details.get("spf_status") == "fail" or auth_details.get("dkim_status") == "fail":
                signals.append(StructuredSignal(
                    signal="AUTH_FAILURE",
                    severity="HIGH",
                    evidence="SPF or DKIM validation failed, indicating possible domain spoofing.",
                    confidence=0.95
                ))
                
        return signals

class BECDetector(BaseExtendedDetector):
    def detect_signals(self, context: Any) -> List[StructuredSignal]:
        signals = []
        body_text = str(getattr(context, "body_plain", "") or "").lower()
        subject = str(getattr(context, "subject", "") or "").lower()
        
        bec_evidence = []
        if "wire transfer" in body_text or "transfer" in subject:
            bec_evidence.append("payment request")
        if "bank account" in body_text or "routing number" in body_text or "new bank" in body_text:
            bec_evidence.append("bank account change")
        if "invoice" in body_text and ("overdue" in body_text or "unpaid" in body_text):
            bec_evidence.append("invoice fraud")
        if "ceo" in body_text or "president" in body_text or "executive" in body_text:
            bec_evidence.append("executive impersonation")
        if "payroll" in body_text and "direct deposit" in body_text:
            bec_evidence.append("payroll change")
        if "gift card" in body_text or "gift cards" in body_text:
            bec_evidence.append("gift-card request")
        if "urgent" in body_text and ("payment" in body_text or "fund" in body_text):
            bec_evidence.append("urgent financial request")
        if "confidential" in body_text and ("request" in body_text or "favor" in body_text):
            bec_evidence.append("confidential request")
            
        if bec_evidence:
            signals.append(StructuredSignal(
                signal="BEC_INDICATORS_PRESENT",
                severity="HIGH",
                evidence=f"BEC patterns identified: {', '.join(bec_evidence)}.",
                confidence=0.90
            ))
            
        return signals

class CredentialHarvestingDetector(BaseExtendedDetector):
    def detect_signals(self, context: Any) -> List[StructuredSignal]:
        signals = []
        # URL intel check
        url_intel = getattr(context, "url_intel", [])
        for record in url_intel:
            if getattr(record, "has_credential_path", False):
                signals.append(StructuredSignal(
                    signal="CREDENTIAL_PATH_URL",
                    severity="CRITICAL",
                    evidence=f"URL path suggests credential harvesting: {getattr(record, 'raw_url', '')}.",
                    confidence=0.98
                ))
            if getattr(record, "is_lookalike", False):
                signals.append(StructuredSignal(
                    signal="LOOKALIKE_DOMAIN_URL",
                    severity="HIGH",
                    evidence=f"Lookalike domain detected in URL: {getattr(record, 'raw_url', '')}.",
                    confidence=0.95
                ))
        return signals

class FinancialFraudDetector(BaseExtendedDetector):
    def detect_signals(self, context: Any) -> List[StructuredSignal]:
        signals = []
        body_text = str(getattr(context, "body_plain", "") or "").lower()
        if "swift code" in body_text or "sort code" in body_text or "beneficiary" in body_text:
            signals.append(StructuredSignal(
                signal="FINANCIAL_FRAUD_TERMS",
                severity="MEDIUM",
                evidence="Financial settlement terms detected.",
                confidence=0.75
            ))
        return signals

class CompositeExtendedThreatDetector(ThreatDetector):
    def __init__(self, base_detector: ThreatDetector):
        self.base_detector = base_detector
        self.detectors = [
            PhishingDetector(),
            ImpersonationDetector(),
            BECDetector(),
            CredentialHarvestingDetector(),
            FinancialFraudDetector()
        ]
        
    def detect(self, email_data: Any) -> ThreatDetectionResult:
        # Run base detector first
        base_result = self.base_detector.detect(email_data)
        
        all_signals: List[StructuredSignal] = []
        for det in self.detectors:
            try:
                all_signals.extend(det.detect_signals(email_data))
            except Exception:
                pass
                
        # Upgrade classification if high confidence signals are present
        if all_signals:
            # We don't overwrite blindly, but we add structured signals
            base_result.signals_detected["structured_signals"] = [asdict(s) for s in all_signals]
            
            # Map specific signals to classification overrides safely
            highest_sev = any(s.severity in ("CRITICAL", "HIGH") for s in all_signals)
            
            # If base was NORMAL but we found HIGH severity structured signals, upgrade appropriately
            if base_result.classification == ThreatCategory.NORMAL and highest_sev:
                has_bec = any(s.signal == "BEC_INDICATORS_PRESENT" for s in all_signals)
                has_phish = any("CREDENTIAL" in s.signal for s in all_signals)
                has_spoof = any(s.signal in ("REPLY_TO_MISMATCH", "AUTH_FAILURE") for s in all_signals)
                
                if has_bec:
                    base_result.classification = ThreatCategory.BEC
                    base_result.confidence = max(base_result.confidence, 0.90)
                    base_result.reasons.append("BEC indicators detected by extended heuristics.")
                elif has_phish or has_spoof:
                    base_result.classification = ThreatCategory.PHISHING
                    base_result.confidence = max(base_result.confidence, 0.85)
                    base_result.reasons.append("Phishing or Impersonation indicators detected by extended heuristics.")

            # Append evidence to reasons
            for s in all_signals:
                if s.severity in ("CRITICAL", "HIGH"):
                    base_result.reasons.append(f"[{s.signal}] {s.evidence}")
                    
        return base_result

extended_detector = CompositeExtendedThreatDetector(default_rule_detector)
