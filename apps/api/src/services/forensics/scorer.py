import ipaddress
from typing import Any
from src.services.forensics.types import OriginCandidateScore, RelayHop

KNOWN_TRUSTED = [
    "google.com",
    "outlook.com",
    "mimecast.com",
    "proofpoint.com",
    "microsoft.com",
    "amazon.com",
    "sendgrid.net",
    "mailgun.org"
]

class OriginCandidateScorer:
    def score_origin_candidates(self, hops: list[RelayHop], auth_details: Any = None) -> OriginCandidateScore:
        best_candidate: str | None = None
        best_score = -1.0
        best_reasons = []
        limitations = []
        
        candidates = []
        for hop in hops:
            if hop.ip_address and hop.ip_address not in candidates:
                candidates.append(hop)
                
        if not candidates:
            return OriginCandidateScore(
                candidate_ip="Unknown",
                candidate_score=0.0,
                reasons=["No candidate IP addresses found in relay hops."],
                confidence=0.0,
                limitations=["Received headers may be missing or stripped."]
            )
            
        # Check chronological consistency globally
        chronologically_consistent = True
        last_dt = None
        for hop in hops:
            if hop.timestamp_parsed:
                if last_dt and hop.timestamp_parsed < last_dt:
                    chronologically_consistent = False
                last_dt = hop.timestamp_parsed

        for hop in candidates:
            score = 50.0
            reasons = []
            
            ip = hop.ip_address
            is_private = hop.is_private_ip
            
            if is_private:
                score -= 40.0
                reasons.append(f"IP {ip} is in a private/reserved address space.")
            else:
                score += 20.0
                reasons.append(f"IP {ip} is publicly routable.")
                
            # Chronology
            if not chronologically_consistent:
                score -= 10.0
                reasons.append("Relay chain has impossible timestamp ordering (backwards in time).")
            else:
                score += 10.0
                reasons.append("Relay chain chronology is consistent.")
                
            # Header consistency
            if not hop.from_host:
                score -= 5.0
                reasons.append("Missing sending hostname.")
                
            # Trusted infrastructure
            trusted = False
            for t in KNOWN_TRUSTED:
                if hop.from_host and t in hop.from_host.lower():
                    trusted = True
                    break
                if hop.by_host and t in hop.by_host.lower():
                    trusted = True
                    break
                    
            if trusted:
                score += 10.0
                reasons.append("Flows through known trusted mail infrastructure.")
                
            # Auth evidence
            if auth_details and hasattr(auth_details, "spf_status"):
                if auth_details.spf_status == "pass":
                    score += 10.0
                    reasons.append("SPF authentication passed for this path.")
                elif auth_details.spf_status == "fail":
                    score -= 10.0
                    reasons.append("SPF authentication failed, potentially forged.")
                    
            if hop.validation_issues:
                score -= len(hop.validation_issues) * 10.0
                for issue in hop.validation_issues:
                    reasons.append(f"Anomaly: {issue}")
                    
            if hop.untrusted_node:
                score -= 30.0
                reasons.append("Node flagged as untrusted/unresolvable.")

            # Ensure we favor the earliest public hop
            # The earliest public hop usually gets higher priority
            if not is_private and best_candidate is None:
                score += 5.0 # tie breaker for earliest
                
            # Restrict score range
            score = max(0.0, min(100.0, score))
            
            if score > best_score:
                best_score = score
                best_candidate = ip
                best_reasons = reasons
                
        if not chronologically_consistent:
            limitations.append("Timestamp inconsistencies reduce reliability of the origin sequence.")
            
        return OriginCandidateScore(
            candidate_ip=best_candidate or candidates[0].ip_address,
            candidate_score=best_score,
            reasons=best_reasons,
            confidence=best_score / 100.0,
            limitations=limitations
        )
