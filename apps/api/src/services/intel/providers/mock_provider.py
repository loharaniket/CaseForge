from src.services.intel.types import (
    DomainReputationProvider,
    IPReputationProvider,
    ProviderStatus,
    ReputationResult,
)


class MockIPReputationProvider(IPReputationProvider):
    """Deterministic development and offline testing IP threat intelligence provider."""

    KNOWN_MALICIOUS_IPS = {
        "198.51.100.200": (95.0, ["botnet", "phishing_host", "c2"]),
        "198.51.100.25": (85.0, ["spam_relay", "credential_harvesting"]),
        "203.0.113.199": (75.0, ["spoof_relay"]),
        "198.51.100.45": (80.0, ["malware_distribution"]),
    }

    KNOWN_CLEAN_IPS = {
        "192.0.2.15": (0.0, ["authorized_relay"]),
        "198.51.100.90": (0.0, ["verified_mta"]),
        "192.0.2.88": (0.0, ["trusted_vendor_mta"]),
    }

    @property
    def provider_name(self) -> str:
        return "MockIPIntelProvider"

    async def lookup_ip(self, ip: str) -> ReputationResult:
        clean_ip = ip.strip()

        if clean_ip in self.KNOWN_MALICIOUS_IPS:
            score, tags = self.KNOWN_MALICIOUS_IPS[clean_ip]
            return ReputationResult(
                indicator=clean_ip,
                indicator_type="ip",
                provider_name=self.provider_name,
                status=ProviderStatus.SUCCESS,
                reputation_score=score,
                is_malicious=score >= 50.0,
                threat_tags=tags,
                details={"mock_matched": True, "category": "malicious_indicator"},
                attribution="ThreatTrace Mock Intelligence DB",
            )

        if clean_ip in self.KNOWN_CLEAN_IPS:
            score, tags = self.KNOWN_CLEAN_IPS[clean_ip]
            return ReputationResult(
                indicator=clean_ip,
                indicator_type="ip",
                provider_name=self.provider_name,
                status=ProviderStatus.SUCCESS,
                reputation_score=score,
                is_malicious=False,
                threat_tags=tags,
                details={"mock_matched": True, "category": "clean_indicator"},
                attribution="ThreatTrace Mock Intelligence DB",
            )

        # Default fallback for unknown IP
        return ReputationResult(
            indicator=clean_ip,
            indicator_type="ip",
            provider_name=self.provider_name,
            status=ProviderStatus.SUCCESS,
            reputation_score=0.0,
            is_malicious=False,
            threat_tags=["unclassified"],
            details={"mock_matched": False},
            attribution="ThreatTrace Mock Intelligence DB",
        )


class MockDomainReputationProvider(DomainReputationProvider):
    """Deterministic development and offline testing Domain threat intelligence provider."""

    KNOWN_MALICIOUS_DOMAINS = {
        "attacker-infra.com": (92.0, ["phishing", "c2_domain"]),
        "phish-login.attacker-infra.com": (98.0, ["credential_phishing"]),
        "covert-attacker.org": (85.0, ["spoofed_domain"]),
        "attacker-c2.net": (90.0, ["c2_infrastructure"]),
        "dark-web.org": (88.0, ["darkweb_drop"]),
    }

    KNOWN_CLEAN_DOMAINS = {
        "security-ops.com": (0.0, ["verified_enterprise"]),
        "victim-corp.com": (0.0, ["internal_domain"]),
        "trusted-vendor.com": (0.0, ["partner_domain"]),
    }

    @property
    def provider_name(self) -> str:
        return "MockDomainIntelProvider"

    async def lookup_domain(self, domain: str) -> ReputationResult:
        clean_domain = domain.strip().lower()

        if clean_domain in self.KNOWN_MALICIOUS_DOMAINS:
            score, tags = self.KNOWN_MALICIOUS_DOMAINS[clean_domain]
            return ReputationResult(
                indicator=clean_domain,
                indicator_type="domain",
                provider_name=self.provider_name,
                status=ProviderStatus.SUCCESS,
                reputation_score=score,
                is_malicious=score >= 50.0,
                threat_tags=tags,
                details={"mock_matched": True, "category": "malicious_indicator"},
                attribution="ThreatTrace Mock Intelligence DB",
            )

        if clean_domain in self.KNOWN_CLEAN_DOMAINS:
            score, tags = self.KNOWN_CLEAN_DOMAINS[clean_domain]
            return ReputationResult(
                indicator=clean_domain,
                indicator_type="domain",
                provider_name=self.provider_name,
                status=ProviderStatus.SUCCESS,
                reputation_score=score,
                is_malicious=False,
                threat_tags=tags,
                details={"mock_matched": True, "category": "clean_indicator"},
                attribution="ThreatTrace Mock Intelligence DB",
            )

        # Default fallback for unknown domain
        return ReputationResult(
            indicator=clean_domain,
            indicator_type="domain",
            provider_name=self.provider_name,
            status=ProviderStatus.SUCCESS,
            reputation_score=0.0,
            is_malicious=False,
            threat_tags=["unclassified"],
            details={"mock_matched": False},
            attribution="ThreatTrace Mock Intelligence DB",
        )
