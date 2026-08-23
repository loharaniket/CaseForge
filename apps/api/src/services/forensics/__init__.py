"""Header forensics and email authentication analysis package."""

from src.services.forensics.auth_analyzer import (
    AuthStatus,
    EmailAuthenticationAnalyzer,
    NormalizedEmailAuthentication,
    ProtocolAuthResult,
    default_auth_analyzer,
    normalize_auth_status,
)
from src.services.forensics.service import (
    HeaderForensicsService,
    default_forensics_service,
    get_forensics_service,
)
from src.services.forensics.types import (
    AuthenticationResult,
    AuthenticationStatus,
    HeaderForensicsResult,
    RelayHop,
)

__all__ = [
    "AuthStatus",
    "AuthenticationResult",
    "AuthenticationStatus",
    "EmailAuthenticationAnalyzer",
    "HeaderForensicsResult",
    "HeaderForensicsService",
    "NormalizedEmailAuthentication",
    "ProtocolAuthResult",
    "RelayHop",
    "default_auth_analyzer",
    "default_forensics_service",
    "get_forensics_service",
    "normalize_auth_status",
]
