from abc import ABC, abstractmethod

from src.services.parser.types import ParsedEmailData


class EmailParser(ABC):
    """Abstract interface for email forensic parsing implementations."""

    @abstractmethod
    def parse(self, raw_content: bytes) -> ParsedEmailData:
        """Parses raw email bytes into structured forensic email data.

        Args:
            raw_content: Untrusted raw email byte payload.

        Returns:
            ParsedEmailData containing decoded headers, body, attachment hashes, and URLs.
        """
        pass
