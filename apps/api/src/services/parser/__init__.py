"""Forensic email parsing abstractions and implementations."""

from src.services.parser.eml_parser import EMLParser, default_eml_parser
from src.services.parser.interface import EmailParser
from src.services.parser.types import AttachmentMetadata, ParsedEmailData
from src.services.parser.url_extractor import extract_urls

__all__ = [
    "AttachmentMetadata",
    "EMLParser",
    "EmailParser",
    "ParsedEmailData",
    "default_eml_parser",
    "extract_urls",
]
