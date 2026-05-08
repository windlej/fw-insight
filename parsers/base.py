"""Parser registry and base classes."""

from abc import ABC, abstractmethod
from typing import Any

_PARSER_REGISTRY: dict[str, type] = {}


class ParseError(Exception):
    """Raised when a config cannot be parsed."""

    def __init__(self, message: str, line_number: int | None = None):
        self.line_number = line_number
        detail = f" at line {line_number}" if line_number else ""
        super().__init__(f"Parse error{detail}: {message}")


class VendorAST(dict):
    """Vendor-specific abstract syntax tree.

    This is a TypedDict-like dict that parsers populate with
    vendor-specific extracted data.
    """

    pass


class VendorParser(ABC):
    """Base class for vendor-specific config parsers."""

    VENDOR_ID: str = ""

    @abstractmethod
    def parse(self, raw_config: str | bytes) -> VendorAST:
        """Parse raw config into a vendor-specific AST.

        Args:
            raw_config: Raw config content (string or bytes)

        Returns:
            VendorAST dict with extracted data

        Raises:
            ParseError: On unrecoverable parsing failures
        """

    @abstractmethod
    def normalize(self, ast: VendorAST) -> dict[str, Any]:
        """Convert vendor AST to canonical Session-compatible dict.

        The returned dict should have keys matching the Session model
        fields (security_policies, nat_rules, etc.).

        Args:
            ast: Vendor-specific AST from parse()

        Returns:
            Dict compatible with Session.model_validate()
        """


def register_parser(parser_class: type[VendorParser]) -> None:
    """Register a parser class in the global registry."""
    if not parser_class.VENDOR_ID:
        raise ValueError(f"Parser {parser_class.__name__} has no VENDOR_ID")
    _PARSER_REGISTRY[parser_class.VENDOR_ID] = parser_class


def get_parser(vendor_id: str) -> VendorParser:
    """Get a parser instance by vendor ID.

    Args:
        vendor_id: Vendor identifier (e.g., "paloalto")

    Returns:
        Parser instance

    Raises:
        ValueError: If no parser is registered for the vendor
    """
    if vendor_id not in _PARSER_REGISTRY:
        available = ", ".join(sorted(_PARSER_REGISTRY.keys()))
        raise ValueError(
            f"No parser registered for vendor '{vendor_id}'. Available: {available}"
        )
    return _PARSER_REGISTRY[vendor_id]()


def list_parsers() -> list[str]:
    """List all registered parser vendor IDs."""
    return sorted(_PARSER_REGISTRY.keys())


def auto_detect_vendor(raw_config: str | bytes) -> str | None:
    """Attempt to detect vendor from config content.

    Returns vendor ID or None if detection fails.
    """
    if isinstance(raw_config, bytes):
        try:
            content = raw_config.decode("utf-8", errors="ignore")
        except Exception:
            return None
    else:
        content = raw_config

    if "<config" in content and "<devices" in content:
        return "paloalto"
    if "config system" in content and "end" in content:
        return "fortinet"
    if "ASA Version" in content:
        return "cisco_asa"
    if "object network" in content and "access-list" in content:
        return "cisco_asa"

    return None
