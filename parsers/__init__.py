"""Parser package - auto-registers all vendor parsers."""

from parsers.base import (
    VendorParser,
    VendorAST,
    ParseError,
    register_parser,
    get_parser,
    list_parsers,
    auto_detect_vendor,
)

from parsers.paloalto import PaloAltoParser
register_parser(PaloAltoParser)

__all__ = [
    "VendorParser",
    "VendorAST",
    "ParseError",
    "register_parser",
    "get_parser",
    "list_parsers",
    "auto_detect_vendor",
]
