"""Parser package - auto-registers all vendor parsers."""

from parsers.base import (
    ParseError,
    VendorAST,
    VendorParser,
    auto_detect_vendor,
    get_parser,
    list_parsers,
    register_parser,
)
from parsers.paloalto import PaloAltoParser

register_parser(PaloAltoParser)

from parsers.fortinet import FortinetParser

register_parser(FortinetParser)

from parsers.cisco_asa import CiscoASAParser

register_parser(CiscoASAParser)

__all__ = [
    "VendorParser",
    "VendorAST",
    "ParseError",
    "register_parser",
    "get_parser",
    "list_parsers",
    "auto_detect_vendor",
]
