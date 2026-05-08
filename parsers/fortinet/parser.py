"""Fortinet FortiGate CLI configuration parser.

Parses FortiGate CLI config exports (text format) and extracts:
- System settings (hostname, version)
- VDOMs (multi-vdom support)
- Interfaces
- Firewall policies (IPv4, policy46, policy64)
- Address objects and address groups
- Service objects and service groups
- Central NAT rules
- IP pools

The FortiGate CLI uses a block-based structure:
    config <section>
        edit <name_or_id>
            set <field> <value>
        next
    end

This parser uses a stack-based approach to track nested blocks.
"""

import logging
import re
from typing import Any

from parsers.base import VendorAST, VendorParser
from parsers.fortinet.normalizer import normalize_fortinet

logger = logging.getLogger(__name__)


class FortinetParser(VendorParser):
    """Parser for Fortinet FortiGate CLI configuration exports."""

    VENDOR_ID = "fortinet"

    POLICY_SECTIONS = (
        "firewall policy",
        "firewall policy46",
        "firewall policy64",
    )

    def parse(self, raw_config: str | bytes) -> VendorAST:
        """Parse FortiGate CLI config into a vendor-specific AST.

        Args:
            raw_config: CLI config content (string or bytes)

        Returns:
            VendorAST with extracted config data

        Raises:
            ParseError: If config structure is malformed
        """
        if isinstance(raw_config, bytes):
            text = raw_config.decode("utf-8", errors="replace")
        else:
            text = raw_config

        lines = text.splitlines()
        ast = VendorAST()
        ast["system"] = {}
        ast["interfaces"] = []
        ast["zones"] = []
        ast["address_objects"] = []
        ast["address_groups"] = []
        ast["service_objects"] = []
        ast["service_groups"] = []
        ast["policies"] = []
        ast["nat_rules"] = []
        ast["ippools"] = []
        ast["raw_config"] = text

        current_path: list[str] = []
        current_obj: dict[str, Any] | None = None
        current_list: list | None = None
        block_depth = 0

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped == "next":
                if current_obj is not None and current_list is not None:
                    current_list.append(current_obj)
                current_obj = None
                continue

            if stripped == "end":
                if current_obj is not None and current_list is not None:
                    current_list.append(current_obj)
                    current_obj = None
                if len(current_path) > 0:
                    current_path.pop()
                continue

            if stripped.startswith("config "):
                section = stripped[7:].strip()
                current_path.append(section)
                current_obj = None

                if section == "firewall address":
                    current_list = ast["address_objects"]
                elif section == "firewall addrgrp":
                    current_list = ast["address_groups"]
                elif section == "firewall service custom":
                    current_list = ast["service_objects"]
                elif section == "firewall service group":
                    current_list = ast["service_groups"]
                elif section in self.POLICY_SECTIONS:
                    current_list = ast["policies"]
                elif section == "firewall central-nat":
                    current_list = ast["nat_rules"]
                elif section == "firewall ippool":
                    current_list = ast["ippools"]
                elif section == "system interface":
                    current_list = ast["interfaces"]
                elif section == "firewall zone":
                    current_list = ast["zones"]
                elif section == "system vdom":
                    current_list = []
                    ast["vdoms"] = []
                    current_list = None
                else:
                    current_list = None
                continue

            if stripped.startswith("set "):
                parts = stripped[4:].split(None, 1)
                if len(parts) != 2:
                    continue

                key, value = parts
                value = self._clean_value(value)

                if current_path and current_path[-1] == "system global":
                    ast["system"][key] = value
                elif current_obj is not None:
                    self._set_nested(current_obj, key, value)
                continue

            if stripped.startswith("edit "):
                name = self._clean_value(stripped[5:].strip())
                current_obj = {"_name": name}

                if current_path and current_path[-1] == "system vdom":
                    ast.setdefault("vdoms", []).append({"name": name, "sections": {}})
                    current_obj = None
                    continue

                if current_list is not None:
                    pass
                continue

            if stripped.startswith("unset "):
                if current_obj is not None:
                    key = stripped[6:].strip()
                    current_obj[key] = None
                continue

        logger.info(
            "Parsed FortiGate config: %d policies, %d NAT rules, %d addresses, %d services",
            len(ast["policies"]),
            len(ast["nat_rules"]),
            len(ast["address_objects"]),
            len(ast["service_objects"]),
        )

        return ast

    def normalize(self, ast: VendorAST) -> dict[str, Any]:
        """Convert FortiGate AST to canonical Session-compatible dict."""
        return normalize_fortinet(ast)

    def _clean_value(self, value: str) -> str:
        """Remove quotes and trailing comments from a value."""
        value = value.strip()
        if '"' in value:
            parts = re.findall(r'"([^"]*)"', value)
            if parts:
                return " ".join(parts)
        if (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]
        comment_match = re.search(r'\s#', value)
        if comment_match:
            value = value[:comment_match.start()]
        return value.strip()

    def _set_nested(self, obj: dict, key: str, value: str) -> None:
        """Set a key-value pair on the current object, handling multi-value fields."""
        if key in ("member", "interface", "srcintf", "dstintf"):
            existing = obj.get(key)
            if isinstance(existing, list):
                existing.extend(self._split_list(value))
            else:
                obj[key] = self._split_list(value)
        elif key in ("srcaddr", "dstaddr", "service", "dst-addr", "src-addr"):
            existing = obj.get(key)
            if isinstance(existing, list):
                existing.extend(self._split_list(value))
            else:
                obj[key] = self._split_list(value)
        else:
            obj[key] = value

    def _split_list(self, value: str) -> list[str]:
        """Split a comma-separated or space-separated list, stripping whitespace."""
        if "," in value:
            return [v.strip() for v in value.split(",") if v.strip()]
        return [v.strip() for v in value.split() if v.strip()]
