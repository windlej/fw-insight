"""Cisco ASA / Firepower CLI configuration parser.

Parses Cisco ASA show running-config output and extracts:
- System settings (hostname, version)
- Interfaces with nameif, IP, security-level
- Name mappings (name -> IP)
- Object network definitions (address objects)
- Object-group network/service definitions
- Access-list entries (IPv4)
- Access-group bindings
- NAT rules (object-level and network-level)

ASA CLI structure:
    ASA Version 9.12(4)
    hostname <name>
    interface <type>/<slot>/<port>
        nameif <name>
        ip address <ip> <mask>
        security-level <level>
    object network <name>
        <type> <value>
    object-group [network|service] <name>
        <field> <value>
    access-list <name> extended <action> <proto> <src> <dst> [log]
    access-group <name> [in|out] interface <iface>
"""

import logging
import re
from typing import Any

from parsers.base import VendorAST, VendorParser
from parsers.cisco_asa.normalizer import normalize_cisco_asa

logger = logging.getLogger(__name__)


RE_ASA_HEADER = re.compile(r"^ASA\s+Version\s+(\S+)", re.IGNORECASE)
RE_HOSTNAME = re.compile(r"^hostname\s+(\S+)")
RE_DOMAIN = re.compile(r"^domain-name\s+(\S+)")
RE_NAME = re.compile(r"^name\s+(\S+)\s+(\S+)")


class CiscoASAParser(VendorParser):
    """Parser for Cisco ASA / Firepower CLI configuration exports."""

    VENDOR_ID = "cisco_asa"

    def parse(self, raw_config: str | bytes) -> VendorAST:
        """Parse ASA CLI config into a vendor-specific AST.

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
        ast["name_mappings"] = {}
        ast["address_objects"] = []
        ast["address_groups"] = []
        ast["service_objects"] = []
        ast["service_groups"] = []
        ast["access_lists"] = {}
        ast["access_groups"] = []
        ast["nat_rules"] = []
        ast["raw_config"] = text

        current_obj: dict[str, Any] | None = None
        current_obj_type: str | None = None
        current_obj_name: str | None = None
        in_block = False

        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("!") or stripped.startswith("#"):
                continue

            if stripped == "exit":
                if in_block and current_obj is not None:
                    self._finalize_object(ast, current_obj_type, current_obj)
                    current_obj = None
                    current_obj_type = None
                    current_obj_name = None
                    in_block = False
                continue

            m = RE_ASA_HEADER.match(stripped)
            if m:
                ast["system"]["version"] = m.group(1)
                continue

            m = RE_HOSTNAME.match(stripped)
            if m:
                ast["system"]["hostname"] = m.group(1)
                continue

            m = RE_DOMAIN.match(stripped)
            if m:
                ast["system"]["domain_name"] = m.group(1)
                continue

            m = RE_NAME.match(stripped)
            if m:
                ip, alias = m.group(1), m.group(2)
                ast["name_mappings"][alias] = ip
                continue

            if stripped.startswith("object network"):
                if in_block and current_obj is not None:
                    self._finalize_object(ast, current_obj_type, current_obj)
                current_obj_name = stripped[len("object network"):].strip()
                existing = next(
                    (o for o in ast["address_objects"] if o.get("_name") == current_obj_name),
                    None,
                )
                if existing:
                    current_obj = existing
                    current_obj_type = "address_object"
                    in_block = True
                    continue
                current_obj = {"_name": current_obj_name, "type": "ip_netmask", "value": ""}
                current_obj_type = "address_object"
                in_block = True
                continue

            if stripped.startswith("object-group network"):
                if in_block and current_obj is not None:
                    self._finalize_object(ast, current_obj_type, current_obj)
                current_obj_name = stripped[len("object-group network"):].strip()
                current_obj = {"_name": current_obj_name, "type": "group", "value": "", "members": []}
                current_obj_type = "address_group"
                in_block = True
                continue

            if stripped.startswith("object-group service"):
                if in_block and current_obj is not None:
                    self._finalize_object(ast, current_obj_type, current_obj)
                rest = stripped[len("object-group service"):].strip()
                parts = rest.split()
                current_obj_name = parts[0]
                current_obj = {"_name": current_obj_name, "members": [], "protocol": parts[1] if len(parts) > 1 else "tcp"}
                current_obj_type = "service_group"
                in_block = True
                continue

            if in_block and current_obj is not None:
                if self._parse_object_line(current_obj, current_obj_type, stripped):
                    continue

            if stripped.startswith("interface "):
                if in_block and current_obj is not None:
                    self._finalize_object(ast, current_obj_type, current_obj)
                    in_block = False
                    current_obj = None
                    current_obj_type = None
                    current_obj_name = None

                iface_name = stripped[len("interface "):].strip()
                current_obj = {"_name": iface_name, "type": "physical", "enabled": True, "ip_addresses": []}
                current_obj_type = "interface"
                in_block = True
                continue

            if stripped.startswith("access-list "):
                self._parse_acl_line(ast, stripped)
                continue

            if stripped.startswith("access-group "):
                m = re.match(
                    r"^access-group\s+(\S+)\s+(in|out)\s+interface\s+(\S+)",
                    stripped,
                )
                if m:
                    ast["access_groups"].append({
                        "name": m.group(1),
                        "direction": m.group(2),
                        "interface": m.group(3),
                    })
                continue

            if stripped.startswith("nat "):
                self._parse_nat_line(ast, stripped)
                continue

            if stripped.startswith("no shutdown"):
                if current_obj_type == "interface" and current_obj is not None:
                    current_obj["enabled"] = True
                continue

            if stripped == "shutdown":
                if current_obj_type == "interface" and current_obj is not None:
                    current_obj["enabled"] = False
                continue

        if in_block and current_obj is not None:
            self._finalize_object(ast, current_obj_type, current_obj)

        logger.info(
            "Parsed Cisco ASA config: %d ACLs, %d address objects, %d groups, %d NAT rules",
            len(ast["access_lists"]),
            len(ast["address_objects"]),
            len(ast["address_groups"]) + len(ast["service_groups"]),
            len(ast["nat_rules"]),
        )

        return ast

    def normalize(self, ast: VendorAST) -> dict[str, Any]:
        """Convert Cisco ASA AST to canonical Session-compatible dict."""
        return normalize_cisco_asa(ast)

    def _parse_object_line(
        self,
        obj: dict[str, Any],
        obj_type: str,
        line: str,
    ) -> bool:
        if obj_type == "address_object":
            return self._parse_address_object_line(obj, line)
        elif obj_type == "address_group":
            return self._parse_address_group_line(obj, line)
        elif obj_type == "service_group":
            return self._parse_service_group_line(obj, line)
        elif obj_type == "interface":
            return self._parse_interface_line(obj, line)
        return False

    def _parse_address_object_line(self, obj: dict, line: str) -> bool:
        if line.startswith("host "):
            obj["type"] = "host"
            obj["value"] = line[5:].strip()
            return True
        if line.startswith("subnet "):
            obj["type"] = "ip_netmask"
            obj["value"] = self._normalize_subnet(line[7:].strip())
            return True
        if line.startswith("range "):
            obj["type"] = "ip_range"
            parts = line[6:].strip().split()
            obj["value"] = f"{parts[0]}-{parts[1]}" if len(parts) >= 2 else parts[0]
            return True
        if line.startswith("fqdn "):
            obj["type"] = "fqdn"
            obj["value"] = line[5:].strip()
            obj["value"] = obj["value"].strip("'\"")
            return True
        if line.startswith("description ") or line.startswith(" remark "):
            key = "description" if line.startswith("description ") else "remark"
            val = line[len(key) + 1:].strip().strip('"\'')
            obj.setdefault("description", val)
            return True
        if line.startswith("nat "):
            self._parse_object_nat(obj, line)
            return True
        return False

    def _parse_address_group_line(self, obj: dict, line: str) -> bool:
        if line.startswith("description ") or line.startswith(" remark "):
            key = "description" if line.startswith("description ") else "remark"
            val = line[len(key) + 1:].strip().strip('"\'')
            obj["description"] = val
            return True
        if line.startswith("network-object object "):
            obj["members"].append(line[21:].strip())
            return True
        if line.startswith("network-object host "):
            obj["members"].append(line[19:].strip())
            return True
        if line.startswith("network-object "):
            val = line[15:].strip()
            obj["members"].append(val)
            return True
        if line.startswith("group-object "):
            obj["members"].append(f"@group:{line[13:].strip()}")
            return True
        return False

    def _parse_service_group_line(self, obj: dict, line: str) -> bool:
        if line.startswith("description ") or line.startswith(" remark "):
            return True
        if line.startswith("protocol "):
            prot = line[9:].strip().lower()
            obj["protocol"] = prot
            return True
        if line.startswith("group-object "):
            obj["members"].append(f"@group:{line[13:].strip()}")
            return True
        if line.startswith("port-object "):
            val = line[12:].strip()
            obj.setdefault("port_objects", [])
            if val.startswith("eq "):
                obj["port_objects"].append(val[3:].strip())
            elif val.startswith("range "):
                parts = val[6:].strip().split()
                if len(parts) >= 2:
                    obj["port_objects"].append(f"{parts[0]}-{parts[1]}")
            return True
        if line.startswith("service-object "):
            val = line[15:].strip()
            obj.setdefault("service_objects", []).append(val)
            return True
        return False

    def _parse_interface_line(self, obj: dict, line: str) -> bool:
        if line.startswith("nameif "):
            obj["zone"] = line[7:].strip()
            return True
        if line.startswith("ip address "):
            parts = line[11:].strip().split()
            if len(parts) >= 2:
                ip = parts[0]
                mask = parts[1]
                cidr = self._netmask_to_cidr(mask)
                if cidr is not None:
                    obj["ip_addresses"].append(f"{ip}/{cidr}")
                else:
                    obj["ip_addresses"].append(f"{ip} {mask}")
            return True
        if line.startswith("security-level "):
            obj["security_level"] = int(line[15:].strip())
            return True
        if line.startswith("description "):
            obj["description"] = line[12:].strip().strip('"\'')
            return True
        if line.startswith("vlan "):
            obj["type"] = "vlan"
            return True
        if line.startswith("no shutdown"):
            obj["enabled"] = True
            return True
        if line == "shutdown":
            obj["enabled"] = False
            return True
        return False

    def _parse_acl_line(self, ast: dict, line: str) -> None:
        m = re.match(
            r"^access-list\s+(\S+)"
            r"(?:\s+line\s+(\d+))?"
            r"\s+extended\s+"
            r"(permit|deny)"
            r"\s+(\S+)"
            r"\s+(.*)",
            line,
        )
        if not m:
            logger.debug("Skipping unparseable ACL line: %s", line[:80])
            return

        acl_name = m.group(1)
        line_num = int(m.group(2)) if m.group(2) else None
        action = m.group(3)
        protocol = m.group(4)
        rest = m.group(5).strip()

        has_log = False
        if rest.endswith(" log") or " log " in rest or rest.endswith(" log"):
            has_log = True
            rest = re.sub(r"\s+log(?: \S+)?$", "", rest)
        elif rest.endswith(" log"):
            has_log = True
            rest = re.sub(r"\s+log$", "", rest)

        src_spec, dst_spec = self._split_src_dst(rest, protocol)

        entry = {
            "line": line_num,
            "action": action,
            "protocol": protocol,
            "source": self._parse_network_spec(src_spec),
            "destination": self._parse_network_spec(dst_spec),
            "logging": has_log,
        }

        if acl_name not in ast["access_lists"]:
            ast["access_lists"][acl_name] = []
        ast["access_lists"][acl_name].append(entry)

    def _split_src_dst(self, rest: str, protocol: str) -> tuple[str, str]:
        """Split ACL remainder into source and destination specs.

        Uses port operators as delimiters to handle tricky cases.
        """
        tokens = rest.split()
        if not tokens:
            return ("", "")

        port_ops = {"eq", "lt", "gt", "neq", "range"}

        src_tokens: list[str] = []
        dst_tokens: list[str] = []
        phase = "src"
        i = 0

        while i < len(tokens):
            token = tokens[i]

            if token in port_ops and protocol.lower() in ("tcp", "udp", "tcp-udp"):
                if phase == "src":
                    src_tokens.append(token)
                    i += 1
                    if token == "range" and i < len(tokens):
                        src_tokens.append(tokens[i])
                        i += 1
                    if i < len(tokens):
                        src_tokens.append(tokens[i])
                        i += 1
                    if i < len(tokens) and tokens[i] in port_ops:
                        phase = "dst"
                        continue
                    phase = "dst"
                    continue
                else:
                    dst_tokens.append(token)
                    i += 1
                    if token == "range" and i < len(tokens):
                        dst_tokens.append(tokens[i])
                        i += 1
                    if i < len(tokens):
                        dst_tokens.append(tokens[i])
                        i += 1
                    continue

            if phase == "src":
                if token in port_ops or (self._is_addr_start(token) and src_tokens):
                    phase = "dst"
                    continue
                src_tokens.append(token)
                i += 1
            else:
                dst_tokens.append(token)
                i += 1

        return " ".join(src_tokens), " ".join(dst_tokens)

    def _is_addr_start(self, token: str) -> bool:
        """Check if token looks like the start of an address spec."""
        return token in ("any", "any4", "any6", "host", "object", "interface")

    def _parse_network_spec(self, spec: str) -> dict[str, Any]:
        """Parse a network address specification from an ACL.

        Handles:
        - any / any4 / any6
        - host <ip>
        - object <name>
        - interface <name>
        - <ip> <mask>
        - <ip>
        """
        result: dict[str, Any] = {"type": "any", "value": "any"}
        if not spec:
            return result

        tokens = spec.split()
        if not tokens:
            return result

        first = tokens[0]

        if first in ("any", "any4", "any6"):
            result["type"] = "any"
            result["value"] = first
        elif first == "host" and len(tokens) >= 2:
            result["type"] = "host"
            result["value"] = tokens[1]
        elif first == "object" and len(tokens) >= 2:
            result["type"] = "object"
            result["value"] = tokens[1]
        elif first == "interface" and len(tokens) >= 2:
            result["type"] = "interface"
            result["value"] = tokens[1]
        elif len(tokens) >= 2 and self._looks_like_ip(tokens[1]):
            result["type"] = "network"
            result["value"] = f"{tokens[0]} {tokens[1]}"
        else:
            result["type"] = "host"
            result["value"] = tokens[0]

        port_tokens = self._extract_port_spec(tokens)
        if port_tokens:
            result["port"] = port_tokens

        return result

    def _extract_port_spec(self, tokens: list[str]) -> dict | None:
        """Extract port specification from the end of an address spec."""
        port_ops = {"eq", "lt", "gt", "neq", "range"}
        addr_tokens = []
        port_tokens = []

        for i, t in enumerate(tokens):
            if t in port_ops:
                addr_tokens = tokens[:i]
                port_tokens = tokens[i:]
                break

        if not port_tokens:
            return None

        op = port_tokens[0]
        if op == "range" and len(port_tokens) >= 3:
            return {"op": op, "value": f"{port_tokens[1]}-{port_tokens[2]}"}
        elif len(port_tokens) >= 2:
            return {"op": op, "value": port_tokens[1]}
        return None

    def _parse_nat_line(self, ast: dict, line: str) -> None:
        m = re.match(
            r"^nat\s+\((\S+),(\S+)\)\s+"
            r"(source|destination)\s+"
            r"(dynamic|static)\s+"
            r"(.*)",
            line,
        )
        if not m:
            logger.debug("Skipping unparseable NAT line: %s", line[:80])
            return

        real_ifc, mapped_ifc = m.group(1), m.group(2)
        nat_dir = m.group(3)
        nat_type = m.group(4)
        rest = m.group(5).strip()

        rule = {
            "real_interface": real_ifc,
            "mapped_interface": mapped_ifc,
            "type": nat_dir,
            "nat_type": nat_type,
            "original_source": None,
            "original_destination": None,
            "translated_source": None,
            "translated_destination": None,
        }

        if nat_dir == "source":
            m2 = re.match(r"(\S+)\s+(dynamic|static)\s+(\S+)", f"{nat_type} {rest}")
            if m2:
                rule["original_source"] = m2.group(1)
                rule["translated_source"] = m2.group(3)
                rule["nat_type"] = m2.group(2).lower()
        elif nat_dir == "destination":
            m2 = re.match(r"(\S+)\s+(\S+)", rest)
            if m2:
                rule["original_destination"] = m2.group(1)
                rule["translated_destination"] = m2.group(2)

        ast["nat_rules"].append(rule)

    def _parse_object_nat(self, obj: dict, line: str) -> None:
        m = re.match(
            r"^nat\s+\((\S+),(\S+)\)\s+"
            r"(static|dynamic)\s+"
            r"(.*)",
            line,
        )
        if not m:
            return

        real_ifc = m.group(1)
        mapped_ifc = m.group(2)
        nat_type = m.group(3)
        rest = m.group(4).strip()

        obj.setdefault("_nat", []).append({
            "real_interface": real_ifc,
            "mapped_interface": mapped_ifc,
            "nat_type": nat_type,
            "translated": rest,
        })

    def _finalize_object(
        self, ast: dict, obj_type: str | None, obj: dict
    ) -> None:
        if obj_type == "address_object":
            name = obj.get("_name", "")
            if any(o.get("_name") == name for o in ast.get("address_objects", [])):
                return
            ast["address_objects"].append(obj)
        elif obj_type == "address_group":
            ast["address_groups"].append(obj)
        elif obj_type == "service_group":
            ast["service_groups"].append(obj)
        elif obj_type == "interface":
            ast["interfaces"].append(obj)

    def _looks_like_ip(self, token: str) -> bool:
        """Check if token looks like an IP address or netmask."""
        return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", token))

    def _normalize_subnet(self, subnet: str) -> str:
        """Normalize subnet format to CIDR.

        Handles '10.0.0.0 255.255.255.0' or '10.0.0.0/24'.
        """
        subnet = subnet.strip()
        if "/" in subnet:
            return subnet
        if " " in subnet:
            parts = subnet.split()
            ip = parts[0]
            mask = parts[1]
            cidr = self._netmask_to_cidr(mask)
            if cidr is not None:
                return f"{ip}/{cidr}"
        return subnet

    def _netmask_to_cidr(self, mask: str) -> int | None:
        mask_map = {
            "255.255.255.255": 32,
            "255.255.255.254": 31,
            "255.255.255.252": 30,
            "255.255.255.248": 29,
            "255.255.255.240": 28,
            "255.255.255.224": 27,
            "255.255.255.192": 26,
            "255.255.255.128": 25,
            "255.255.255.0": 24,
            "255.255.254.0": 23,
            "255.255.252.0": 22,
            "255.255.248.0": 21,
            "255.255.240.0": 20,
            "255.255.224.0": 19,
            "255.255.192.0": 18,
            "255.255.128.0": 17,
            "255.255.0.0": 16,
            "255.254.0.0": 15,
            "255.252.0.0": 14,
            "255.248.0.0": 13,
            "255.240.0.0": 12,
            "255.224.0.0": 11,
            "255.192.0.0": 10,
            "255.128.0.0": 9,
            "255.0.0.0": 8,
            "254.0.0.0": 7,
            "252.0.0.0": 6,
            "248.0.0.0": 5,
            "240.0.0.0": 4,
            "224.0.0.0": 3,
            "192.0.0.0": 2,
            "128.0.0.0": 1,
            "0.0.0.0": 0,
        }
        return mask_map.get(mask)
