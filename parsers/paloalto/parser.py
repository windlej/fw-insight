"""Palo Alto XML config parser.

Parses PAN-OS XML exports and extracts security policies, NAT rules,
interfaces, zones, address objects, and service objects.

Handles both single-vsys and multi-vsys configurations.
"""

import logging
from typing import Any
from lxml import etree

from parsers.base import VendorParser, VendorAST, ParseError
from parsers.paloalto.normalizer import normalize_paloalto

logger = logging.getLogger(__name__)

NS = {"ns": "http://mcafee.com/ns/1.0"}


class PaloAltoParser(VendorParser):
    """Parser for Palo Alto PAN-OS XML configuration exports."""

    VENDOR_ID = "paloalto"

    def parse(self, raw_config: str | bytes) -> VendorAST:
        """Parse Palo Alto XML config into a vendor-specific AST.

        Args:
            raw_config: XML config content

        Returns:
            VendorAST with extracted config data

        Raises:
            ParseError: If XML is malformed or expected structure is missing
        """
        if isinstance(raw_config, str):
            raw_config = raw_config.encode("utf-8")

        try:
            root = etree.fromstring(raw_config)
        except etree.XMLSyntaxError as e:
            raise ParseError(f"Invalid XML: {e}")

        config_elem = root.find(".//config")
        if config_elem is None:
            config_elem = root if root.tag == "config" else None
        if config_elem is None:
            raise ParseError("No <config> element found in XML")

        ast = VendorAST()
        ast["version"] = self._extract_version(config_elem)
        ast["hostname"] = self._extract_hostname(config_elem)
        ast["address_objects"] = self._extract_address_objects(config_elem)
        ast["service_objects"] = self._extract_service_objects(config_elem)
        ast["security_policies"] = self._extract_security_policies(config_elem)
        ast["nat_rules"] = self._extract_nat_rules(config_elem)
        ast["interfaces"] = self._extract_interfaces(config_elem)
        ast["zones"] = self._extract_zones(config_elem)
        ast["raw_xml"] = raw_config.decode("utf-8", errors="replace")

        return ast

    def normalize(self, ast: VendorAST) -> dict[str, Any]:
        """Convert Palo Alto AST to canonical Session-compatible dict."""
        return normalize_paloalto(ast)

    def _extract_version(self, config_elem) -> str | None:
        version = config_elem.get("version")
        if version:
            return version.strip()
        version_elem = config_elem.find(".//version")
        if version_elem is not None and version_elem.text:
            return version_elem.text.strip()
        return None

    def _extract_hostname(self, config_elem) -> str | None:
        hostname_elem = config_elem.find(".//hostname")
        if hostname_elem is not None and hostname_elem.text:
            return hostname_elem.text.strip()
        return None

    def _element_to_dict(self, elem) -> dict[str, Any]:
        """Convert an XML element to a nested dict, preserving structure."""
        result: dict[str, Any] = {}
        result["_tag"] = elem.tag
        if elem.attrib:
            result["@attrib"] = dict(elem.attrib)
        if elem.text and elem.text.strip():
            result["_text"] = elem.text.strip()
        for child in elem:
            child_data = self._element_to_dict(child)
            tag = child.tag
            if tag in result:
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(child_data)
            else:
                result[tag] = child_data
        return result

    def _extract_address_objects(self, config_elem) -> list[dict[str, Any]]:
        objects = []
        for vsys in config_elem.findall(".//vsys/entry"):
            vsys_name = vsys.get("name", "vsys1")
            addr_base = vsys.find("address")
            if addr_base is not None:
                for entry in addr_base.findall("entry"):
                    obj = {
                        "name": entry.get("name"),
                        "type": "ip_netmask",
                        "value": "",
                        "vsys": vsys_name,
                        "vendor_raw": {"entry": self._element_to_dict(entry)},
                    }

                    ip_netmask = entry.find("ip-netmask")
                    ip_range = entry.find("ip-range")
                    fqdn = entry.find("fqdn")

                    if ip_netmask is not None and ip_netmask.text:
                        obj["value"] = ip_netmask.text.strip()
                        obj["type"] = "ip_netmask"
                    elif ip_range is not None and ip_range.text:
                        obj["value"] = ip_range.text.strip()
                        obj["type"] = "ip_range"
                    elif fqdn is not None and fqdn.text:
                        obj["value"] = fqdn.text.strip()
                        obj["type"] = "fqdn"

                    desc = entry.find("description")
                    if desc is not None and desc.text:
                        obj["description"] = desc.text.strip()

                    objects.append(obj)

            addr_groups = vsys.find("address-group")
            if addr_groups is not None:
                for group in addr_groups.findall("entry"):
                    obj = {
                        "name": group.get("name"),
                        "type": "group",
                        "value": "",
                        "members": [],
                        "vsys": vsys_name,
                        "vendor_raw": {"entry": self._element_to_dict(group)},
                    }

                    members = group.find("static")
                    if members is not None:
                        obj["members"] = [
                            m.text.strip() for m in members.findall("member") if m.text
                        ]

                    desc = group.find("description")
                    if desc is not None and desc.text:
                        obj["description"] = desc.text.strip()

                    objects.append(obj)

        return objects

    def _extract_service_objects(self, config_elem) -> list[dict[str, Any]]:
        objects = []
        for vsys in config_elem.findall(".//vsys/entry"):
            vsys_name = vsys.get("name", "vsys1")
            svc_base = vsys.find("service")
            if svc_base is not None:
                for entry in svc_base.findall("entry"):
                    obj = {
                        "name": entry.get("name"),
                        "protocol": "tcp",
                        "ports": [],
                        "vsys": vsys_name,
                        "vendor_raw": {"entry": self._element_to_dict(entry)},
                    }

                    protocol = entry.find("protocol")
                    if protocol is not None:
                        tcp = protocol.find("tcp")
                        udp = protocol.find("udp")
                        if tcp is not None:
                            obj["protocol"] = "tcp"
                            port_elem = tcp.find("port")
                            if port_elem is not None and port_elem.text:
                                obj["ports"] = [
                                    p.strip() for p in port_elem.text.split(",") if p.strip()
                                ]
                        elif udp is not None:
                            obj["protocol"] = "udp"
                            port_elem = udp.find("port")
                            if port_elem is not None and port_elem.text:
                                obj["ports"] = [
                                    p.strip() for p in port_elem.text.split(",") if p.strip()
                                ]

                    desc = entry.find("description")
                    if desc is not None and desc.text:
                        obj["description"] = desc.text.strip()

                    objects.append(obj)

            svc_groups = vsys.find("service-group")
            if svc_groups is not None:
                for group in svc_groups.findall("entry"):
                    members_elem = group.find("members")
                    members = []
                    if members_elem is not None:
                        members = [
                            m.text.strip() for m in members_elem.findall("member") if m.text
                        ]
                    obj = {
                        "name": group.get("name"),
                        "protocol": "any",
                        "ports": [],
                        "members": members,
                        "vsys": vsys_name,
                        "vendor_raw": {"entry": self._element_to_dict(group)},
                    }
                    objects.append(obj)

        return objects

    def _extract_security_policies(self, config_elem) -> list[dict[str, Any]]:
        policies = []
        for vsys in config_elem.findall(".//vsys/entry"):
            vsys_name = vsys.get("name", "vsys1")
            rulebase = vsys.find("rulebase/security/rules")
            if rulebase is None:
                rulebase = vsys.find(".//rulebase/security/rules")
            if rulebase is None:
                continue

            for position, entry in enumerate(rulebase.findall("entry"), start=1):
                policy = {
                    "id": entry.get("name"),
                    "name": entry.get("name"),
                    "position": position,
                    "vsys": vsys_name,
                    "vendor_raw": {"entry": self._element_to_dict(entry)},
                }

                to_elem = entry.find("to")
                if to_elem is not None:
                    policy["destination_zones"] = [
                        m.text.strip() for m in to_elem.findall("member") if m.text
                    ]

                from_elem = entry.find("from")
                if from_elem is not None:
                    policy["source_zones"] = [
                        m.text.strip() for m in from_elem.findall("member") if m.text
                    ]

                src_elem = entry.find("source")
                if src_elem is not None:
                    policy["source_addresses"] = [
                        m.text.strip() for m in src_elem.findall("member") if m.text
                    ]

                dst_elem = entry.find("destination")
                if dst_elem is not None:
                    policy["destination_addresses"] = [
                        m.text.strip() for m in dst_elem.findall("member") if m.text
                    ]

                svc_elem = entry.find("service")
                if svc_elem is not None:
                    policy["services"] = [
                        m.text.strip() for m in svc_elem.findall("member") if m.text
                    ]

                action_elem = entry.find("action")
                if action_elem is not None and action_elem.text:
                    policy["action"] = action_elem.text.strip()

                disabled_elem = entry.find("disabled")
                if disabled_elem is not None and disabled_elem.text == "yes":
                    policy["enabled"] = False

                log_start = entry.find("log-start")
                log_end = entry.find("log-end")
                policy["log_start"] = (
                    log_start is not None and log_start.text == "yes"
                )
                policy["log_end"] = (
                    log_end is not None and log_end.text == "yes"
                )

                desc_elem = entry.find("description")
                if desc_elem is not None and desc_elem.text:
                    policy["description"] = desc_elem.text.strip()

                tag_elem = entry.find("tag")
                if tag_elem is not None:
                    policy["tags"] = [
                        m.text.strip() for m in tag_elem.findall("member") if m.text
                    ]

                policies.append(policy)

        return policies

    def _extract_nat_rules(self, config_elem) -> list[dict[str, Any]]:
        rules = []
        for vsys in config_elem.findall(".//vsys/entry"):
            vsys_name = vsys.get("name", "vsys1")
            nat_base = vsys.find("rulebase/nat/rules")
            if nat_base is None:
                nat_base = vsys.find(".//rulebase/nat/rules")
            if nat_base is None:
                continue

            for position, entry in enumerate(nat_base.findall("entry"), start=1):
                rule = {
                    "id": entry.get("name"),
                    "name": entry.get("name"),
                    "position": position,
                    "vsys": vsys_name,
                    "vendor_raw": {"entry": self._element_to_dict(entry)},
                }

                nat_type = entry.find("nat-type")
                if nat_type is not None and nat_type.text:
                    rule["type"] = nat_type.text.strip()

                src_elem = entry.find("source")
                if src_elem is not None:
                    rule["source_addresses"] = [
                        m.text.strip() for m in src_elem.findall("member") if m.text
                    ]

                dst_elem = entry.find("destination")
                if dst_elem is not None:
                    rule["destination_addresses"] = [
                        m.text.strip() for m in dst_elem.findall("member") if m.text
                    ]

                svc_elem = entry.find("service")
                if svc_elem is not None and svc_elem.text:
                    rule["service"] = svc_elem.text.strip()

                src_xlate = entry.find("source-translation")
                if src_xlate is not None:
                    dynamic = src_xlate.find("dynamic-ip-and-port")
                    if dynamic is not None:
                        rule["translated_source"] = self._extract_xlate_addr(dynamic)

                dst_xlate = entry.find("destination-translation")
                if dst_xlate is not None:
                    rule["translated_destination"] = self._extract_xlate_addr(dst_xlate)

                disabled_elem = entry.find("disabled")
                if disabled_elem is not None and disabled_elem.text == "yes":
                    rule["enabled"] = False

                rules.append(rule)

        return rules

    def _extract_xlate_addr(self, parent) -> list[str]:
        addresses = []
        trans_addr = parent.find("translated-address")
        if trans_addr is not None and trans_addr.text:
            addresses.append(trans_addr.text.strip())
        return addresses

    def _extract_interfaces(self, config_elem) -> list[dict[str, Any]]:
        interfaces = []
        for network in config_elem.findall(".//network"):
            iface_container = network.find("interface")
            if iface_container is None:
                continue

            for iface_type in ("ethernet", "vlan", "tunnel", "loopback", "aggregate-ethernet"):
                type_base = iface_container.find(iface_type)
                if type_base is None:
                    continue

                for entry in type_base.findall("entry"):
                    iface = {
                        "name": entry.get("name"),
                        "type": iface_type,
                        "vendor_raw": {"entry": self._element_to_dict(entry)},
                    }

                    layer3 = entry.find("layer3")
                    if layer3 is not None:
                        ip_elem = layer3.find("ip")
                        if ip_elem is not None:
                            for addr_entry in ip_elem.findall(".//entry"):
                                addr_name = addr_entry.get("name")
                                if addr_name:
                                    iface.setdefault("ip_addresses", []).append(addr_name)

                        zone_elem = layer3.find("zone")
                        if zone_elem is not None:
                            zone_member = zone_elem.find("member")
                            if zone_member is not None and zone_member.text:
                                iface["zone"] = zone_member.text.strip()

                    interfaces.append(iface)

        return interfaces

    def _extract_zones(self, config_elem) -> list[dict[str, Any]]:
        zones = []
        for zone_elem in config_elem.findall(".//zone/entry"):
            zone = {
                "name": zone_elem.get("name"),
                "vendor_raw": {"entry": self._element_to_dict(zone_elem)},
            }

            zone_type = zone_elem.get("network")
            if zone_type:
                zone["type"] = zone_type

            network = zone_elem.find("network")
            if network is not None:
                zone["interfaces"] = [
                    m.text.strip() for m in network.findall("member") if m.text
                ]

            zones.append(zone)

        return zones
