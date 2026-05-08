"""Cisco ASA / Firepower AST to canonical Session normalizer.

Maps ASA-specific fields to the canonical data model:
- permit -> allow
- deny -> deny
- any/any4/any6 -> any
- host <ip> -> <ip>/32
- object <name> -> resolved through address objects
- interface <name> -> zone from nameif
- access-list entries -> security policies
- object-group members -> flattened address/service references
"""

import logging
from typing import Any

from core.models import (
    AddressObject,
    Interface,
    NATRule,
    RuleEndpoint,
    SecurityPolicy,
    ServiceObject,
    ServiceRef,
    Zone,
)

logger = logging.getLogger(__name__)


def normalize_cisco_asa(ast: dict[str, Any]) -> dict[str, Any]:
    """Convert Cisco ASA AST to canonical Session-compatible dict."""
    name_mappings = ast.get("name_mappings", {})

    addr_objects = _normalize_address_objects(
        ast.get("address_objects", []),
        ast.get("address_groups", []),
        name_mappings,
    )
    svc_objects = _normalize_service_objects(
        ast.get("service_objects", []),
        ast.get("service_groups", []),
    )

    addr_map = {o["name"]: o for o in addr_objects}
    svc_map = {o["name"]: o for o in svc_objects}

    interfaces = _normalize_interfaces(ast.get("interfaces", []))
    zones = _normalize_zones(ast.get("interfaces", []))
    iface_name_map = {i["name"]: i for i in interfaces}

    access_groups = ast.get("access_groups", [])
    policies = _normalize_policies(
        ast.get("access_lists", {}),
        access_groups,
        addr_map,
        svc_map,
        iface_name_map,
    )

    nat_rules = _normalize_nat_rules(
        ast.get("nat_rules", []),
        ast.get("address_objects", []),
    )

    hostname = ast.get("system", {}).get("hostname")
    version = ast.get("system", {}).get("version")

    return {
        "vendor": "cisco_asa",
        "hostname": hostname,
        "vendor_version": version,
        "security_policies": policies,
        "nat_rules": nat_rules,
        "interfaces": interfaces,
        "zones": zones,
        "address_objects": addr_objects,
        "service_objects": svc_objects,
        "metadata": {
            "acl_count": len(ast.get("access_lists", {})),
        },
    }


def _normalize_address_objects(
    raw_objects: list[dict],
    raw_groups: list[dict],
    name_mappings: dict[str, str],
) -> list[dict]:
    """Normalize ASA address objects and groups to canonical AddressObjects.

    Handles:
    - host <ip> -> ip_netmask with /32
    - subnet <ip> <mask> -> ip_netmask with CIDR
    - range <start> <end> -> ip_range
    - fqdn <name> -> fqdn
    - name <ip> <alias> -> ip_netmap (from name mappings)
    - object-group network -> address groups
    """
    objects = []

    for alias, ip in name_mappings.items():
        objects.append(
            AddressObject(
                name=alias,
                type="ip_netmask",
                value=f"{ip}/32",
            ).model_dump()
        )

    for obj in raw_objects:
        name = obj.get("_name", "unknown")
        obj_type = obj.get("type", "ip_netmask")
        value = obj.get("value", "")

        if obj_type == "host":
            obj_type = "ip_netmask"
            ip = value
            value = f"{ip}/32"
        elif obj_type == "ip_netmask":
            pass
        elif obj_type == "fqdn":
            value = value.strip("'\"")
        elif obj_type == "ip_range":
            pass

        objects.append(
            AddressObject(
                name=name,
                type=obj_type,
                value=value,
                description=obj.get("description"),
                vendor_raw=obj,
            ).model_dump()
        )

    for grp in raw_groups:
        name = grp.get("_name", "unknown")
        members = []
        for m in grp.get("members", []):
            if m.startswith("@group:"):
                members.append(m[7:])
            else:
                obj = _parse_inline_address(m)
                if obj:
                    members.append(obj.get("name", m))
                else:
                    members.append(m)

        objects.append(
            AddressObject(
                name=name,
                type="group",
                value="",
                members=members if members else None,
                description=grp.get("description"),
                vendor_raw=grp,
            ).model_dump()
        )

    return objects


def _normalize_service_objects(
    raw_objects: list[dict],
    raw_groups: list[dict],
) -> list[dict]:
    objects = []

    for obj in raw_objects:
        name = obj.get("_name", "unknown")
        protocol = obj.get("protocol", "tcp").lower()
        if protocol not in ("tcp", "udp", "icmp", "sctp", "ip"):
            protocol = "tcp"

        objects.append(
            ServiceObject(
                name=name,
                protocol=protocol,
                ports=obj.get("ports", []),
                description=obj.get("description"),
                vendor_raw=obj,
            ).model_dump()
        )

    for grp in raw_groups:
        name = grp.get("_name", "unknown")
        members = []
        for m in grp.get("members", []):
            if m.startswith("@group:"):
                members.append(m[7:])

        ports = grp.get("port_objects", [])
        svc_objs = grp.get("service_objects", [])
        raw_protocol = grp.get("protocol", "").lower()

        all_members = list(members)
        for s in svc_objs:
            all_members.append(s)

        objects.append(
            ServiceObject(
                name=name,
                protocol=raw_protocol if raw_protocol else "any",
                ports=ports,
                members=all_members if all_members else None,
                vendor_raw=grp,
            ).model_dump()
        )

    return objects


def _resolve_addresses(
    raw_addrs: list[str] | None,
    addr_map: dict,
) -> list[str]:
    """Resolve a list of address references, expanding groups."""
    if not raw_addrs:
        return ["any"]

    resolved = []
    for addr in raw_addrs:
        if addr.lower() in ("any", "any4", "any6"):
            resolved.append("any")
            continue
        if addr in addr_map:
            obj = addr_map[addr]
            if obj.get("members"):
                resolved.extend(_resolve_addresses(obj["members"], addr_map))
            elif obj.get("value"):
                resolved.append(obj["value"])
            else:
                resolved.append(addr)
        else:
            resolved.append(addr)
    return list(dict.fromkeys(resolved))


def _resolve_services(
    raw_svcs: list[str] | None,
    svc_map: dict,
) -> list[ServiceRef]:
    if not raw_svcs:
        return [ServiceRef(protocol="any")]

    resolved = []
    for svc in raw_svcs:
        if svc.upper() in ("ANY", "IP"):
            resolved.append(ServiceRef(protocol="any"))
            continue
        if svc in svc_map:
            obj = svc_map[svc]
            if obj.get("members"):
                resolved.extend(_resolve_services(obj["members"], svc_map))
            else:
                resolved.append(
                    ServiceRef(
                        protocol=obj.get("protocol", "tcp"),
                        ports=obj.get("ports", []),
                    )
                )
        else:
            resolved.append(ServiceRef(protocol="tcp", ports=[svc]))
    return resolved or [ServiceRef(protocol="any")]


def _normalize_policies(
    access_lists: dict[str, list[dict]],
    access_groups: list[dict],
    addr_map: dict,
    svc_map: dict,
    iface_name_map: dict,
) -> list[dict]:
    policies = []
    global_position = 0

    ag_by_name: dict[str, dict] = {}
    for ag in access_groups:
        ag_by_name[ag["name"]] = ag

    for acl_name, entries in access_lists.items():
        ag = ag_by_name.get(acl_name)

        dst_zones = []
        src_zones = []
        if ag:
            iface = iface_name_map.get(ag["interface"])
            if iface and iface.get("zone"):
                if ag["direction"] == "in":
                    dst_zones = [iface["zone"]]
                elif ag["direction"] == "out":
                    src_zones = [iface["zone"]]

        for entry in entries:
            global_position += 1
            src_spec = entry.get("source", {})
            dst_spec = entry.get("destination", {})

            src_addrs = _resolve_ace_address(src_spec, addr_map)
            dst_addrs = _resolve_ace_address(dst_spec, addr_map)

            protocol = entry.get("protocol", "ip").lower()

            services = _resolve_ace_service(protocol, src_spec, dst_spec, svc_map)

            action = entry.get("action", "deny").lower()
            if action == "permit":
                action = "allow"
            elif action in ("deny", "reject"):
                action = "deny"

            canonical = {
                "id": f"{acl_name}-{global_position}",
                "name": entry.get("name") or f"{acl_name} rule {entry.get('line', global_position)}",
                "position": global_position,
                "source": RuleEndpoint(
                    addresses=src_addrs,
                    zones=src_zones or [],
                ),
                "destination": RuleEndpoint(
                    addresses=dst_addrs,
                    zones=dst_zones or [],
                ),
                "services": services,
                "action": action,
                "enabled": True,
                "logging": {
                    "log_start": False,
                    "log_end": entry.get("logging", False),
                },
                "vendor_raw": entry,
            }

            policies.append(SecurityPolicy(**canonical).model_dump())

    return policies


def _resolve_ace_address(
    spec: dict[str, Any],
    addr_map: dict,
) -> list[str]:
    """Resolve an ACE address spec to a list of canonical addresses."""
    spec_type = spec.get("type", "any")
    value = spec.get("value", "any")

    if spec_type == "any":
        return ["any"]
    elif spec_type == "host":
        return [f"{value}/32"]
    elif spec_type == "object":
        return _resolve_addresses([value], addr_map)
    elif spec_type == "interface":
        return [f"@interface:{value}"]
    elif spec_type == "network":
        parts = value.split()
        if len(parts) == 2:
            from parsers.cisco_asa.parser import CiscoASAParser
            parser = CiscoASAParser()
            cidr = parser._netmask_to_cidr(parts[1])
            if cidr is not None:
                return [f"{parts[0]}/{cidr}"]
        return [value]
    else:
        return [value]


def _resolve_ace_service(
    protocol: str,
    src_spec: dict[str, Any],
    dst_spec: dict[str, Any],
    svc_map: dict,
) -> list[ServiceRef]:
    """Resolve service from ACL protocol and optional port specs."""
    if protocol == "ip":
        return [ServiceRef(protocol="any")]

    if protocol in ("tcp", "udp", "tcp-udp"):
        dst_port = dst_spec.get("port")
        src_port = src_spec.get("port")

        if dst_port:
            op = dst_port.get("op", "eq")
            val = dst_port.get("value", "")
            if op in ("eq", "lt", "gt", "neq"):
                return [ServiceRef(protocol=protocol, ports=[f"{op}_{val}"] if op != "eq" else [val])]
            elif op == "range":
                return [ServiceRef(protocol=protocol, ports=[val])]

        if src_port:
            val = src_port.get("value", "")
            return [ServiceRef(protocol=protocol, ports=[f"source_{val}"])]

        return [ServiceRef(protocol=protocol)]

    if protocol in ("icmp", "icmp6", "esp", "ah", "gre"):
        return [ServiceRef(protocol=protocol)]

    return [ServiceRef(protocol=protocol)]


def _normalize_interfaces(raw_interfaces: list[dict]) -> list[dict]:
    interfaces = []

    for raw in raw_interfaces:
        name = raw.get("_name", "unknown")
        iface_type = raw.get("type", "physical")
        enabled = raw.get("enabled", True)
        ip_addresses = raw.get("ip_addresses", [])
        zone = raw.get("zone")
        description = raw.get("description")

        iface = {
            "name": name,
            "type": iface_type,
            "enabled": enabled,
            "ip_addresses": ip_addresses,
            "zone": zone,
            "description": description,
            "vendor_raw": raw,
        }

        interfaces.append(Interface(**iface).model_dump())

    return interfaces


def _normalize_zones(raw_interfaces: list[dict]) -> list[dict]:
    zones = []

    for iface in raw_interfaces:
        zone_name = iface.get("zone")
        if not zone_name:
            continue

        existing = next((z for z in zones if z["name"] == zone_name), None)
        if existing:
            if iface.get("_name") not in existing["interfaces"]:
                existing["interfaces"].append(iface["_name"])
        else:
            zones.append(
                Zone(
                    name=zone_name,
                    type="layer3",
                    interfaces=[iface["_name"]],
                    vendor_raw={},
                ).model_dump()
            )

    return zones


def _normalize_nat_rules(
    raw_nat: list[dict],
    raw_address_objects: list[dict],
) -> list[dict]:
    rules = []

    for position, raw in enumerate(raw_nat, start=1):
        nat_type = "source_nat"
        if raw.get("type") == "destination":
            nat_type = "destination_nat"
        elif raw.get("nat_type") == "static":
            nat_type = "static"

        rule = {
            "id": f"nat-{position}",
            "name": None,
            "position": position,
            "type": nat_type,
            "original_source": raw.get("original_source"),
            "translated_source": raw.get("translated_source"),
            "original_destination": raw.get("original_destination"),
            "translated_destination": raw.get("translated_destination"),
            "enabled": True,
            "vendor_raw": raw,
        }

        rules.append(NATRule(**rule).model_dump())

    for obj in raw_address_objects:
        nat_entries = obj.get("_nat", [])
        for nat_entry in nat_entries:
            position = len(rules) + 1
            obj_name = obj.get("_name", "unknown")
            translated = nat_entry.get("translated", "")

            rule = {
                "id": f"object-nat-{obj_name}",
                "name": f"NAT for object {obj_name}",
                "position": position,
                "type": "static" if nat_entry.get("nat_type") == "static" else "source_nat",
                "original_source": obj_name,
                "translated_source": translated,
                "original_destination": None,
                "translated_destination": None,
                "enabled": True,
                "vendor_raw": nat_entry,
            }

            rules.append(NATRule(**rule).model_dump())

    return rules


def _parse_inline_address(spec: str) -> dict | None:
    """Parse an inline address from a network-object line."""
    parts = spec.split()
    if len(parts) == 2:
        ip, mask = parts
        from parsers.cisco_asa.parser import CiscoASAParser
        parser = CiscoASAParser()
        cidr = parser._netmask_to_cidr(mask)
        if cidr is not None:
            return {"name": f"{ip}/{cidr}", "type": "ip_netmask", "value": f"{ip}/{cidr}"}
    return None
