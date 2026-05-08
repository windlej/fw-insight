"""Palo Alto AST to canonical Session normalizer."""

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


def normalize_paloalto(ast: dict[str, Any]) -> dict[str, Any]:
    """Convert Palo Alto AST to canonical Session-compatible dict.

    Resolves object references, flattens hierarchical policies,
    and populates vendor_raw on every entity.
    """
    addr_objects = _normalize_address_objects(ast.get("address_objects", []))
    svc_objects = _normalize_service_objects(ast.get("service_objects", []))

    addr_map = {o["name"]: o for o in addr_objects}
    svc_map = {o["name"]: o for o in svc_objects}

    policies = _normalize_policies(
        ast.get("security_policies", []),
        addr_map,
        svc_map,
    )

    nat_rules = _normalize_nat_rules(ast.get("nat_rules", []), addr_map, svc_map)

    interfaces = _normalize_interfaces(ast.get("interfaces", []))
    zones = _normalize_zones(ast.get("zones", []))

    return {
        "vendor": "paloalto",
        "hostname": ast.get("hostname"),
        "vendor_version": ast.get("version"),
        "security_policies": policies,
        "nat_rules": nat_rules,
        "interfaces": interfaces,
        "zones": zones,
        "address_objects": addr_objects,
        "service_objects": svc_objects,
        "metadata": {
            "vsys_list": list(set(
                obj.get("vsys", "vsys1")
                for obj in ast.get("address_objects", [])
                + ast.get("service_objects", [])
            )),
        },
    }


def _normalize_address_objects(raw_objects: list[dict]) -> list[dict]:
    objects = []
    for obj in raw_objects:
        canonical = {
            "name": obj["name"],
            "type": obj.get("type", "ip_netmask"),
            "value": obj.get("value", ""),
            "description": obj.get("description"),
            "vendor_raw": obj.get("vendor_raw", {}),
        }
        if obj.get("members"):
            canonical["members"] = obj["members"]
        objects.append(AddressObject(**canonical).model_dump())
    return objects


def _normalize_service_objects(raw_objects: list[dict]) -> list[dict]:
    objects = []
    for obj in raw_objects:
        canonical = {
            "name": obj["name"],
            "protocol": obj.get("protocol", "tcp"),
            "ports": obj.get("ports", []),
            "description": obj.get("description"),
            "vendor_raw": obj.get("vendor_raw", {}),
        }
        if obj.get("members"):
            canonical["members"] = obj["members"]
        objects.append(ServiceObject(**canonical).model_dump())
    return objects


def _resolve_addresses(raw_addrs: list[str], addr_map: dict) -> list[str]:
    resolved = []
    for addr in raw_addrs:
        if addr.lower() in ("any", "none"):
            if addr.lower() == "any":
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


def _resolve_services(raw_svcs: list[str], svc_map: dict) -> list[ServiceRef]:
    resolved = []
    for svc in raw_svcs:
        if svc.lower() in ("any", "application-default"):
            if svc.lower() == "any":
                resolved.append(ServiceRef(protocol="any"))
            continue
        if svc in svc_map:
            obj = svc_map[svc]
            if obj.get("members"):
                resolved.extend(_resolve_services(obj["members"], svc_map))
            else:
                resolved.append(ServiceRef(
                    protocol=obj.get("protocol", "tcp"),
                    ports=obj.get("ports", []),
                ))
        else:
            resolved.append(ServiceRef(protocol="any", ports=[svc]))
    return resolved or [ServiceRef(protocol="any")]


def _normalize_policies(
    raw_policies: list[dict],
    addr_map: dict,
    svc_map: dict,
) -> list[dict]:
    policies = []
    for raw in raw_policies:
        source_addrs = raw.get("source_addresses", ["any"])
        dest_addrs = raw.get("destination_addresses", ["any"])

        source = RuleEndpoint(
            addresses=_resolve_addresses(source_addrs, addr_map),
            zones=raw.get("source_zones", []),
        )
        destination = RuleEndpoint(
            addresses=_resolve_addresses(dest_addrs, addr_map),
            zones=raw.get("destination_zones", []),
        )

        raw_svcs = raw.get("services", ["any"])
        services = _resolve_services(raw_svcs, svc_map)

        canonical = {
            "id": raw["id"],
            "name": raw.get("name"),
            "position": raw["position"],
            "source": source,
            "destination": destination,
            "services": services,
            "action": raw.get("action", "allow"),
            "enabled": raw.get("enabled", True),
            "logging": {
                "log_start": raw.get("log_start", False),
                "log_end": raw.get("log_end", False),
            },
            "description": raw.get("description"),
            "vendor_raw": raw.get("vendor_raw", {}),
        }

        policies.append(SecurityPolicy(**canonical).model_dump())

    return policies


def _normalize_nat_rules(
    raw_rules: list[dict],
    addr_map: dict,
    svc_map: dict,
) -> list[dict]:
    rules = []
    for raw in raw_rules:
        nat_type_map = {
            "ipv4": "source_nat",
            "nat64": "source_nat",
            "nptv6": "destination_nat",
        }
        raw_type = raw.get("type", "ipv4")
        rule_type = nat_type_map.get(raw_type, raw_type)

        orig_src = raw.get("source_addresses", ["any"])
        orig_dst = raw.get("destination_addresses", ["any"])

        translated_src = raw.get("translated_source", [])
        translated_dst = raw.get("translated_destination", [])

        rule = {
            "id": raw["id"],
            "name": raw.get("name"),
            "position": raw["position"],
            "type": rule_type,
            "original_source": ", ".join(_resolve_addresses(orig_src, addr_map)) if orig_src != ["any"] else None,
            "translated_source": ", ".join(translated_src) if translated_src else None,
            "original_destination": ", ".join(_resolve_addresses(orig_dst, addr_map)) if orig_dst != ["any"] else None,
            "translated_destination": ", ".join(translated_dst) if translated_dst else None,
            "enabled": raw.get("enabled", True),
            "vendor_raw": raw.get("vendor_raw", {}),
        }

        if raw.get("service") and raw["service"] != "any":
            rule["original_service"] = ServiceRef(protocol="tcp", ports=[raw["service"]])

        rules.append(NATRule(**rule).model_dump())

    return rules


def _normalize_interfaces(raw_interfaces: list[dict]) -> list[dict]:
    interfaces = []
    for raw in raw_interfaces:
        iface = {
            "name": raw["name"],
            "type": raw.get("type", "physical"),
            "enabled": raw.get("enabled", True),
            "ip_addresses": raw.get("ip_addresses", []),
            "zone": raw.get("zone"),
            "description": raw.get("description"),
            "vendor_raw": raw.get("vendor_raw", {}),
        }
        interfaces.append(Interface(**iface).model_dump())
    return interfaces


def _normalize_zones(raw_zones: list[dict]) -> list[dict]:
    zones = []
    for raw in raw_zones:
        zone = {
            "name": raw["name"],
            "type": raw.get("type"),
            "interfaces": raw.get("interfaces", []),
            "vendor_raw": raw.get("vendor_raw", {}),
        }
        zones.append(Zone(**zone).model_dump())
    return zones
