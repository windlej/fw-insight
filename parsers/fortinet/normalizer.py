"""Fortinet FortiGate AST to canonical Session normalizer.

Maps FortiGate-specific fields to the canonical data model:
- accept → allow
- srcaddr/dstaddr → resolved (groups expanded, "all" → "any")
- srcintf/dstintf → zones (interfaces mapped to zone names)
- logtraffic all → log_end: true
- service groups → expanded service references
- Multi-vdom → flattened with vdom tags in vendor_raw
"""

from typing import Any

from core.models import (
    SecurityPolicy,
    NATRule,
    Interface,
    Zone,
    AddressObject,
    ServiceObject,
    RuleEndpoint,
    ServiceRef,
)


def normalize_fortinet(ast: dict[str, Any]) -> dict[str, Any]:
    """Convert FortiGate AST to canonical Session-compatible dict."""
    interfaces = _normalize_interfaces(ast.get("interfaces", []))
    zones = _normalize_zones(ast.get("zones", []), interfaces)

    addr_objects = _normalize_address_objects(
        ast.get("address_objects", []),
        ast.get("address_groups", []),
    )
    svc_objects = _normalize_service_objects(
        ast.get("service_objects", []),
        ast.get("service_groups", []),
    )

    addr_map = {o["name"]: o for o in addr_objects}
    svc_map = {o["name"]: o for o in svc_objects}
    iface_to_zone = {
        iface["name"]: iface.get("zone")
        for iface in interfaces
        if iface.get("zone")
    }
    ippool_map = {p.get("name") or p.get("_name", ""): p for p in ast.get("ippools", [])}

    all_policies = ast.get("policies", [])
    policies = _normalize_policies(all_policies, addr_map, svc_map, iface_to_zone)

    nat_rules = _normalize_nat_rules(
        ast.get("nat_rules", []),
        ast.get("policies", []),
        addr_map,
        svc_map,
        ippool_map,
    )

    hostname = ast.get("system", {}).get("hostname")
    version = ast.get("system", {}).get("version")

    return {
        "vendor": "fortinet",
        "hostname": hostname,
        "vendor_version": version,
        "security_policies": policies,
        "nat_rules": nat_rules,
        "interfaces": interfaces,
        "zones": zones,
        "address_objects": addr_objects,
        "service_objects": svc_objects,
        "metadata": {
            "vdom_count": len(ast.get("vdoms", [])),
        },
    }


def _normalize_address_objects(
    raw_objects: list[dict],
    raw_groups: list[dict],
) -> list[dict]:
    objects = []

    for obj in raw_objects:
        fg_type = obj.get("type", "ipmask")
        name = obj.get("_name", "unknown")
        value = ""

        if fg_type == "ipmask":
            subnet = obj.get("subnet", "")
            value = _normalize_subnet(subnet)
            obj_type = "ip_netmask"
        elif fg_type == "iprange":
            start = obj.get("start-ip", "")
            end = obj.get("end-ip", "")
            value = f"{start}-{end}" if start and end else start
            obj_type = "ip_range"
        elif fg_type == "fqdn":
            value = obj.get("fqdn", "")
            obj_type = "fqdn"
        elif fg_type == "geography":
            value = obj.get("country", "")
            obj_type = "fqdn"
        else:
            value = obj.get("subnet", obj.get("start-ip", ""))
            obj_type = "ip_netmask"

        objects.append(
            AddressObject(
                name=name,
                type=obj_type,
                value=value,
                description=obj.get("comment"),
                vendor_raw=obj,
            ).model_dump()
        )

    for grp in raw_groups:
        name = grp.get("_name", "unknown")
        members_raw = grp.get("member", [])
        if isinstance(members_raw, str):
            members = [members_raw]
        else:
            members = [m for m in (members_raw or []) if m]

        objects.append(
            AddressObject(
                name=name,
                type="group",
                value="",
                members=members,
                description=grp.get("comment"),
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
        protocol = obj.get("protocol", "TCP").lower()
        if protocol not in ("tcp", "udp", "icmp", "sctp"):
            protocol = "tcp"

        ports = []
        portrange = obj.get("tcp-portrange") or obj.get("udp-portrange") or ""
        if portrange:
            ports = _extract_ports(portrange)

        objects.append(
            ServiceObject(
                name=name,
                protocol=protocol,
                ports=ports,
                description=obj.get("comment"),
                vendor_raw=obj,
            ).model_dump()
        )

    for grp in raw_groups:
        name = grp.get("_name", "unknown")
        members_raw = grp.get("member", [])
        if isinstance(members_raw, str):
            members = [members_raw]
        else:
            members = [m for m in (members_raw or []) if m]

        objects.append(
            ServiceObject(
                name=name,
                protocol="any",
                ports=[],
                members=members,
                description=grp.get("comment"),
                vendor_raw=grp,
            ).model_dump()
        )

    return objects


def _resolve_addresses(
    raw_addrs: list[str],
    addr_map: dict,
) -> list[str]:
    resolved = []
    for addr in raw_addrs:
        if addr.lower() in ("all", "any"):
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
    raw_svcs: list[str],
    svc_map: dict,
) -> list[ServiceRef]:
    resolved = []
    for svc in raw_svcs:
        if svc.upper() == "ALL":
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
    iface_to_zone: dict,
) -> list[dict]:
    policies = []

    for position, raw in enumerate(raw_policies, start=1):
        src_addrs = raw.get("srcaddr", ["all"])
        dst_addrs = raw.get("dstaddr", ["all"])
        src_ifaces = raw.get("srcintf", [])
        dst_ifaces = raw.get("dstintf", [])

        src_zones = [
            iface_to_zone.get(i)
            for i in src_ifaces
            if iface_to_zone.get(i)
        ]
        src_zones = [z for z in src_zones if z]

        dst_zones = [
            iface_to_zone.get(i)
            for i in dst_ifaces
            if iface_to_zone.get(i)
        ]
        dst_zones = [z for z in dst_zones if z]

        source = RuleEndpoint(
            addresses=_resolve_addresses(
                src_addrs if isinstance(src_addrs, list) else [src_addrs],
                addr_map,
            ),
            zones=src_zones,
        )
        destination = RuleEndpoint(
            addresses=_resolve_addresses(
                dst_addrs if isinstance(dst_addrs, list) else [dst_addrs],
                addr_map,
            ),
            zones=dst_zones,
        )

        raw_svcs = raw.get("service", ["ALL"])
        if isinstance(raw_svcs, str):
            raw_svcs = [raw_svcs]
        services = _resolve_services(raw_svcs, svc_map)

        action = raw.get("action", "accept").lower()
        if action == "accept":
            action = "allow"
        elif action in ("deny", "reject"):
            action = "deny"
        else:
            action = "allow"

        logtraffic = raw.get("logtraffic", "").lower()
        log_end = logtraffic in ("all", "utm", "security")
        log_start = raw.get("logtraffic-start", "").lower() == "enable"

        status = raw.get("status", "enable").lower()
        enabled = status != "disable"

        policy_type = _detect_policy_type(raw)

        canonical = {
            "id": str(raw.get("_name", position)),
            "name": raw.get("name"),
            "position": position,
            "source": source,
            "destination": destination,
            "services": services,
            "action": action,
            "enabled": enabled,
            "logging": {
                "log_start": log_start,
                "log_end": log_end,
            },
            "schedule": raw.get("schedule") if raw.get("schedule") != "always" else None,
            "description": raw.get("comments") or raw.get("comment"),
            "vendor_raw": {**raw, "policy_type": policy_type},
        }

        policies.append(SecurityPolicy(**canonical).model_dump())

    return policies


def _normalize_nat_rules(
    raw_nat: list[dict],
    raw_policies: list[dict],
    addr_map: dict,
    svc_map: dict,
    ippool_map: dict,
) -> list[dict]:
    rules = []

    for position, raw in enumerate(raw_nat, start=1):
        status = raw.get("status", "enable").lower()
        enabled = status != "disable"

        src_addrs = raw.get("src-addr", ["all"])
        if isinstance(src_addrs, str):
            src_addrs = [src_addrs]
        orig_source = ", ".join(_resolve_addresses(src_addrs, addr_map)) if src_addrs != ["all"] else None

        dst_addrs = raw.get("dst-addr", ["all"])
        if isinstance(dst_addrs, str):
            dst_addrs = [dst_addrs]
        orig_dest = ", ".join(_resolve_addresses(dst_addrs, addr_map)) if dst_addrs != ["all"] else None

        ippool_name = raw.get("ippool")
        extip = raw.get("extip")

        translated_src = None
        translated_dest = None

        if ippool_name and ippool_name in ippool_map:
            pool = ippool_map[ippool_name]
            start = pool.get("startip", "")
            end = pool.get("endip", "")
            if start:
                translated_src = f"{start}-{end}" if end else start

        if extip:
            translated_dest = extip

        nat_type = "source_nat"
        if raw.get("fixedport", "").lower() == "enable":
            nat_type = "static"
        if translated_dest and not translated_src:
            nat_type = "destination_nat"

        rule = {
            "id": str(raw.get("_name", position)),
            "name": raw.get("comments") or raw.get("name"),
            "position": position,
            "type": nat_type,
            "original_source": orig_source,
            "translated_source": translated_src,
            "original_destination": orig_dest,
            "translated_destination": translated_dest,
            "enabled": enabled,
            "vendor_raw": raw,
        }

        rules.append(NATRule(**rule).model_dump())

    for position, raw in enumerate(raw_policies, start=len(rules) + 1):
        if raw.get("nat", "").lower() != "enable":
            continue

        src_addrs = raw.get("srcaddr", ["all"])
        if isinstance(src_addrs, str):
            src_addrs = [src_addrs]
        resolved_src = _resolve_addresses(src_addrs, addr_map)

        pool_names = raw.get("poolname", [])
        if isinstance(pool_names, str):
            pool_names = [pool_names]

        translated_src = None
        for pname in pool_names:
            if pname in ippool_map:
                pool = ippool_map[pname]
                start = pool.get("startip", "")
                end = pool.get("endip", "")
                if start:
                    translated_src = f"{start}-{end}" if end else start
                break

        rule = {
            "id": f"policy-nat-{raw.get('_name', position)}",
            "name": f"NAT for policy {raw.get('name') or raw.get('_name')}",
            "position": position,
            "type": "source_nat",
            "original_source": ", ".join(resolved_src) if resolved_src != ["any"] else None,
            "translated_source": translated_src,
            "original_destination": None,
            "translated_destination": None,
            "enabled": raw.get("status", "enable").lower() != "disable",
            "vendor_raw": raw,
        }

        rules.append(NATRule(**rule).model_dump())

    return rules


def _normalize_interfaces(raw_interfaces: list[dict]) -> list[dict]:
    interfaces = []

    for raw in raw_interfaces:
        name = raw.get("_name", "unknown")
        mode = raw.get("mode", "static")
        ip = raw.get("ip", "")

        status = raw.get("status", "").lower()
        enabled = status != "down"

        if mode in ("static", "dhcp"):
            iface_type = "physical"
        elif mode == "vlan":
            iface_type = "vlan"
        elif mode == "tunnel":
            iface_type = "tunnel"
        else:
            iface_type = "physical"

        addresses = []
        if ip:
            ip = ip.replace(" ", "/")
            addresses = [ip]

        zone = raw.get("zone")

        iface = {
            "name": name,
            "type": iface_type,
            "enabled": enabled,
            "ip_addresses": addresses,
            "zone": zone,
            "description": raw.get("description") or raw.get("alias"),
            "vendor_raw": raw,
        }

        interfaces.append(Interface(**iface).model_dump())

    return interfaces


def _normalize_zones(raw_zones: list[dict], interfaces: list[dict]) -> list[dict]:
    zones = []
    iface_names = {i["name"] for i in interfaces}

    for raw in raw_zones:
        name = raw.get("_name", "unknown")
        members_raw = raw.get("interface", [])
        if isinstance(members_raw, str):
            members = [members_raw]
        else:
            members = [m for m in (members_raw or []) if m]

        zone = {
            "name": name,
            "type": "layer3",
            "interfaces": members,
            "vendor_raw": raw,
        }

        zones.append(Zone(**zone).model_dump())

    for iface in interfaces:
        if iface.get("zone") and iface["zone"] not in [z["name"] for z in zones]:
            zones.append(
                Zone(
                    name=iface["zone"],
                    type="layer3",
                    interfaces=[iface["name"]],
                ).model_dump()
            )

    return zones


def _normalize_subnet(subnet: str) -> str:
    """Normalize FortiGate subnet format to CIDR.

    FortiGate uses '10.0.0.0 255.255.255.0' or '10.0.0.0/24'.
    """
    subnet = subnet.strip()
    if "/" in subnet:
        return subnet
    if " " in subnet:
        parts = subnet.split()
        ip = parts[0]
        mask = parts[1]
        cidr = _netmask_to_cidr(mask)
        if cidr is not None:
            return f"{ip}/{cidr}"
    return subnet


def _netmask_to_cidr(mask: str) -> int | None:
    """Convert dotted decimal netmask to CIDR prefix length."""
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


def _extract_ports(portrange: str) -> list[str]:
    """Extract port numbers from FortiGate portrange format.

    Formats:
    - "80" → ["80"]
    - "80 443" → ["80", "443"]
    - "10.0.0.1:8080-10.0.0.2:9090" → ["8080-9090"]
    - "0-65535" → ["0-65535"]
    """
    ports = []
    for entry in portrange.split():
        entry = entry.strip()
        if ":" in entry:
            parts = entry.split(":")
            port_part = parts[-1] if parts else entry
        else:
            port_part = entry

        if "-" in port_part:
            parts = port_part.split("-", 1)
            try:
                low = int(parts[0])
                high = int(parts[1])
                if low == high:
                    ports.append(str(low))
                else:
                    ports.append(f"{low}-{high}")
            except (ValueError, IndexError):
                ports.append(port_part)
        else:
            try:
                int(port_part)
                ports.append(port_part)
            except ValueError:
                ports.append(port_part)

    return ports


def _detect_policy_type(raw: dict) -> str:
    """Detect the policy type from raw FortiGate data."""
    if raw.get("nat", "").lower() == "enable":
        return "nat"
    if raw.get("action", "").lower() == "accept":
        return "accept"
    return raw.get("action", "unknown")
