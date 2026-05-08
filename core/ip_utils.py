"""IP address and CIDR utility functions."""

import ipaddress


def parse_address(addr: str) -> ipaddress.IPv4Network | ipaddress.IPv4Address | None:
    """Parse an address string into an IPv4Network or IPv4Address.

    Returns None for special values like 'any', 'none', FQDNs, or invalid input.
    """
    if not addr or addr.lower() in ("any", "none", ""):
        return None

    try:
        if "/" in addr:
            return ipaddress.IPv4Network(addr, strict=False)
        if "-" in addr and not addr.startswith("-"):
            parts = addr.split("-", 1)
            return ipaddress.IPv4Network(f"{parts[0]}/32")
        return ipaddress.IPv4Address(addr)
    except (ValueError, TypeError):
        return None


def contains(container: str, contained: str) -> bool:
    """Check if container address/network contains the contained address/network.

    Returns True if either value is 'any'.
    """
    if container == "any" or contained == "any":
        return True

    c = parse_address(container)
    d = parse_address(contained)

    if c is None or d is None:
        return container == contained

    if isinstance(c, ipaddress.IPv4Address):
        c = ipaddress.IPv4Network(f"{c}/32")
    if isinstance(d, ipaddress.IPv4Address):
        d = ipaddress.IPv4Network(f"{d}/32")

    try:
        return d.subnet_of(c)
    except TypeError:
        return False


def overlaps(a: str, b: str) -> bool:
    """Check if two addresses/networks overlap.

    Returns True if either value is 'any'.
    """
    if a == "any" or b == "any":
        return True

    addr_a = parse_address(a)
    addr_b = parse_address(b)

    if addr_a is None or addr_b is None:
        return a == b

    if isinstance(addr_a, ipaddress.IPv4Address):
        addr_a = ipaddress.IPv4Network(f"{addr_a}/32")
    if isinstance(addr_b, ipaddress.IPv4Address):
        addr_b = ipaddress.IPv4Network(f"{addr_b}/32")

    return addr_a.overlaps(addr_b)


def address_count(addr: str) -> int:
    """Return the number of IP addresses in a network.

    Returns 0 for special values, FQDNs, or invalid input.
    """
    parsed = parse_address(addr)
    if parsed is None:
        return 0
    if isinstance(parsed, ipaddress.IPv4Address):
        return 1
    return parsed.num_addresses


def is_private(addr: str) -> bool:
    """Check if an address is in a private range.

    Returns False for 'any' or invalid input.
    """
    parsed = parse_address(addr)
    if parsed is None:
        return False
    if isinstance(parsed, ipaddress.IPv4Address):
        return parsed.is_private
    return parsed.network_address.is_private


def is_public(addr: str) -> bool:
    """Check if an address is public (not private, not loopback).

    Returns False for 'any' or invalid input.
    """
    parsed = parse_address(addr)
    if parsed is None:
        return False
    if isinstance(parsed, ipaddress.IPv4Address):
        return not parsed.is_private and not parsed.is_loopback
    return not parsed.network_address.is_private and not parsed.network_address.is_loopback


def normalize_cidr(addr: str) -> str:
    """Normalize an address string to canonical CIDR notation.

    Returns the original string if it cannot be parsed.
    """
    parsed = parse_address(addr)
    if parsed is None:
        return addr
    if isinstance(parsed, ipaddress.IPv4Address):
        return str(ipaddress.IPv4Network(f"{parsed}/32"))
    return str(parsed)
