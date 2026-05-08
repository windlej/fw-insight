"""Tests for core.ip_utils."""

import ipaddress

from core.ip_utils import (
    address_count,
    contains,
    is_private,
    is_public,
    normalize_cidr,
    overlaps,
    parse_address,
)


class TestParseAddress:
    def test_cidr(self):
        result = parse_address("10.0.0.0/24")
        assert result is not None
        assert result == ipaddress.IPv4Network("10.0.0.0/24", strict=False)

    def test_single_ip(self):
        result = parse_address("192.168.1.1")
        assert result is not None
        assert result == ipaddress.IPv4Address("192.168.1.1")

    def test_any_returns_none(self):
        assert parse_address("any") is None

    def test_empty_returns_none(self):
        assert parse_address("") is None

    def test_none_returns_none(self):
        assert parse_address("none") is None

    def test_fqdn_returns_none(self):
        assert parse_address("example.com") is None

    def test_invalid_ip_returns_none(self):
        assert parse_address("999.999.999.999") is None

    def test_ip_range_returns_first_as_32(self):
        result = parse_address("10.0.0.1-10.0.0.100")
        assert result is not None
        assert result == ipaddress.IPv4Network("10.0.0.1/32")

    def test_leading_dash_treated_as_invalid(self):
        assert parse_address("-5") is None


class TestContains:
    def test_any_container(self):
        assert contains("any", "10.0.0.1") is True

    def test_any_contained(self):
        assert contains("10.0.0.0/8", "any") is True

    def test_subnet_of(self):
        assert contains("10.0.0.0/8", "10.1.2.3/32") is True

    def test_not_contains(self):
        assert contains("192.168.1.0/24", "10.0.0.1") is False

    def test_equal_strings(self):
        assert contains("10.0.0.1", "10.0.0.1") is True

    def test_non_parseable_equals(self):
        assert contains("srv-web", "srv-web") is True

    def test_non_parseable_not_equal(self):
        assert contains("srv-web", "srv-db") is False

    def test_single_ip_in_network(self):
        assert contains("10.0.0.0/24", "10.0.0.50") is True

    def test_same_network(self):
        assert contains("10.0.0.0/24", "10.0.0.0/24") is True


class TestOverlaps:
    def test_any_overlaps(self):
        assert overlaps("any", "10.0.0.1") is True

    def test_overlapping_networks(self):
        assert overlaps("10.0.0.0/8", "10.1.0.0/16") is True

    def test_non_overlapping(self):
        assert overlaps("10.0.0.0/24", "192.168.1.0/24") is False

    def test_equal_overlaps(self):
        assert overlaps("10.0.0.0/24", "10.0.0.0/24") is True

    def test_non_parseable_equal(self):
        assert overlaps("srv-web", "srv-web") is True

    def test_non_parseable_not_equal(self):
        assert overlaps("srv-web", "srv-db") is False


class TestAddressCount:
    def test_single_host(self):
        assert address_count("10.0.0.1") == 1

    def test_cidr_24(self):
        assert address_count("10.0.0.0/24") == 256

    def test_cidr_8(self):
        assert address_count("10.0.0.0/8") == 16777216

    def test_any_returns_zero(self):
        assert address_count("any") == 0

    def test_fqdn_returns_zero(self):
        assert address_count("example.com") == 0

    def test_invalid_returns_zero(self):
        assert address_count("not-an-ip") == 0


class TestIsPrivate:
    def test_private_10(self):
        assert is_private("10.0.0.1") is True

    def test_private_172(self):
        assert is_private("172.16.0.1") is True

    def test_private_192(self):
        assert is_private("192.168.1.1") is True

    def test_private_cidr(self):
        assert is_private("10.0.0.0/8") is True

    def test_public(self):
        assert is_public("8.8.8.8") is True

    def test_public_cidr(self):
        assert is_public("8.8.8.0/24") is True

    def test_any_not_private(self):
        assert is_private("any") is False

    def test_any_not_public(self):
        assert is_public("any") is False

    def test_loopback_not_public(self):
        assert is_public("127.0.0.1") is False

    def test_loopback_cidr_not_public(self):
        assert is_public("127.0.0.0/8") is False


class TestNormalizeCidr:
    def test_single_ip_to_32(self):
        assert normalize_cidr("10.0.0.1") == "10.0.0.1/32"

    def test_cidr_unchanged(self):
        assert normalize_cidr("10.0.0.0/24") == "10.0.0.0/24"

    def test_cidr_normalized(self):
        assert normalize_cidr("10.0.0.0 255.255.255.0") == "10.0.0.0 255.255.255.0"

    def test_fqdn_unchanged(self):
        assert normalize_cidr("example.com") == "example.com"

    def test_any_unchanged(self):
        assert normalize_cidr("any") == "any"
