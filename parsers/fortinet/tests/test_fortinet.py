"""Tests for Fortinet FortiGate parser."""

from pathlib import Path

from core.models import Session
from parsers.fortinet.normalizer import normalize_fortinet
from parsers.fortinet.parser import FortinetParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestFortinetParser:
    def test_parse_minimal(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)

        assert ast["system"]["hostname"] == "fgt-vm-01"
        assert len(ast["address_objects"]) == 2
        assert len(ast["service_objects"]) == 1
        assert len(ast["policies"]) == 2
        assert len(ast["nat_rules"]) == 1
        assert len(ast["interfaces"]) == 2
        assert len(ast["ippools"]) == 1

    def test_parse_medium(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)

        assert ast["system"]["hostname"] == "fgt-prod-01"
        assert len(ast["address_objects"]) == 8
        assert len(ast["address_groups"]) == 1
        assert len(ast["service_objects"]) == 8
        assert len(ast["service_groups"]) == 1
        assert len(ast["policies"]) == 16
        assert len(ast["nat_rules"]) == 3
        assert len(ast["ippools"]) == 2

        policy_names = [p.get("name") for p in ast["policies"]]
        assert "Allow-Any-Any-Legacy" in policy_names
        assert "Allow-Internet-RDP" in policy_names
        assert "Deny-All" in policy_names

    def test_parse_complex(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-complex.conf").read_text()
        ast = parser.parse(config)

        assert ast["system"]["hostname"] == "fgt-enterprise"
        assert len(ast["policies"]) == 30
        assert len(ast["nat_rules"]) == 5
        assert len(ast["address_objects"]) == 20
        assert len(ast["address_groups"]) == 6
        assert len(ast["service_objects"]) == 11
        assert len(ast["service_groups"]) == 3
        assert len(ast["ippools"]) == 4
        assert len(ast["interfaces"]) == 8
        assert len(ast["zones"]) == 5

        vdoms = ast.get("vdoms", [])
        assert len(vdoms) == 2

    def test_parse_invalid(self):
        parser = FortinetParser()
        ast = parser.parse("this is not a valid config")
        assert ast["policies"] == []
        assert ast["address_objects"] == []

    def test_parse_quoted_values(self):
        parser = FortinetParser()
        config = '''
config firewall address
    edit "my-address"
        set type ipmask
        set subnet 10.0.0.0/24
        set comment "test comment"
    next
end
'''
        ast = parser.parse(config)
        assert len(ast["address_objects"]) == 1
        assert ast["address_objects"][0]["_name"] == "my-address"
        assert ast["address_objects"][0]["comment"] == "test comment"


class TestFortinetNormalizer:
    def test_normalize_minimal(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        assert session.vendor == "fortinet"
        assert session.hostname == "fgt-vm-01"
        assert len(session.security_policies) == 2
        assert session.security_policies[0].action == "allow"
        assert session.security_policies[1].action == "deny"

    def test_normalize_address_mapping(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        addr = next((o for o in session.address_objects if o.name == "internal-net"), None)
        assert addr is not None
        assert addr.type == "ip_netmask"
        assert addr.value == "10.0.1.0/24"

    def test_normalize_iprange(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        addr = next((o for o in session.address_objects if o.name == "External-CDN"), None)
        assert addr is not None
        assert addr.type == "ip_range"
        assert addr.value == "151.101.0.1-151.101.255.254"

    def test_normalize_fqdn(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        addr = next((o for o in session.address_objects if o.name == "mail-server"), None)
        assert addr is not None
        assert addr.type == "fqdn"
        assert addr.value == "mail.example.com"

    def test_normalize_resolves_groups(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        addr_group = next(
            (o for o in session.address_objects if o.name == "All-Servers"),
            None,
        )
        assert addr_group is not None
        assert addr_group.type == "group"
        assert addr_group.members is not None
        assert len(addr_group.members) == 3

    def test_normalize_service_resolution(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        svc = next((o for o in session.service_objects if o.name == "Web-Services"), None)
        assert svc is not None
        assert svc.protocol == "any"
        assert svc.members is not None

    def test_normalize_accept_to_allow(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        assert session.security_policies[0].action == "allow"

    def test_normalize_all_to_any(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        any_any = [
            p for p in session.security_policies
            if "any" in p.source.addresses
            and "any" in p.destination.addresses
            and p.action == "allow"
        ]
        assert len(any_any) == 2
        names = [p.name for p in any_any]
        assert "Allow-Any-Any-Legacy" in names
        assert "Any-Any-Test" in names

    def test_normalize_disabled_rules(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        disabled = [p for p in session.security_policies if not p.enabled]
        assert len(disabled) == 1
        assert disabled[0].name == "Disabled-Old-Rule"

    def test_normalize_preserves_vendor_raw(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        assert session.security_policies[0].vendor_raw
        assert session.address_objects[0].vendor_raw

    def test_normalize_nat_rules(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        assert len(session.nat_rules) > 0

        dst_nat = [
            r for r in session.nat_rules
            if r.type == "destination_nat"
        ]
        assert len(dst_nat) >= 1

    def test_normalize_port_range(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        svc = next((o for o in session.service_objects if o.name == "Wide-Port-Range"), None)
        assert svc is not None
        assert "1024-65535" in svc.ports

    def test_normalize_medium_findings(self):
        parser = FortinetParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_fortinet(ast)
        session = Session.model_validate(session_data)

        internet_rdp = [
            p for p in session.security_policies
            if p.name == "Allow-Internet-RDP"
        ]
        assert len(internet_rdp) == 1
        assert internet_rdp[0].source.addresses == ["any"]
        assert "10.10.100.20/32" in internet_rdp[0].destination.addresses
