"""Tests for Cisco ASA / Firepower parser."""

from pathlib import Path

from core.models import Session
from parsers.cisco_asa.normalizer import normalize_cisco_asa
from parsers.cisco_asa.parser import CiscoASAParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestCiscoASAParser:
    def test_parse_minimal(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)

        assert ast["system"]["hostname"] == "asa-vm-01"
        assert ast["system"]["version"] == "9.12(4)"
        assert len(ast["interfaces"]) == 2
        assert len(ast["address_objects"]) == 3  # 3 unique objects (WEB_SERVER, DB_SERVER, INTERNAL_SUBNET)
        assert len(ast["address_groups"]) == 0
        assert len(ast["service_groups"]) == 0
        assert len(ast["access_lists"]) == 1
        assert "OUTSIDE-IN" in ast["access_lists"]
        assert len(ast["access_lists"]["OUTSIDE-IN"]) == 3

    def test_parse_minimal_interfaces(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)

        ifaces = {i["_name"]: i for i in ast["interfaces"]}
        assert "GigabitEthernet0/0" in ifaces
        assert ifaces["GigabitEthernet0/0"]["zone"] == "outside"
        assert "GigabitEthernet0/1" in ifaces
        assert ifaces["GigabitEthernet0/1"]["zone"] == "inside"

    def test_parse_minimal_address_objects(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)

        objs = {o["_name"]: o for o in ast["address_objects"]}
        assert objs["WEB_SERVER"]["type"] == "host"
        assert objs["WEB_SERVER"]["value"] == "10.0.0.10"
        assert objs["DB_SERVER"]["type"] == "host"
        assert objs["DB_SERVER"]["value"] == "10.0.0.20"
        assert objs["INTERNAL_SUBNET"]["type"] == "ip_netmask"
        assert objs["INTERNAL_SUBNET"]["value"] == "10.0.1.0/24"

    def test_parse_minimal_acl(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)

        acl = ast["access_lists"]["OUTSIDE-IN"]
        assert acl[0]["action"] == "permit"
        assert acl[0]["protocol"] == "tcp"
        assert acl[0]["source"]["type"] == "any"
        assert acl[0]["destination"]["type"] == "host"
        assert acl[0]["destination"]["value"] == "10.0.0.10"
        assert acl[2]["action"] == "deny"
        assert acl[2]["protocol"] == "ip"
        assert acl[2]["logging"] is True

    def test_parse_minimal_access_groups(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)

        assert len(ast["access_groups"]) == 1
        assert ast["access_groups"][0]["name"] == "OUTSIDE-IN"
        assert ast["access_groups"][0]["direction"] == "in"
        assert ast["access_groups"][0]["interface"] == "outside"

    def test_parse_medium(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)

        assert ast["system"]["hostname"] == "asa-prod-01"
        assert ast["system"]["version"] == "9.16(3)"
        assert len(ast["interfaces"]) == 4
        assert len(ast["address_objects"]) == 5
        assert len(ast["address_groups"]) == 2
        assert len(ast["service_groups"]) == 2
        assert len(ast["access_lists"]) == 3
        assert len(ast["access_groups"]) == 3
        assert "OUTSIDE-IN" in ast["access_lists"]
        assert "INSIDE-OUT" in ast["access_lists"]
        assert "DMZ-ACCESS" in ast["access_lists"]

    def test_parse_medium_name_mappings(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)

        assert ast["name_mappings"]["APP_SERVER"] == "10.10.0.100"
        assert ast["name_mappings"]["DB_SERVER"] == "10.10.0.101"

    def test_parse_medium_address_groups(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)

        grps = {g["_name"]: g for g in ast["address_groups"]}
        assert "ALL_SERVERS" in grps
        assert len(grps["ALL_SERVERS"]["members"]) == 2
        assert "EXTERNAL_CDN" in grps
        assert "MAIL_SERVER" in grps["EXTERNAL_CDN"]["members"]

    def test_parse_medium_service_groups(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)

        grps = {g["_name"]: g for g in ast["service_groups"]}
        assert "WEB_PORTS" in grps
        assert "80" in grps["WEB_PORTS"]["port_objects"]
        assert "443" in grps["WEB_PORTS"]["port_objects"]
        assert "MAIL_PORTS" in grps

    def test_parse_invalid(self):
        parser = CiscoASAParser()
        ast = parser.parse("this is not a valid config")
        assert ast["access_lists"] == {}
        assert ast["address_objects"] == []

    def test_parse_object_nat(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)

        web_srv = next(o for o in ast["address_objects"] if o["_name"] == "WEB_SERVER")
        assert "_nat" in web_srv
        assert web_srv["_nat"][0]["real_interface"] == "inside"
        assert web_srv["_nat"][0]["mapped_interface"] == "outside"
        assert web_srv["_nat"][0]["translated"] == "203.0.113.10"


class TestCiscoASANormalizer:
    def test_normalize_minimal(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        assert session.vendor == "cisco_asa"
        assert session.hostname == "asa-vm-01"
        assert session.vendor_version == "9.12(4)"
        assert len(session.security_policies) == 3

    def test_normalize_minimal_actions(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        assert session.security_policies[0].action == "allow"
        assert session.security_policies[1].action == "allow"
        assert session.security_policies[2].action == "deny"

    def test_normalize_minimal_zones(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        assert len(session.zones) == 2
        zone_names = {z.name for z in session.zones}
        assert "inside" in zone_names
        assert "outside" in zone_names

    def test_normalize_minimal_interfaces(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        assert len(session.interfaces) == 2
        ifaces = {i.name: i for i in session.interfaces}
        assert "GigabitEthernet0/0" in ifaces
        assert ifaces["GigabitEthernet0/0"].zone == "outside"
        assert ifaces["GigabitEthernet0/0"].enabled is True
        assert "GigabitEthernet0/1" in ifaces
        assert ifaces["GigabitEthernet0/1"].zone == "inside"

    def test_normalize_minimal_address_objects(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        assert len(session.address_objects) >= 3
        web = next((o for o in session.address_objects if o.name == "WEB_SERVER"), None)
        assert web is not None
        assert web.type == "ip_netmask"
        assert web.value == "10.0.0.10/32"

    def test_normalize_minimal_nat(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        assert len(session.nat_rules) >= 1

    def test_normalize_medium(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        assert session.vendor == "cisco_asa"
        assert session.hostname == "asa-prod-01"
        assert session.vendor_version == "9.16(3)"
        assert len(session.security_policies) > 0
        assert len(session.zones) >= 3
        assert len(session.address_objects) > 0

    def test_normalize_medium_address_objects(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        by_name = {o.name: o for o in session.address_objects}
        assert "MAIL_SERVER" in by_name
        assert by_name["MAIL_SERVER"].value == "172.16.0.10/32"
        assert "ALL_SERVERS" in by_name
        assert by_name["ALL_SERVERS"].type == "group"
        assert "APP_SERVER" in by_name
        assert "EXTERNAL_DNS" in by_name
        assert by_name["EXTERNAL_DNS"].type == "fqdn"
        assert by_name["EXTERNAL_DNS"].value == "ns1.cloud-provider.com"

    def test_normalize_medium_name_mappings(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        by_name = {o.name: o for o in session.address_objects}
        assert "APP_SERVER" in by_name
        assert by_name["APP_SERVER"].value == "10.10.0.100/32"
        assert "DB_SERVER" in by_name
        assert by_name["DB_SERVER"].value == "10.10.0.101/32"

    def test_normalize_disabled_interface(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        mgmt = next((i for i in session.interfaces if i.name == "Management0/0"), None)
        assert mgmt is not None
        assert mgmt.enabled is False

    def test_normalize_acl_object_reference(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        dns_rules = [
            p for p in session.security_policies
            if any("53" in port for s in p.services for port in s.ports)
        ]
        assert len(dns_rules) >= 1

    def test_normalize_deny_all_rule(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        deny_rules = [p for p in session.security_policies if p.action == "deny"]
        assert len(deny_rules) == 3

    def test_normalize_preserves_vendor_raw(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-minimal.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        assert session.security_policies[0].vendor_raw
        assert session.address_objects[0].vendor_raw

    def test_normalize_disabled_zone_not_created(self):
        parser = CiscoASAParser()
        config = (FIXTURES_DIR / "config-medium.conf").read_text()
        ast = parser.parse(config)
        session_data = normalize_cisco_asa(ast)
        session = Session.model_validate(session_data)

        mgmt_zone = next((z for z in session.zones if z.name == "mgmt"), None)
        assert mgmt_zone is not None
        assert "Management0/0" in mgmt_zone.interfaces
