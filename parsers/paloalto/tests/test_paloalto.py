"""Tests for Palo Alto parser."""

import pytest
from pathlib import Path

from parsers.paloalto.parser import PaloAltoParser
from parsers.paloalto.normalizer import normalize_paloalto
from core.models import Session

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestPaloAltoParser:
    def test_parse_minimal(self):
        parser = PaloAltoParser()
        config = (FIXTURES_DIR / "config-minimal.xml").read_text()
        ast = parser.parse(config)

        assert ast["version"] == "10.1.0"
        assert ast["hostname"] == "pa-fw-01"
        assert len(ast["address_objects"]) == 2
        assert len(ast["service_objects"]) == 1
        assert len(ast["security_policies"]) == 2
        assert len(ast["nat_rules"]) == 1
        assert len(ast["interfaces"]) == 2
        assert len(ast["zones"]) == 2

    def test_parse_medium(self):
        parser = PaloAltoParser()
        config = (FIXTURES_DIR / "config-medium.xml").read_text()
        ast = parser.parse(config)

        assert ast["hostname"] == "pa-fw-prod-01"
        assert len(ast["address_objects"]) == 7
        assert len(ast["security_policies"]) == 12
        assert len(ast["nat_rules"]) == 2
        assert len(ast["zones"]) == 5

        policy_names = [p["name"] for p in ast["security_policies"]]
        assert "Allow-Any-Any-Legacy" in policy_names
        assert "Allow-Internet-RDP" in policy_names
        assert "Deny-All" in policy_names

    def test_parse_complex(self):
        parser = PaloAltoParser()
        config = (FIXTURES_DIR / "config-complex.xml").read_text()
        ast = parser.parse(config)

        assert ast["hostname"] == "pa-fw-enterprise"
        assert ast["version"] == "11.0.1"
        assert len(ast["security_policies"]) == 27
        assert len(ast["nat_rules"]) == 5
        assert len(ast["zones"]) == 6
        assert len(ast["interfaces"]) == 7

    def test_parse_invalid_xml(self):
        parser = PaloAltoParser()
        with pytest.raises(Exception):
            parser.parse("this is not xml")

    def test_parse_missing_config(self):
        parser = PaloAltoParser()
        with pytest.raises(Exception):
            parser.parse("<root><noconfig/></root>")


class TestPaloAltoNormalizer:
    def test_normalize_minimal(self):
        parser = PaloAltoParser()
        config = (FIXTURES_DIR / "config-minimal.xml").read_text()
        ast = parser.parse(config)
        session_data = normalize_paloalto(ast)
        session = Session.model_validate(session_data)

        assert session.vendor == "paloalto"
        assert session.hostname == "pa-fw-01"
        assert session.vendor_version == "10.1.0"
        assert len(session.security_policies) == 2
        assert session.security_policies[0].action == "allow"
        assert session.security_policies[1].action == "deny"

    def test_normalize_resolves_groups(self):
        parser = PaloAltoParser()
        config = (FIXTURES_DIR / "config-medium.xml").read_text()
        ast = parser.parse(config)
        session_data = normalize_paloalto(ast)
        session = Session.model_validate(session_data)

        addr_group = next(
            (o for o in session.address_objects if o.name == "All-Servers"),
            None,
        )
        assert addr_group is not None
        assert addr_group.type == "group"
        assert addr_group.members is not None
        assert len(addr_group.members) == 3

    def test_normalize_preserves_vendor_raw(self):
        parser = PaloAltoParser()
        config = (FIXTURES_DIR / "config-minimal.xml").read_text()
        ast = parser.parse(config)
        session_data = normalize_paloalto(ast)
        session = Session.model_validate(session_data)

        assert session.security_policies[0].vendor_raw
        assert session.address_objects[0].vendor_raw

    def test_normalize_medium_findings(self):
        parser = PaloAltoParser()
        config = (FIXTURES_DIR / "config-medium.xml").read_text()
        ast = parser.parse(config)
        session_data = normalize_paloalto(ast)
        session = Session.model_validate(session_data)

        any_any = [
            p for p in session.security_policies
            if "any" in p.source.addresses
            and "any" in p.destination.addresses
            and p.action == "allow"
        ]
        assert len(any_any) == 1
        assert any_any[0].name == "Allow-Any-Any-Legacy"

        disabled = [p for p in session.security_policies if not p.enabled]
        assert len(disabled) == 1
