"""Tests for core.models."""

import pytest

from core.models import (
    Session,
    SecurityPolicy,
    NATRule,
    Interface,
    Zone,
    AddressObject,
    ServiceObject,
    ServiceRef,
    RuleEndpoint,
    Finding,
    AnalysisResult,
    ConfigDiff,
    Severity,
    Category,
)


class TestSeverity:
    def test_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestCategory:
    def test_values(self):
        assert Category.SECURITY.value == "security"
        assert Category.OPERATIONAL.value == "operational"
        assert Category.COMPLIANCE.value == "compliance"


class TestServiceRef:
    def test_defaults(self):
        svc = ServiceRef()
        assert svc.protocol == "any"
        assert svc.ports == []

    def test_custom(self):
        svc = ServiceRef(protocol="tcp", ports=["80", "443"])
        assert svc.protocol == "tcp"
        assert svc.ports == ["80", "443"]


class TestRuleEndpoint:
    def test_defaults(self):
        ep = RuleEndpoint()
        assert ep.addresses == []
        assert ep.zones == []
        assert ep.users is None

    def test_custom(self):
        ep = RuleEndpoint(addresses=["any"], zones=["untrust"], users=["admin"])
        assert ep.addresses == ["any"]
        assert ep.zones == ["untrust"]
        assert ep.users == ["admin"]


class TestSecurityPolicy:
    def test_defaults(self):
        p = SecurityPolicy(id="1", name="test", position=1)
        assert p.action == "allow"
        assert p.enabled is True
        assert p.logging == {"log_start": False, "log_end": False}
        assert p.schedule is None
        assert p.vendor_raw == {}

    def test_allow_action(self):
        p = SecurityPolicy(id="1", position=1, action="allow")
        assert p.action == "allow"

    def test_deny_action(self):
        p = SecurityPolicy(id="1", position=1, action="deny")
        assert p.action == "deny"


class TestNATRule:
    def test_defaults(self):
        r = NATRule(id="1", name="nat-1", position=1)
        assert r.type == "source_nat"
        assert r.enabled is True

    def test_static_nat(self):
        r = NATRule(id="1", position=1, type="static")
        assert r.type == "static"

    def test_translation_fields(self):
        r = NATRule(
            id="1",
            position=1,
            translated_source="198.51.100.1",
            translated_destination="203.0.113.1",
        )
        assert r.translated_source == "198.51.100.1"
        assert r.translated_destination == "203.0.113.1"


class TestInterface:
    def test_defaults(self):
        i = Interface(name="eth0")
        assert i.type == "physical"
        assert i.enabled is True
        assert i.ip_addresses == []
        assert i.zone is None

    def test_with_ip(self):
        i = Interface(name="eth0", ip_addresses=["10.0.0.1/24"])
        assert i.ip_addresses == ["10.0.0.1/24"]


class TestZone:
    def test_defaults(self):
        z = Zone(name="untrust")
        assert z.type is None
        assert z.interfaces == []

    def test_with_interfaces(self):
        z = Zone(name="trust", interfaces=["eth0", "eth1"])
        assert z.interfaces == ["eth0", "eth1"]


class TestAddressObject:
    def test_defaults(self):
        o = AddressObject(name="srv-web", value="10.0.0.1/32")
        assert o.type == "ip_netmask"
        assert o.members is None

    def test_group_type(self):
        o = AddressObject(name="all-servers", value="", type="group", members=["srv-web", "srv-db"])
        assert o.type == "group"
        assert o.members == ["srv-web", "srv-db"]


class TestServiceObject:
    def test_defaults(self):
        o = ServiceObject(name="HTTP", protocol="tcp", ports=["80"])
        assert o.protocol == "tcp"
        assert o.ports == ["80"]


class TestSession:
    def test_defaults(self):
        s = Session(vendor="paloalto")
        assert s.vendor == "paloalto"
        assert s.id is not None
        assert s.security_policies == []
        assert s.nat_rules == []

    def test_rule_count(self):
        s = Session(vendor="fortinet", security_policies=[
            SecurityPolicy(id="1", position=1),
            SecurityPolicy(id="2", position=2),
        ])
        assert s.rule_count == 2

    def test_with_hostname(self):
        s = Session(vendor="paloalto", hostname="fw-01", vendor_version="10.1.0")
        assert s.hostname == "fw-01"
        assert s.vendor_version == "10.1.0"


class TestFinding:
    def test_defaults(self):
        f = Finding(check_id="FW-001", title="Test", description="desc", entity_id="1", entity_type="security_policy")
        assert f.severity == Severity.INFO
        assert f.category == Category.SECURITY
        assert f.references == []
        assert f.related_entity_ids == []


class TestAnalysisResult:
    def test_defaults(self):
        r = AnalysisResult(session_id="abc")
        assert r.findings == []
        assert r.health_score == 100
        assert r.finding_counts == {}

    def test_health_score_no_findings(self):
        r = AnalysisResult(session_id="abc")
        r.calculate_health_score()
        assert r.health_score == 100

    def test_health_score_with_findings(self):
        r = AnalysisResult(session_id="abc", findings=[
            Finding(check_id="FW-001", severity=Severity.HIGH, title="t", description="d", entity_id="1", entity_type="security_policy"),
        ])
        r.calculate_health_score()
        assert r.health_score < 100

    def test_compute_finding_counts(self):
        r = AnalysisResult(session_id="abc", findings=[
            Finding(check_id="FW-001", severity=Severity.HIGH, title="t1", description="d", entity_id="1", entity_type="security_policy"),
            Finding(check_id="FW-002", severity=Severity.HIGH, title="t2", description="d", entity_id="2", entity_type="security_policy"),
            Finding(check_id="FW-003", severity=Severity.MEDIUM, title="t3", description="d", entity_id="3", entity_type="security_policy"),
        ])
        r.compute_finding_counts()
        assert r.finding_counts == {"high": 2, "medium": 1}

    def test_rule_count_for_scoring(self):
        r = AnalysisResult(session_id="abc", findings=[
            Finding(check_id="FW-001", severity=Severity.HIGH, title="t", description="d", entity_id="1", entity_type="security_policy"),
            Finding(check_id="FW-002", severity=Severity.MEDIUM, title="t", description="d", entity_id="1", entity_type="security_policy"),
            Finding(check_id="FW-003", severity=Severity.LOW, title="t", description="d", entity_id="2", entity_type="security_policy"),
        ])
        assert r.rule_count_for_scoring() == 2


class TestConfigDiff:
    def test_defaults(self):
        d = ConfigDiff(session_a_id="a", session_b_id="b", vendor_match=True)
        assert d.added_rules == []
        assert d.removed_rules == []
        assert d.modified_rules == []
        assert d.vendor_match is True
