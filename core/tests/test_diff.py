"""Tests for core.diff."""

import pytest

from core.diff import diff_sessions, _compare_rules
from core.models import (
    Session,
    SecurityPolicy,
    RuleEndpoint,
    ServiceRef,
    AddressObject,
    FieldChange,
)


def _make_session(vendor, policies, address_objects=None):
    return Session(
        vendor=vendor,
        security_policies=policies,
        address_objects=address_objects or [],
    )


def _make_policy(id, name, position=1, action="allow", src_addrs=None, dst_addrs=None, services=None, enabled=True):
    return SecurityPolicy(
        id=id,
        name=name,
        position=position,
        source=RuleEndpoint(addresses=src_addrs or ["any"]),
        destination=RuleEndpoint(addresses=dst_addrs or ["any"]),
        services=services or [ServiceRef(protocol="any")],
        action=action,
        enabled=enabled,
    )


class TestDiffSessions:
    def test_no_changes(self):
        policy = _make_policy("1", "allow-all", src_addrs=["10.0.0.0/8"], dst_addrs=["10.0.0.1/32"])
        a = _make_session("paloalto", [policy])
        b = _make_session("paloalto", [policy])
        diff = diff_sessions(a, b)
        assert diff.added_rules == []
        assert diff.removed_rules == []
        assert diff.modified_rules == []

    def test_added_rule(self):
        a = _make_session("paloalto", [])
        b = _make_session("paloalto", [_make_policy("1", "new-rule")])
        diff = diff_sessions(a, b)
        assert len(diff.added_rules) == 1
        assert diff.added_rules[0].name == "new-rule"
        assert diff.removed_rules == []

    def test_removed_rule(self):
        a = _make_session("paloalto", [_make_policy("1", "old-rule")])
        b = _make_session("paloalto", [])
        diff = diff_sessions(a, b)
        assert len(diff.removed_rules) == 1
        assert diff.removed_rules[0].name == "old-rule"
        assert diff.added_rules == []

    def test_modified_rule(self):
        a_policy = _make_policy("1", "rule", action="allow", src_addrs=["10.0.0.0/8"])
        b_policy = _make_policy("1", "rule", action="deny", src_addrs=["10.0.0.0/8"])
        a = _make_session("paloalto", [a_policy])
        b = _make_session("paloalto", [b_policy])
        diff = diff_sessions(a, b)
        assert len(diff.modified_rules) == 1
        changes = diff.modified_rules[0].changes
        assert any(c.field == "action" for c in changes)

    def test_vendor_mismatch(self):
        a = _make_session("paloalto", [])
        b = _make_session("fortinet", [])
        diff = diff_sessions(a, b)
        assert diff.vendor_match is False

    def test_added_object(self):
        a = _make_session("paloalto", [])
        b = _make_session("paloalto", [], address_objects=[
            AddressObject(name="new-obj", value="10.0.0.1/32"),
        ])
        diff = diff_sessions(a, b)
        assert len(diff.added_objects) == 1
        assert diff.added_objects[0].name == "new-obj"

    def test_removed_object(self):
        a = _make_session("paloalto", [], address_objects=[
            AddressObject(name="old-obj", value="10.0.0.1/32"),
        ])
        b = _make_session("paloalto", [])
        diff = diff_sessions(a, b)
        assert len(diff.removed_objects) == 1
        assert diff.removed_objects[0].name == "old-obj"

    def test_modified_object(self):
        a = _make_session("paloalto", [], address_objects=[
            AddressObject(name="srv", value="10.0.0.1/32"),
        ])
        b = _make_session("paloalto", [], address_objects=[
            AddressObject(name="srv", value="10.0.0.2/32"),
        ])
        diff = diff_sessions(a, b)
        assert len(diff.modified_objects) == 1
        assert diff.modified_objects[0].changes[0].field == "value"
        assert diff.modified_objects[0].changes[0].old_value == "10.0.0.1/32"

    def test_multiple_changes(self):
        a_policy = _make_policy("1", "rule", action="allow", src_addrs=["10.0.0.0/8"], dst_addrs=["any"], enabled=True)
        b_policy = _make_policy("1", "rule-renamed", action="deny", src_addrs=["192.168.0.0/16"], dst_addrs=["10.0.0.1"], enabled=False)
        a = _make_session("paloalto", [a_policy])
        b = _make_session("paloalto", [b_policy])
        diff = diff_sessions(a, b)
        assert len(diff.modified_rules) == 1
        changes = diff.modified_rules[0].changes
        change_fields = [c.field for c in changes]
        assert "action" in change_fields
        assert "enabled" in change_fields
        assert "name" in change_fields


class TestCompareRules:
    def test_no_changes(self):
        a = _make_policy("1", "rule")
        b = _make_policy("1", "rule")
        changes = _compare_rules(a, b)
        assert changes == []

    def test_action_change(self):
        a = _make_policy("1", "rule", action="allow")
        b = _make_policy("1", "rule", action="deny")
        changes = _compare_rules(a, b)
        assert len(changes) == 1
        assert changes[0].field == "action"
        assert changes[0].old_value == "allow"
        assert changes[0].new_value == "deny"

    def test_source_change(self):
        a = _make_policy("1", "rule", src_addrs=["10.0.0.0/8"])
        b = _make_policy("1", "rule", src_addrs=["192.168.0.0/16"])
        changes = _compare_rules(a, b)
        assert any(c.field == "source" for c in changes)

    def test_services_change(self):
        a = _make_policy("1", "rule", services=[ServiceRef(protocol="any")])
        b = _make_policy("1", "rule", services=[ServiceRef(protocol="tcp", ports=["80"])])
        changes = _compare_rules(a, b)
        assert any(c.field == "services" for c in changes)
