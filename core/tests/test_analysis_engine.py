"""Tests for core.analysis engine and registry."""

import pytest

from core.models import (
    Session,
    SecurityPolicy,
    RuleEndpoint,
    ServiceRef,
    Finding,
)
from core.analysis.engine import AnalysisEngine
from core.analysis.registry import check, get_checks, run_checks, _CHECK_REGISTRY


class TestRegistry:
    def test_get_checks_returns_checks(self):
        checks = get_checks()
        assert len(checks) >= 6

    def test_check_ids_present(self):
        check_ids = [c["id"] for c in get_checks()]
        assert "FW-001" in check_ids
        assert "FW-002" in check_ids
        assert "FW-003" in check_ids
        assert "FW-004" in check_ids
        assert "FW-005" in check_ids
        assert "FW-006" in check_ids


class TestEngine:
    def test_analyze_empty_session(self):
        engine = AnalysisEngine()
        session = Session(vendor="test")
        result = engine.analyze(session)
        assert result.session_id == session.id
        assert result.findings == []
        assert result.health_score == 100

    def test_analyze_with_any_any(self):
        engine = AnalysisEngine()
        policy = SecurityPolicy(
            id="1",
            name="any-any",
            position=1,
            source=RuleEndpoint(addresses=["any"]),
            destination=RuleEndpoint(addresses=["any"]),
            services=[ServiceRef(protocol="any")],
            action="allow",
        )
        session = Session(vendor="test", security_policies=[policy])
        result = engine.analyze(session)
        assert len(result.findings) >= 1

        finding_ids = [f.check_id for f in result.findings]
        assert "FW-001" in finding_ids
        assert result.health_score < 100

    def test_analyze_computes_counts(self):
        engine = AnalysisEngine()
        policy = SecurityPolicy(
            id="1",
            name="any-any",
            position=1,
            source=RuleEndpoint(addresses=["any"]),
            destination=RuleEndpoint(addresses=["any"]),
            services=[ServiceRef(protocol="any")],
            action="allow",
            logging={"log_start": False, "log_end": False},
        )
        session = Session(vendor="test", security_policies=[policy])
        result = engine.analyze(session)
        assert len(result.finding_counts) > 0


class TestCheckDecorator:
    def test_custom_check_registration(self):
        initial_count = len(_CHECK_REGISTRY)

        @check(id="TEST-001", severity="info", title="Test", description="Test check")
        def test_check(session):
            return []

        assert len(_CHECK_REGISTRY) == initial_count + 1
        last_check = _CHECK_REGISTRY[-1]
        assert last_check["id"] == "TEST-001"

    def test_check_with_vendor_filter(self):
        @check(id="TEST-002", severity="info", title="Test", description="Test", vendor="fortinet")
        def test_check_fortinet(session):
            return []

        all_checks = get_checks()
        fortinet_checks = get_checks("fortinet")
        paloalto_checks = get_checks("paloalto")

        test_in_all = any(c["id"] == "TEST-002" for c in all_checks)
        test_in_fortinet = any(c["id"] == "TEST-002" for c in fortinet_checks)
        test_in_paloalto = any(c["id"] == "TEST-002" for c in paloalto_checks)

        assert test_in_all is True
        assert test_in_fortinet is True
        assert test_in_paloalto is False


class TestRunWithFailingCheck:
    def test_failing_check_doesnt_crash(self):
        @check(id="TEST-BROKEN", severity="critical", title="Broken", description="Fails")
        def broken_check(session):
            raise ValueError("intentional failure")

        session = Session(vendor="test")
        findings = run_checks(session)
        assert isinstance(findings, list)
