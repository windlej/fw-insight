"""Tests for core.analysis checks."""


from core.analysis.registry import run_checks
from core.models import (
    RuleEndpoint,
    SecurityPolicy,
    ServiceRef,
    Session,
)


def _make_session(policies):
    return Session(vendor="test", security_policies=policies)


def _make_policy(
    id="1",
    position=1,
    src_addrs=None,
    dst_addrs=None,
    services=None,
    action="allow",
    enabled=True,
    log_end=False,
    log_start=False,
):
    return SecurityPolicy(
        id=id,
        name=f"policy-{id}",
        position=position,
        source=RuleEndpoint(addresses=src_addrs or []),
        destination=RuleEndpoint(addresses=dst_addrs or []),
        services=services or [ServiceRef(protocol="any")],
        action=action,
        enabled=enabled,
        logging={"log_start": log_start, "log_end": log_end},
    )


class TestAnyAnyAllow:
    def test_detects_any_any(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["any"], services=[ServiceRef(protocol="any")])
        findings = run_checks(_make_session([p]))
        fw001 = [f for f in findings if f.check_id == "FW-001"]
        assert len(fw001) == 1
        assert fw001[0].entity_id == "1"

    def test_ignores_deny(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["any"], action="deny")
        findings = run_checks(_make_session([p]))
        fw001 = [f for f in findings if f.check_id == "FW-001"]
        assert len(fw001) == 0

    def test_ignores_disabled(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["any"], enabled=False)
        findings = run_checks(_make_session([p]))
        fw001 = [f for f in findings if f.check_id == "FW-001"]
        assert len(fw001) == 0

    def test_ignores_specific_source(self):
        p = _make_policy(src_addrs=["10.0.0.0/8"], dst_addrs=["any"])
        findings = run_checks(_make_session([p]))
        fw001 = [f for f in findings if f.check_id == "FW-001"]
        assert len(fw001) == 0

    def test_ignores_specific_destination(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["10.0.0.1/32"])
        findings = run_checks(_make_session([p]))
        fw001 = [f for f in findings if f.check_id == "FW-001"]
        assert len(fw001) == 0

    def test_ignores_specific_service(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["any"], services=[ServiceRef(protocol="tcp", ports=["80"])])
        findings = run_checks(_make_session([p]))
        fw001 = [f for f in findings if f.check_id == "FW-001"]
        assert len(fw001) == 0


class TestLoggingDisabled:
    def test_finds_allow_without_log_end(self):
        p = _make_policy(log_end=False)
        findings = run_checks(_make_session([p]))
        fw004 = [f for f in findings if f.check_id == "FW-004"]
        assert len(fw004) == 1

    def test_ignores_with_log_end(self):
        p = _make_policy(log_end=True)
        findings = run_checks(_make_session([p]))
        fw004 = [f for f in findings if f.check_id == "FW-004"]
        assert len(fw004) == 0

    def test_ignores_deny(self):
        p = _make_policy(action="deny", log_end=False)
        findings = run_checks(_make_session([p]))
        fw004 = [f for f in findings if f.check_id == "FW-004"]
        assert len(fw004) == 0

    def test_ignores_disabled(self):
        p = _make_policy(enabled=False, log_end=False)
        findings = run_checks(_make_session([p]))
        fw004 = [f for f in findings if f.check_id == "FW-004"]
        assert len(fw004) == 0


class TestLargeCidr:
    def test_detects_large_cidr(self):
        p = _make_policy(src_addrs=["10.0.0.0/8"], dst_addrs=["10.0.0.1/32"])
        findings = run_checks(_make_session([p]))
        fw003 = [f for f in findings if f.check_id == "FW-003"]
        assert len(fw003) == 1

    def test_ignores_small_cidr(self):
        p = _make_policy(src_addrs=["10.0.0.0/24"], dst_addrs=["10.0.0.1/32"])
        findings = run_checks(_make_session([p]))
        fw003 = [f for f in findings if f.check_id == "FW-003"]
        assert len(fw003) == 0

    def test_ignores_any(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["10.0.0.1/32"])
        findings = run_checks(_make_session([p]))
        fw003 = [f for f in findings if f.check_id == "FW-003"]
        assert len(fw003) == 0

    def test_ignores_disabled(self):
        p = _make_policy(src_addrs=["10.0.0.0/8"], enabled=False)
        findings = run_checks(_make_session([p]))
        fw003 = [f for f in findings if f.check_id == "FW-003"]
        assert len(fw003) == 0

    def test_large_cidr_in_destination(self):
        p = _make_policy(src_addrs=["10.0.0.1/32"], dst_addrs=["10.0.0.0/8"])
        findings = run_checks(_make_session([p]))
        fw003 = [f for f in findings if f.check_id == "FW-003"]
        assert len(fw003) == 1


class TestInternetExposure:
    def test_detects_exposure(self):
        p = _make_policy(
            src_addrs=["any"],
            dst_addrs=["10.0.0.1/32"],
            services=[ServiceRef(protocol="tcp", ports=["80"])],
        )
        findings = run_checks(_make_session([p]))
        fw002 = [f for f in findings if f.check_id == "FW-002"]
        assert len(fw002) == 1

    def test_ignores_public_destination(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["1.1.1.1"])
        findings = run_checks(_make_session([p]))
        fw002 = [f for f in findings if f.check_id == "FW-002"]
        assert len(fw002) == 0

    def test_ignores_any_destination(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["any"])
        findings = run_checks(_make_session([p]))
        fw002 = [f for f in findings if f.check_id == "FW-002"]
        assert len(fw002) == 0

    def test_ignores_specific_source(self):
        p = _make_policy(src_addrs=["192.168.1.0/24"], dst_addrs=["10.0.0.1/32"])
        findings = run_checks(_make_session([p]))
        fw002 = [f for f in findings if f.check_id == "FW-002"]
        assert len(fw002) == 0

    def test_ignores_deny(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["10.0.0.1/32"], action="deny")
        findings = run_checks(_make_session([p]))
        fw002 = [f for f in findings if f.check_id == "FW-002"]
        assert len(fw002) == 0

    def test_ignores_disabled(self):
        p = _make_policy(src_addrs=["any"], dst_addrs=["10.0.0.1/32"], enabled=False)
        findings = run_checks(_make_session([p]))
        fw002 = [f for f in findings if f.check_id == "FW-002"]
        assert len(fw002) == 0

    def test_detects_0_0_0_0_source(self):
        p = _make_policy(src_addrs=["0.0.0.0/0"], dst_addrs=["192.168.1.1"])
        findings = run_checks(_make_session([p]))
        fw002 = [f for f in findings if f.check_id == "FW-002"]
        assert len(fw002) == 1


class TestRedundancy:
    def test_detects_duplicate(self):
        p1 = _make_policy(id="1", position=1, src_addrs=["10.0.0.0/8"], dst_addrs=["any"])
        p2 = _make_policy(id="2", position=2, src_addrs=["10.0.0.0/8"], dst_addrs=["any"])
        findings = run_checks(_make_session([p1, p2]))
        fw006 = [f for f in findings if f.check_id == "FW-006"]
        assert len(fw006) == 1
        assert fw006[0].entity_id == "2"

    def test_no_duplicate(self):
        p1 = _make_policy(id="1", position=1, src_addrs=["10.0.0.0/8"], dst_addrs=["any"])
        p2 = _make_policy(id="2", position=2, src_addrs=["192.168.0.0/16"], dst_addrs=["any"])
        findings = run_checks(_make_session([p1, p2]))
        fw006 = [f for f in findings if f.check_id == "FW-006"]
        assert len(fw006) == 0


class TestShadowing:
    def test_detects_shadowed(self):
        p1 = _make_policy(id="1", position=1, src_addrs=["any"], dst_addrs=["any"])
        p2 = _make_policy(id="2", position=2, src_addrs=["10.0.0.0/8"], dst_addrs=["10.0.0.1/32"])
        findings = run_checks(_make_session([p1, p2]))
        fw005 = [f for f in findings if f.check_id == "FW-005"]
        assert len(fw005) == 1
        assert fw005[0].entity_id == "2"
        assert fw005[0].related_entity_ids == ["1"]

    def test_no_shadow_different_action(self):
        p1 = _make_policy(id="1", position=1, src_addrs=["any"], dst_addrs=["any"], action="deny")
        p2 = _make_policy(id="2", position=2, src_addrs=["10.0.0.0/8"], dst_addrs=["10.0.0.1/32"], action="allow")
        findings = run_checks(_make_session([p1, p2]))
        fw005 = [f for f in findings if f.check_id == "FW-005"]
        assert len(fw005) == 0

    def test_no_shadow_disabled(self):
        p1 = _make_policy(id="1", position=1, src_addrs=["any"], dst_addrs=["any"], enabled=False)
        p2 = _make_policy(id="2", position=2, src_addrs=["10.0.0.0/8"], dst_addrs=["10.0.0.1/32"])
        findings = run_checks(_make_session([p1, p2]))
        fw005 = [f for f in findings if f.check_id == "FW-005"]
        assert len(fw005) == 0

    def test_no_shadow_non_overlapping(self):
        p1 = _make_policy(id="1", position=1, src_addrs=["10.0.0.0/8"], dst_addrs=["any"])
        p2 = _make_policy(id="2", position=2, src_addrs=["192.168.0.0/16"], dst_addrs=["any"])
        findings = run_checks(_make_session([p1, p2]))
        fw005 = [f for f in findings if f.check_id == "FW-005"]
        assert len(fw005) == 0
