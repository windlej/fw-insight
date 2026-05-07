"""FW-005: Potentially Shadowed Rule detection."""

from core.models import Finding, Session
from core.analysis.registry import check
from core.ip_utils import contains


def _service_contains(earlier_services, later_services) -> bool:
    """Check if earlier rule's services are a superset of later rule's services."""
    for later_svc in later_services:
        found_match = False
        for earlier_svc in earlier_services:
            if earlier_svc.protocol == "any" or earlier_svc.protocol == later_svc.protocol:
                if not earlier_svc.ports or earlier_svc.ports == ["any"]:
                    found_match = True
                    break
                if not later_svc.ports or later_svc.ports == ["any"]:
                    continue
                for lp in later_svc.ports:
                    if lp not in earlier_svc.ports and earlier_svc.ports != ["any"]:
                        continue
                found_match = True
                break
        if not found_match:
            return False
    return True


def _endpoint_contains(earlier_addrs, later_addrs) -> bool:
    """Check if earlier endpoint addresses contain later endpoint addresses."""
    if "any" in earlier_addrs:
        return True
    for later_addr in later_addrs:
        if not any(contains(ea, later_addr) for ea in earlier_addrs):
            return False
    return True


@check(
    id="FW-005",
    severity="low",
    title="Potentially Shadowed Rule",
    description="Rule may be unreachable because an earlier rule matches a superset of the same traffic.",
    category="operational",
    references=[
        "RFC 2196 - Section 3.3.2: Rule ordering should be reviewed for conflicts",
    ],
)
def check_shadowing(session: Session) -> list[Finding]:
    findings = []
    policies = sorted(session.security_policies, key=lambda p: p.position)

    for i, later in enumerate(policies):
        if not later.enabled:
            continue

        for earlier in policies[:i]:
            if not earlier.enabled:
                continue

            if earlier.action != later.action:
                continue

            source_contains = _endpoint_contains(earlier.source.addresses, later.source.addresses)
            dest_contains = _endpoint_contains(earlier.destination.addresses, later.destination.addresses)
            service_contains_result = _service_contains(earlier.services, later.services)

            if source_contains and dest_contains and service_contains_result:
                findings.append(
                    Finding(
                        description=(
                            f"Rule '{later.name or later.id}' at position {later.position} "
                            f"may be shadowed by '{earlier.name or earlier.id}' at position {earlier.position}, "
                            f"which matches a superset of the same traffic with the same action."
                        ),
                        entity_id=later.id,
                        entity_type="security_policy",
                        related_entity_ids=[earlier.id],
                    )
                )
                break

    return findings
