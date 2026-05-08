"""FW-001: Any-Any Allow Rule detection."""

from core.analysis.registry import check
from core.models import Finding, SecurityPolicy, Session


def _is_any_any(policy: SecurityPolicy) -> bool:
    if policy.action != "allow" or not policy.enabled:
        return False

    source_any = "any" in policy.source.addresses
    dest_any = "any" in policy.destination.addresses

    if not source_any or not dest_any:
        return False

    service_any = any(s.protocol == "any" for s in policy.services)
    return service_any


@check(
    id="FW-001",
    severity="high",
    title="Any-Any Allow Rule",
    description="Rule permits traffic from any source to any destination on all protocols and ports.",
    category="security",
    references=[
        "RFC 2196 - Section 3.3.1: Access control policies should be specific",
        "CIS Controls v8 - Control 4.2: Establish secure configuration of network infrastructure",
        "NIST SP 800-41 Rev. 1 - Section 3.3: Firewall rules should follow least privilege",
    ],
)
def check_any_any_allow(session: Session) -> list[Finding]:
    findings = []
    for policy in session.security_policies:
        if _is_any_any(policy):
            findings.append(
                Finding(
                    description=(
                        f"Rule '{policy.name or policy.id}' at position {policy.position} "
                        f"permits traffic from any source to any destination on all protocols and ports."
                    ),
                    entity_id=policy.id,
                    entity_type="security_policy",
                )
            )
    return findings
