"""FW-003: Large CIDR Allowance detection."""

from core.models import Finding, Session
from core.analysis.registry import check
from core.ip_utils import address_count


@check(
    id="FW-003",
    severity="medium",
    title="Large CIDR Allowance",
    description="Rule includes a large address range (prefix length <= 8) in source or destination.",
    category="security",
    references=[
        "RFC 2196 - Section 3.3.1: Access control policies should use specific address ranges",
        "CIS Controls v8 - Control 4.5: Implement access control for network devices",
    ],
)
def check_large_cidr(session: Session) -> list[Finding]:
    findings = []
    for policy in session.security_policies:
        if not policy.enabled:
            continue

        large_addrs = []
        for addr in policy.source.addresses + policy.destination.addresses:
            if addr == "any":
                continue
            count = address_count(addr)
            if count >= 16777216:
                large_addrs.append(addr)

        if large_addrs:
            findings.append(
                Finding(
                    description=(
                        f"Rule '{policy.name or policy.id}' at position {policy.position} "
                        f"includes large address range(s): {', '.join(large_addrs)}. "
                        f"Each range covers 16,777,216 or more hosts."
                    ),
                    entity_id=policy.id,
                    entity_type="security_policy",
                )
            )

    return findings
