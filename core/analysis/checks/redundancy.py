"""FW-006: Redundant/Duplicate Rule detection."""

from core.models import Finding, Session
from core.analysis.registry import check


def _services_equal(a, b) -> bool:
    if len(a) != len(b):
        return False
    for sa, sb in zip(a, b):
        if sa.protocol != sb.protocol:
            return False
        if set(sa.ports) != set(sb.ports):
            return False
    return True


@check(
    id="FW-006",
    severity="low",
    title="Redundant Rule",
    description="Rule is an exact duplicate of another rule in the policy.",
    category="operational",
    references=[
        "RFC 2196 - Section 3.3.2: Rules should be reviewed for redundancy",
    ],
)
def check_redundancy(session: Session) -> list[Finding]:
    findings = []
    policies = sorted(session.security_policies, key=lambda p: p.position)
    seen_rules: list = []

    for policy in policies:
        fingerprint = (
            tuple(sorted(policy.source.addresses)),
            tuple(sorted(policy.destination.addresses)),
            tuple(sorted(policy.source.zones)),
            tuple(sorted(policy.destination.zones)),
            tuple(sorted(s.protocol for s in policy.services)),
            policy.action,
            policy.enabled,
        )

        for earlier_fp, earlier_policy in seen_rules:
            if fingerprint == earlier_fp:
                findings.append(
                    Finding(
                        description=(
                            f"Rule '{policy.name or policy.id}' at position {policy.position} "
                            f"is an exact duplicate of '{earlier_policy.name or earlier_policy.id}' "
                            f"at position {earlier_policy.position}."
                        ),
                        entity_id=policy.id,
                        entity_type="security_policy",
                        related_entity_ids=[earlier_policy.id],
                    )
                )
                break

        seen_rules.append((fingerprint, policy))

    return findings
