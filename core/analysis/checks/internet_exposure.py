"""FW-002: Internet-Exposed Service detection."""

from core.models import Finding, Session
from core.analysis.registry import check
from core.ip_utils import is_private


@check(
    id="FW-002",
    severity="high",
    title="Internet-Exposed Service",
    description="Rule permits inbound traffic from any source (0.0.0.0/0) to an internal destination.",
    category="security",
    references=[
        "CIS Controls v8 - Control 4.4: Implement and manage a firewall on servers",
        "NIST SP 800-41 Rev. 1 - Section 3.4: Inbound traffic should be restricted",
    ],
)
def check_internet_exposure(session: Session) -> list[Finding]:
    findings = []
    for policy in session.security_policies:
        if policy.action != "allow" or not policy.enabled:
            continue

        source_is_any = "any" in policy.source.addresses or "0.0.0.0/0" in policy.source.addresses
        if not source_is_any:
            continue

        for addr in policy.destination.addresses:
            if addr == "any":
                continue
            if is_private(addr):
                services = ", ".join(
                    f"{s.protocol}/{','.join(s.ports) if s.ports else 'any'}"
                    for s in policy.services
                )
                findings.append(
                    Finding(
                        description=(
                            f"Rule '{policy.name or policy.id}' at position {policy.position} "
                            f"permits inbound traffic from any source to internal address {addr} "
                            f"on service(s): {services}."
                        ),
                        entity_id=policy.id,
                        entity_type="security_policy",
                    )
                )
                break

    return findings
