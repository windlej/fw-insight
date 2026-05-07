"""FW-004: Logging Disabled on Allow Rules."""

from core.models import Finding, Session
from core.analysis.registry import check


@check(
    id="FW-004",
    severity="medium",
    title="Logging Disabled on Allow Rule",
    description="Allow rule does not have session-end logging enabled, which may impact incident response capability.",
    category="operational",
    references=[
        "NIST SP 800-92 - Section 3.2: Log all allowed and denied connections",
        "CIS Controls v8 - Control 8.2: Collect audit logs",
    ],
)
def check_logging_disabled(session: Session) -> list[Finding]:
    findings = []
    for policy in session.security_policies:
        if policy.action != "allow" or not policy.enabled:
            continue

        log_config = policy.logging
        log_end = log_config.get("log_end", False) if log_config else False

        if not log_end:
            findings.append(
                Finding(
                    description=(
                        f"Rule '{policy.name or policy.id}' at position {policy.position} "
                        f"does not have session-end logging enabled."
                    ),
                    entity_id=policy.id,
                    entity_type="security_policy",
                )
            )

    return findings
