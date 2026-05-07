# Adding an Analysis Check

## Steps

1. **Create check file**

   `core/analysis/checks/<name>.py`:
   ```python
   from core.models import Finding, Session
   from core.analysis.registry import check

   @check(
       id="FW-XXX",
       severity="high",
       title="Short Title",
       description="Neutral factual description of the finding.",
       category="security",
       references=[
           "RFC XXXX - Section X.X: Description",
       ],
   )
   def check_name(session: Session) -> list[Finding]:
       findings = []
       for policy in session.security_policies:
           # Your logic here
           if condition_met:
               findings.append(Finding(
                   description=f"Rule '{policy.name or policy.id}' ...",
                   entity_id=policy.id,
                   entity_type="security_policy",
               ))
       return findings
   ```

2. **Register the check**

   Add to `core/analysis/checks/__init__.py`:
   ```python
   from core.analysis.checks.<name> import check_name
   ```

3. **Add tests**

   Test that the check triggers when it should and doesn't trigger when it shouldn't.

## Severity Guidelines

- **critical**: Immediate security risk (any-any allow)
- **high**: Significant risk (internet-exposed services)
- **medium**: Operational concern (missing logging, large CIDRs)
- **low**: Housekeeping (shadowed rules, redundancy)
- **info**: Informational

## Language Guidelines

Use neutral, factual language:
- "Rule X permits traffic from any source to any destination"
- NOT "CRITICAL: Remove this dangerous rule immediately"
