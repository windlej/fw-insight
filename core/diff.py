"""Configuration diff engine for comparing sessions."""

from core.models import ConfigDiff, FieldChange, ModifiedRule, Session


def diff_sessions(session_a: Session, session_b: Session) -> ConfigDiff:
    """Compare two sessions and produce a ConfigDiff.

    Matching is done by rule ID first, then by name as fallback.
    """
    diff = ConfigDiff(
        session_a_id=session_a.id,
        session_b_id=session_b.id,
        vendor_match=(session_a.vendor == session_b.vendor),
    )

    a_rules = {r.id: r for r in session_a.security_policies}
    b_rules = {r.id: r for r in session_b.security_policies}

    a_names = {r.name: r for r in session_a.security_policies if r.name}
    b_names = {r.name: r for r in session_b.security_policies if r.name}

    matched_ids: set[str] = set()
    matched_names: set[str] = set()

    for rule_id, rule_a in a_rules.items():
        if rule_id in b_rules:
            matched_ids.add(rule_id)
            changes = _compare_rules(rule_a, b_rules[rule_id])
            if changes:
                diff.modified_rules.append(
                    ModifiedRule(
                        rule_id=rule_id,
                        rule_name=rule_a.name,
                        changes=changes,
                    )
                )
        elif rule_a.name and rule_a.name in b_names:
            matched_names.add(rule_a.name)
            changes = _compare_rules(rule_a, b_names[rule_a.name])
            if changes:
                diff.modified_rules.append(
                    ModifiedRule(
                        rule_id=rule_a.name,
                        rule_name=rule_a.name,
                        changes=changes,
                    )
                )

    for rule_id, rule_a in a_rules.items():
        if rule_id not in matched_ids and rule_id not in b_rules:
            if rule_a.name and rule_a.name in matched_names:
                continue
            diff.removed_rules.append(rule_a)

    for rule_id, rule_b in b_rules.items():
        if rule_id not in matched_ids and rule_id not in a_rules:
            if rule_b.name and rule_b.name in matched_names:
                continue
            diff.added_rules.append(rule_b)

    a_objs = {o.name: o for o in session_a.address_objects}
    b_objs = {o.name: o for o in session_b.address_objects}

    for name, obj_a in a_objs.items():
        if name not in b_objs:
            diff.removed_objects.append(obj_a)
        elif obj_a.value != b_objs[name].value:
            diff.modified_objects.append(
                ModifiedRule(
                    rule_id=name,
                    changes=[
                        FieldChange(field="value", old_value=obj_a.value, new_value=b_objs[name].value)
                    ],
                )
            )

    for name, obj_b in b_objs.items():
        if name not in a_objs:
            diff.added_objects.append(obj_b)

    return diff


def _compare_rules(a, b) -> list[FieldChange]:
    """Compare two rules and return list of field changes."""
    changes = []

    for field in ("name", "action", "enabled", "description", "schedule"):
        av = getattr(a, field, None)
        bv = getattr(b, field, None)
        if av != bv:
            changes.append(FieldChange(field=field, old_value=av, new_value=bv))

    if a.source.model_dump() != b.source.model_dump():
        changes.append(FieldChange(field="source", old_value=a.source, new_value=b.source))

    if a.destination.model_dump() != b.destination.model_dump():
        changes.append(FieldChange(field="destination", old_value=a.destination, new_value=b.destination))

    if a.services != b.services:
        changes.append(
            FieldChange(
                field="services",
                old_value=[s.model_dump() for s in a.services],
                new_value=[s.model_dump() for s in b.services],
            )
        )

    return changes
