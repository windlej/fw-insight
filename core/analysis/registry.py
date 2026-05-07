"""Check registry and decorator."""

import functools
import logging
from typing import Any, Callable

from core.models import Finding, Session
from core.analysis.findings import Category, Severity

logger = logging.getLogger(__name__)

_CHECK_REGISTRY: list[dict[str, Any]] = []


def check(
    id: str,
    severity: str,
    title: str,
    description: str,
    category: str = "security",
    references: list[str] | None = None,
    vendor: str | None = None,
):
    """Decorator to register an analysis check.

    Args:
        id: Unique check identifier (e.g., "FW-001")
        severity: critical, high, medium, low, info
        title: Short human-readable title
        description: Detailed description used in findings
        category: security, operational, or compliance
        references: List of RFC/best-practice references
        vendor: If set, only runs for this vendor. None = all vendors.
    """
    def decorator(func: Callable) -> Callable:
        _CHECK_REGISTRY.append({
            "id": id,
            "severity": severity,
            "title": title,
            "description": description,
            "category": category,
            "references": references or [],
            "vendor": vendor,
            "func": func,
        })

        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        return wrapper
    return decorator


def get_checks(vendor: str | None = None) -> list[dict[str, Any]]:
    """Get registered checks, optionally filtered by vendor."""
    if vendor is None:
        return list(_CHECK_REGISTRY)
    return [
        c for c in _CHECK_REGISTRY
        if c["vendor"] is None or c["vendor"] == vendor
    ]


def run_checks(session: Session) -> list[Finding]:
    """Execute all applicable checks against a session.

    Returns:
        List of Finding objects
    """
    checks = get_checks(session.vendor)
    findings: list[Finding] = []

    for check_meta in checks:
        try:
            check_findings = check_meta["func"](session)
            for f in check_findings:
                f.check_id = check_meta["id"]
                f.severity = Severity(check_meta["severity"])
                f.category = Category(check_meta["category"])
                f.title = check_meta["title"]
                if not f.references:
                    f.references = check_meta["references"]
            findings.extend(check_findings)
            logger.debug("Check %s produced %d findings", check_meta["id"], len(check_findings))
        except Exception:
            logger.exception("Check %s failed", check_meta["id"])

    return findings
