"""Import all checks to register them."""

from core.analysis.checks.any_any import check_any_any_allow
from core.analysis.checks.internet_exposure import check_internet_exposure
from core.analysis.checks.large_cidr import check_large_cidr
from core.analysis.checks.logging import check_logging_disabled
from core.analysis.checks.redundancy import check_redundancy
from core.analysis.checks.shadowing import check_shadowing

__all__ = [
    "check_any_any_allow",
    "check_internet_exposure",
    "check_large_cidr",
    "check_logging_disabled",
    "check_shadowing",
    "check_redundancy",
]
