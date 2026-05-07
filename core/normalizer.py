"""Normalize vendor-specific AST to canonical Session model."""

import hashlib
import logging
from typing import Any

from core.constants import MAX_RULES
from core.models import Session

logger = logging.getLogger(__name__)


def normalize(
    vendor_id: str,
    ast: dict[str, Any],
    source_filename: str | None = None,
    source_content: bytes | None = None,
) -> Session:
    """Normalize a vendor AST to a canonical Session.

    This is a generic normalizer that expects the vendor parser to have
    already produced a structured dict with known keys. Vendor-specific
    normalizers should call this with their mapped data.

    Args:
        vendor_id: Vendor identifier (e.g., "paloalto")
        ast: Vendor-specific AST dict with keys matching Session fields
        source_filename: Original filename
        source_content: Raw config bytes for checksum

    Returns:
        Validated Session model

    Raises:
        ValueError: If rule count exceeds MAX_RULES
    """
    data = dict(ast)
    data["vendor"] = vendor_id

    if source_filename:
        data["source_filename"] = source_filename

    if source_content:
        data["source_checksum"] = hashlib.sha256(source_content).hexdigest()

    policy_count = len(data.get("security_policies", []))
    if policy_count > MAX_RULES:
        raise ValueError(
            f"Config contains {policy_count} security policies, "
            f"exceeds limit of {MAX_RULES}. Set MAX_RULES env var to override."
        )

    session = Session.model_validate(data)
    logger.info(
        "Normalized %s config: %d policies, %d NAT rules, %d objects",
        vendor_id,
        len(session.security_policies),
        len(session.nat_rules),
        len(session.address_objects) + len(session.service_objects),
    )
    return session
