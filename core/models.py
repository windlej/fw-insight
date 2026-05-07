"""Canonical data models for fw-insight.

All models use permissive schema (extra='allow') so unknown fields pass through
with a warning logged rather than causing validation failure.
"""

import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

logger = logging.getLogger(__name__)


class PermissiveModel(BaseModel):
    """Base model that allows extra fields with a warning."""

    model_config = ConfigDict(extra="allow")

    def model_post_init(self, __context: Any) -> None:
        extra = self.model_extra
        if extra:
            logger.debug(
                "Extra fields on %s: %s",
                self.__class__.__name__,
                list(extra.keys()),
            )


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    SECURITY = "security"
    OPERATIONAL = "operational"
    COMPLIANCE = "compliance"


class ServiceRef(PermissiveModel):
    """Canonical service reference."""

    protocol: str = "any"
    ports: list[str] = Field(default_factory=list)


class RuleEndpoint(PermissiveModel):
    """Source or destination endpoint for a rule."""

    addresses: list[str] = Field(default_factory=list)
    zones: list[str] = Field(default_factory=list)
    users: list[str] | None = None


class SecurityPolicy(PermissiveModel):
    """Canonical firewall security policy rule."""

    id: str
    name: str | None = None
    position: int
    source: RuleEndpoint = Field(default_factory=RuleEndpoint)
    destination: RuleEndpoint = Field(default_factory=RuleEndpoint)
    services: list[ServiceRef] = Field(default_factory=lambda: [ServiceRef()])
    action: str = "allow"
    enabled: bool = True
    logging: dict[str, bool] = Field(default_factory=lambda: {"log_start": False, "log_end": False})
    schedule: str | None = None
    description: str | None = None
    vendor_raw: dict[str, Any] = Field(default_factory=dict)


class NATRule(PermissiveModel):
    """Canonical NAT rule."""

    id: str
    name: str | None = None
    position: int
    type: str = "source_nat"
    original_source: str | None = None
    translated_source: str | None = None
    original_destination: str | None = None
    translated_destination: str | None = None
    original_service: ServiceRef | None = None
    translated_service: ServiceRef | None = None
    enabled: bool = True
    vendor_raw: dict[str, Any] = Field(default_factory=dict)


class Interface(PermissiveModel):
    """Canonical network interface."""

    name: str
    type: str = "physical"
    enabled: bool = True
    ip_addresses: list[str] = Field(default_factory=list)
    zone: str | None = None
    description: str | None = None
    vendor_raw: dict[str, Any] = Field(default_factory=dict)


class Zone(PermissiveModel):
    """Canonical security zone."""

    name: str
    type: str | None = None
    interfaces: list[str] = Field(default_factory=list)
    vendor_raw: dict[str, Any] = Field(default_factory=dict)


class AddressObject(PermissiveModel):
    """Canonical address object."""

    name: str
    type: str = "ip_netmask"
    value: str
    members: list[str] | None = None
    description: str | None = None
    vendor_raw: dict[str, Any] = Field(default_factory=dict)


class ServiceObject(PermissiveModel):
    """Canonical service object."""

    name: str
    protocol: str = "tcp"
    ports: list[str] = Field(default_factory=list)
    description: str | None = None
    vendor_raw: dict[str, Any] = Field(default_factory=dict)


class Session(PermissiveModel):
    """Top-level canonical session representing a parsed firewall config."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    vendor: str
    vendor_version: str | None = None
    hostname: str | None = None
    parsed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    source_filename: str | None = None
    source_checksum: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    labels: dict[str, str] = Field(default_factory=dict)
    security_policies: list[SecurityPolicy] = Field(default_factory=list)
    nat_rules: list[NATRule] = Field(default_factory=list)
    interfaces: list[Interface] = Field(default_factory=list)
    zones: list[Zone] = Field(default_factory=list)
    address_objects: list[AddressObject] = Field(default_factory=list)
    service_objects: list[ServiceObject] = Field(default_factory=list)

    @property
    def rule_count(self) -> int:
        return len(self.security_policies)


class Finding(PermissiveModel):
    """A single analysis finding."""

    check_id: str = ""
    severity: Severity = Severity.INFO
    category: Category = Category.SECURITY
    title: str = ""
    description: str
    entity_id: str
    entity_type: str
    references: list[str] = Field(default_factory=list)
    related_entity_ids: list[str] = Field(default_factory=list)


class AnalysisResult(PermissiveModel):
    """Result of running analysis against a session."""

    session_id: str
    findings: list[Finding] = Field(default_factory=list)
    health_score: int = 100
    finding_counts: dict[str, int] = Field(default_factory=dict)

    def calculate_health_score(self) -> int:
        from core.constants import SEVERITY_WEIGHTS

        total_weight = sum(
            SEVERITY_WEIGHTS.get(f.severity.value, 0) for f in self.findings
        )
        max_possible = max(self.rule_count_for_scoring(), 1) * 10
        raw_score = min(total_weight / max_possible * 100, 100)
        self.health_score = max(0, int(100 - raw_score))
        return self.health_score

    def rule_count_for_scoring(self) -> int:
        return len(set(f.entity_id for f in self.findings if f.entity_type == "security_policy"))

    def compute_finding_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            key = f.severity.value
            counts[key] = counts.get(key, 0) + 1
        self.finding_counts = counts
        return counts


class FieldChange(PermissiveModel):
    """A single field change in a diff."""

    field: str
    old_value: Any
    new_value: Any


class ModifiedRule(PermissiveModel):
    """A rule that exists in both sessions but has changes."""

    rule_id: str
    rule_name: str | None = None
    changes: list[FieldChange] = Field(default_factory=list)


class ConfigDiff(PermissiveModel):
    """Diff between two sessions."""

    session_a_id: str
    session_b_id: str
    vendor_match: bool
    added_rules: list[SecurityPolicy] = Field(default_factory=list)
    removed_rules: list[SecurityPolicy] = Field(default_factory=list)
    modified_rules: list[ModifiedRule] = Field(default_factory=list)
    added_objects: list[AddressObject] = Field(default_factory=list)
    removed_objects: list[AddressObject] = Field(default_factory=list)
    modified_objects: list[ModifiedRule] = Field(default_factory=list)
