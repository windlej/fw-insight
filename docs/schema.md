# Canonical Data Schema

## Session

Top-level object representing a parsed firewall configuration.

```json
{
  "id": "uuid",
  "vendor": "paloalto",
  "vendor_version": "11.0.1",
  "hostname": "pa-fw-01",
  "parsed_at": "2025-01-15T10:30:00Z",
  "source_filename": "config.xml",
  "source_checksum": "sha256...",
  "labels": {},
  "metadata": {},
  "security_policies": [...],
  "nat_rules": [...],
  "interfaces": [...],
  "zones": [...],
  "address_objects": [...],
  "service_objects": [...]
}
```

## SecurityPolicy

```json
{
  "id": "rule-name",
  "name": "Allow-Web",
  "position": 1,
  "source": { "addresses": ["10.0.0.0/8"], "zones": ["trust"], "users": null },
  "destination": { "addresses": ["any"], "zones": ["untrust"] },
  "services": [{ "protocol": "tcp", "ports": ["80", "443"] }],
  "action": "allow",
  "enabled": true,
  "logging": { "log_start": false, "log_end": true },
  "schedule": null,
  "description": "Allow web traffic",
  "vendor_raw": {}
}
```

## Finding

```json
{
  "check_id": "FW-001",
  "severity": "high",
  "category": "security",
  "title": "Any-Any Allow Rule",
  "description": "Rule 'Allow-All' permits traffic from any source to any destination...",
  "entity_id": "rule-name",
  "entity_type": "security_policy",
  "references": ["RFC 2196 - Section 3.3.1"],
  "related_entity_ids": []
}
```

## Extension Mechanism

Every entity has a `vendor_raw` field that stores the complete vendor-specific representation. This is opaque to the core engine but available to vendor-specific analysis plugins. This ensures zero data loss during normalization.

## Permissive Schema

All models use `extra='allow'` so unknown fields pass through with a warning logged. This allows the tool to handle evolving vendor configs without breaking on new fields.
