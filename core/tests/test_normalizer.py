"""Tests for core.normalizer."""

import pytest

from core.normalizer import normalize
from core.models import Session


class TestNormalize:
    def test_basic_normalization(self):
        ast = {
            "hostname": "fw-01",
            "vendor_version": "10.1.0",
            "security_policies": [
                {
                    "id": "1",
                    "name": "allow-all",
                    "position": 1,
                    "source": {"addresses": ["any"]},
                    "destination": {"addresses": ["any"]},
                    "services": [{"protocol": "any"}],
                    "action": "allow",
                }
            ],
            "address_objects": [
                {"name": "srv-web", "type": "ip_netmask", "value": "10.0.0.1/32"},
            ],
        }
        result = normalize("paloalto", ast)
        assert isinstance(result, Session)
        assert result.vendor == "paloalto"
        assert result.hostname == "fw-01"
        assert len(result.security_policies) == 1
        assert len(result.address_objects) == 1

    def test_empty_ast(self):
        result = normalize("test", {})
        assert result.vendor == "test"
        assert result.security_policies == []
        assert result.address_objects == []

    def test_source_filename(self):
        result = normalize("test", {}, source_filename="config.xml")
        assert result.source_filename == "config.xml"

    def test_source_checksum(self):
        content = b"test config content"
        result = normalize("test", {}, source_content=content)
        import hashlib
        expected = hashlib.sha256(content).hexdigest()
        assert result.source_checksum == expected

    def test_max_rules_exceeded(self):
        from core.constants import MAX_RULES
        policies = [
            {"id": str(i), "name": f"rule-{i}", "position": i, "source": {}, "destination": {}, "services": [], "action": "allow"}
            for i in range(MAX_RULES + 1)
        ]
        ast = {"security_policies": policies}
        with pytest.raises(ValueError, match="exceeds limit"):
            normalize("test", ast)
