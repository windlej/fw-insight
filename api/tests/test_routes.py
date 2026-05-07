"""Tests for API routes."""

import sys
from unittest.mock import MagicMock, patch

# Mock weasyprint for environments without native Pango/GObject libs
if "weasyprint" not in sys.modules:
    mock_wp = MagicMock()
    mock_wp.HTML = MagicMock()
    sys.modules["weasyprint"] = mock_wp

import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.storage import init_db, save_session, get_session, list_sessions, delete_session, get_findings


@pytest.fixture
def client():
    init_db()
    return TestClient(app)


@pytest.fixture
def saved_session_id():
    session_data = {
        "vendor": "paloalto",
        "vendor_version": "10.1.0",
        "hostname": "test-fw",
        "parsed_at": "2024-01-01T00:00:00Z",
        "source_checksum": "test-checksum-fixtures",
        "labels": {},
        "metadata": {},
        "security_policies": [
            {"id": "1", "name": "allow-all", "position": 1, "source": {"addresses": ["any"]}, "destination": {"addresses": ["any"]}, "services": [{"protocol": "any"}], "action": "allow"}
        ],
        "nat_rules": [],
        "interfaces": [],
        "zones": [],
        "address_objects": [],
        "service_objects": [],
        "health_score": 80,
        "finding_counts": {"high": 1},
    }
    findings = [
        {"check_id": "FW-001", "severity": "high", "category": "security", "title": "Any-Any", "description": "desc", "entity_id": "1", "entity_type": "security_policy"}
    ]
    sid = save_session(session_data, findings, None, "test-fixture.xml")
    return sid


class TestHealthCheck:
    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


class TestListParsers:
    def test_list_parsers(self, client):
        resp = client.get("/api/v1/parsers")
        assert resp.status_code == 200
        data = resp.json()
        assert "parsers" in data
        parser_names = data["parsers"]
        assert "paloalto" in parser_names
        assert "fortinet" in parser_names


class TestUploadSession:
    def test_upload_paloalto(self, client):
        xml_content = b"""<?xml version="1.0"?>
<config version="10.1.0" urldb="paloaltonetworks">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig>
        <system>
          <hostname>pa-test</hostname>
        </system>
      </deviceconfig>
      <vsys>
        <entry name="vsys1">
          <address>
            <entry name="any"/>
          </address>
          <rulebase>
            <security>
              <rules>
                <entry name="allow-all">
                  <from>
                    <member>any</member>
                  </from>
                  <to>
                    <member>any</member>
                  </to>
                  <source>
                    <member>any</member>
                  </source>
                  <destination>
                    <member>any</member>
                  </destination>
                  <service>
                    <member>application-default</member>
                  </service>
                  <action>allow</action>
                </entry>
              </rules>
            </security>
            <nat>
              <rules/>
            </nat>
          </rulebase>
        </entry>
      </vsys>
    </entry>
  </devices>
</config>"""
        resp = client.post(
            "/api/v1/sessions",
            files={"file": ("config.xml", xml_content, "application/xml")},
            data={"vendor": "paloalto"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["vendor"] == "paloalto"
        assert data["rule_count"] >= 0

    def test_upload_auto_detect(self, client):
        config = b"config system global\n    set hostname fgt-test\nend\n"
        resp = client.post(
            "/api/v1/sessions",
            files={"file": ("fortigate.conf", config, "text/plain")},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["vendor"] == "fortinet"

    def test_upload_unknown_vendor(self, client):
        resp = client.post(
            "/api/v1/sessions",
            files={"file": ("unknown.txt", b"not a firewall config", "text/plain")},
        )
        assert resp.status_code == 400


class TestSessionsRoutes:
    def test_list_sessions(self, client, saved_session_id):
        resp = client.get("/api/v1/sessions")
        assert resp.status_code == 200
        data = resp.json()
        assert "sessions" in data
        ids = [s["id"] for s in data["sessions"]]
        assert saved_session_id in ids

    def test_get_session(self, client, saved_session_id):
        resp = client.get(f"/api/v1/sessions/{saved_session_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == saved_session_id
        assert data["vendor"] == "paloalto"

    def test_get_session_not_found(self, client):
        resp = client.get("/api/v1/sessions/nonexistent")
        assert resp.status_code == 404

    def test_delete_session(self, client, saved_session_id):
        resp = client.delete(f"/api/v1/sessions/{saved_session_id}")
        assert resp.status_code == 200

        resp = client.get(f"/api/v1/sessions/{saved_session_id}")
        assert resp.status_code == 404


class TestFindingsRoutes:
    def test_get_findings(self, client, saved_session_id):
        resp = client.get(f"/api/v1/sessions/{saved_session_id}/analysis")
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert len(data["findings"]) >= 1


class TestAnalysisRoutes:
    def test_reanalyze(self, client, saved_session_id):
        resp = client.get(f"/api/v1/sessions/{saved_session_id}/analysis")
        assert resp.status_code == 200
        data = resp.json()
        assert "findings" in data
        assert "health_score" in data


class TestDiffRoutes:
    def test_diff_sessions(self, client):
        a_data = {
            "vendor": "paloalto",
            "parsed_at": "2024-01-01T00:00:00Z",
            "security_policies": [
                {"id": "1", "name": "rule-a", "position": 1, "source": {"addresses": ["any"]}, "destination": {"addresses": ["10.0.0.1"]}, "services": [{"protocol": "any"}], "action": "allow"}
            ],
            "address_objects": [],
            "nat_rules": [],
            "interfaces": [],
            "zones": [],
            "service_objects": [],
        }
        b_data = {
            "vendor": "paloalto",
            "parsed_at": "2024-01-01T00:00:00Z",
            "security_policies": [
                {"id": "1", "name": "rule-a", "position": 1, "source": {"addresses": ["any"]}, "destination": {"addresses": ["10.0.0.2"]}, "services": [{"protocol": "any"}], "action": "deny"}
            ],
            "address_objects": [],
            "nat_rules": [],
            "interfaces": [],
            "zones": [],
            "service_objects": [],
        }
        sid_a = save_session(a_data, [], None, "a.xml")
        sid_b = save_session(b_data, [], None, "b.xml")

        resp = client.post("/api/v1/diff", json={"session_a_id": sid_a, "session_b_id": sid_b})
        assert resp.status_code == 200
        data = resp.json()
        assert "added_rules" in data
        assert "removed_rules" in data
        assert "modified_rules" in data
