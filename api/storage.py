"""SQLite storage layer for sessions, findings, and configs."""

import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session as DBSession

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get("STORAGE_PATH", "data/fw-insight.db")

Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)

engine = create_engine(f"sqlite:///{DB_PATH}", echo=False)


def init_db():
    """Create tables if they don't exist."""
    with engine.begin() as conn:
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                vendor TEXT NOT NULL,
                vendor_version TEXT,
                hostname TEXT,
                parsed_at TEXT,
                source_filename TEXT,
                source_checksum TEXT UNIQUE,
                labels TEXT DEFAULT '{}',
                metadata TEXT DEFAULT '{}',
                security_policies TEXT DEFAULT '[]',
                nat_rules TEXT DEFAULT '[]',
                interfaces TEXT DEFAULT '[]',
                zones TEXT DEFAULT '[]',
                address_objects TEXT DEFAULT '[]',
                service_objects TEXT DEFAULT '[]',
                health_score INTEGER DEFAULT 100,
                finding_counts TEXT DEFAULT '{}',
                created_at TEXT DEFAULT (datetime('now'))
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL REFERENCES sessions(id),
                check_id TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                entity_id TEXT NOT NULL,
                entity_type TEXT NOT NULL,
                references TEXT DEFAULT '[]',
                related_entity_ids TEXT DEFAULT '[]'
            )
        """))
        conn.execute(text("""
            CREATE TABLE IF NOT EXISTS raw_configs (
                session_id TEXT PRIMARY KEY REFERENCES sessions(id),
                raw_content BLOB,
                raw_filename TEXT
            )
        """))
    logger.info("Database initialized at %s", DB_PATH)


def save_session(session_data: dict, findings: list[dict], raw_content: bytes | None, raw_filename: str | None) -> str:
    """Save a session and its findings to the database.

    Returns the session ID.
    """
    from uuid import uuid4

    session_id = session_data.get("id", str(uuid4()))
    findings_data = json.dumps(findings, default=str)

    with DBSession(engine) as db:
        existing = db.execute(
            text("SELECT id FROM sessions WHERE source_checksum = :checksum"),
            {"checksum": session_data.get("source_checksum")},
        ).fetchone()

        if existing:
            db.execute(
                text("DELETE FROM findings WHERE session_id = :sid"),
                {"sid": existing[0]},
            )
            session_id = existing[0]
            db.execute(
                text("""
                    UPDATE sessions SET
                        vendor = :vendor,
                        vendor_version = :vendor_version,
                        hostname = :hostname,
                        parsed_at = :parsed_at,
                        source_filename = :source_filename,
                        labels = :labels,
                        metadata = :metadata,
                        security_policies = :security_policies,
                        nat_rules = :nat_rules,
                        interfaces = :interfaces,
                        zones = :zones,
                        address_objects = :address_objects,
                        service_objects = :service_objects,
                        health_score = :health_score,
                        finding_counts = :finding_counts
                    WHERE id = :id
                """),
                {
                    "id": session_id,
                    "vendor": session_data["vendor"],
                    "vendor_version": session_data.get("vendor_version"),
                    "hostname": session_data.get("hostname"),
                    "parsed_at": session_data.get("parsed_at"),
                    "source_filename": session_data.get("source_filename"),
                    "labels": json.dumps(session_data.get("labels", {})),
                    "metadata": json.dumps(session_data.get("metadata", {})),
                    "security_policies": json.dumps(session_data.get("security_policies", [])),
                    "nat_rules": json.dumps(session_data.get("nat_rules", [])),
                    "interfaces": json.dumps(session_data.get("interfaces", [])),
                    "zones": json.dumps(session_data.get("zones", [])),
                    "address_objects": json.dumps(session_data.get("address_objects", [])),
                    "service_objects": json.dumps(session_data.get("service_objects", [])),
                    "health_score": session_data.get("health_score", 100),
                    "finding_counts": json.dumps(session_data.get("finding_counts", {})),
                },
            )
        else:
            db.execute(
                text("""
                    INSERT INTO sessions (
                        id, vendor, vendor_version, hostname, parsed_at,
                        source_filename, source_checksum, labels, metadata,
                        security_policies, nat_rules, interfaces, zones,
                        address_objects, service_objects, health_score, finding_counts
                    ) VALUES (
                        :id, :vendor, :vendor_version, :hostname, :parsed_at,
                        :source_filename, :source_checksum, :labels, :metadata,
                        :security_policies, :nat_rules, :interfaces, :zones,
                        :address_objects, :service_objects, :health_score, :finding_counts
                    )
                """),
                {
                    "id": session_id,
                    "vendor": session_data["vendor"],
                    "vendor_version": session_data.get("vendor_version"),
                    "hostname": session_data.get("hostname"),
                    "parsed_at": session_data.get("parsed_at"),
                    "source_filename": session_data.get("source_filename"),
                    "source_checksum": session_data.get("source_checksum"),
                    "labels": json.dumps(session_data.get("labels", {})),
                    "metadata": json.dumps(session_data.get("metadata", {})),
                    "security_policies": json.dumps(session_data.get("security_policies", [])),
                    "nat_rules": json.dumps(session_data.get("nat_rules", [])),
                    "interfaces": json.dumps(session_data.get("interfaces", [])),
                    "zones": json.dumps(session_data.get("zones", [])),
                    "address_objects": json.dumps(session_data.get("address_objects", [])),
                    "service_objects": json.dumps(session_data.get("service_objects", [])),
                    "health_score": session_data.get("health_score", 100),
                    "finding_counts": json.dumps(session_data.get("finding_counts", {})),
                },
            )

        for f in findings:
            finding_id = f.get("id", str(uuid4()))
            db.execute(
                text("""
                    INSERT INTO findings (
                        id, session_id, check_id, severity, category, title,
                        description, entity_id, entity_type, references, related_entity_ids
                    ) VALUES (
                        :id, :session_id, :check_id, :severity, :category, :title,
                        :description, :entity_id, :entity_type, :references, :related_entity_ids
                    )
                """),
                {
                    "id": finding_id,
                    "session_id": session_id,
                    "check_id": f.get("check_id", ""),
                    "severity": f.get("severity", "info"),
                    "category": f.get("category", "security"),
                    "title": f.get("title", ""),
                    "description": f.get("description", ""),
                    "entity_id": f.get("entity_id", ""),
                    "entity_type": f.get("entity_type", ""),
                    "references": json.dumps(f.get("references", [])),
                    "related_entity_ids": json.dumps(f.get("related_entity_ids", [])),
                },
            )

        if raw_content is not None:
            db.execute(
                text("""
                    INSERT OR REPLACE INTO raw_configs (session_id, raw_content, raw_filename)
                    VALUES (:session_id, :raw_content, :raw_filename)
                """),
                {
                    "session_id": session_id,
                    "raw_content": raw_content,
                    "raw_filename": raw_filename,
                },
            )

        db.commit()

    logger.info("Saved session %s with %d findings", session_id, len(findings))
    return session_id


def get_session(session_id: str) -> dict | None:
    """Get a session by ID."""
    with DBSession(engine) as db:
        row = db.execute(
            text("SELECT * FROM sessions WHERE id = :id"),
            {"id": session_id},
        ).mappings().fetchone()

    if row is None:
        return None

    return {
        "id": row["id"],
        "vendor": row["vendor"],
        "vendor_version": row["vendor_version"],
        "hostname": row["hostname"],
        "parsed_at": row["parsed_at"],
        "source_filename": row["source_filename"],
        "source_checksum": row["source_checksum"],
        "labels": json.loads(row["labels"]),
        "metadata": json.loads(row["metadata"]),
        "security_policies": json.loads(row["security_policies"]),
        "nat_rules": json.loads(row["nat_rules"]),
        "interfaces": json.loads(row["interfaces"]),
        "zones": json.loads(row["zones"]),
        "address_objects": json.loads(row["address_objects"]),
        "service_objects": json.loads(row["service_objects"]),
        "health_score": row["health_score"],
        "finding_counts": json.loads(row["finding_counts"]),
        "created_at": row["created_at"],
    }


def list_sessions() -> list[dict]:
    """List all sessions."""
    with DBSession(engine) as db:
        rows = db.execute(text("SELECT * FROM sessions ORDER BY created_at DESC")).mappings().fetchall()

    return [
        {
            "id": r["id"],
            "vendor": r["vendor"],
            "vendor_version": r["vendor_version"],
            "hostname": r["hostname"],
            "parsed_at": r["parsed_at"],
            "source_filename": r["source_filename"],
            "source_checksum": r["source_checksum"],
            "labels": json.loads(r["labels"]),
            "health_score": r["health_score"],
            "finding_counts": json.loads(r["finding_counts"]),
            "rule_count": len(json.loads(r["security_policies"])),
            "created_at": r["created_at"],
        }
        for r in rows
    ]


def get_findings(session_id: str) -> list[dict]:
    """Get findings for a session."""
    with DBSession(engine) as db:
        rows = db.execute(
            text("SELECT * FROM findings WHERE session_id = :sid ORDER BY severity, check_id"),
            {"sid": session_id},
        ).mappings().fetchall()

    return [
        {
            "id": r["id"],
            "check_id": r["check_id"],
            "severity": r["severity"],
            "category": r["category"],
            "title": r["title"],
            "description": r["description"],
            "entity_id": r["entity_id"],
            "entity_type": r["entity_type"],
            "references": json.loads(r["references"]),
            "related_entity_ids": json.loads(r["related_entity_ids"]),
        }
        for r in rows
    ]


def get_raw_config(session_id: str) -> bytes | None:
    """Get raw config content for a session."""
    with DBSession(engine) as db:
        row = db.execute(
            text("SELECT raw_content FROM raw_configs WHERE session_id = :sid"),
            {"sid": session_id},
        ).fetchone()

    return row[0] if row else None


def delete_session(session_id: str) -> bool:
    """Delete a session and all associated data."""
    with DBSession(engine) as db:
        db.execute(text("DELETE FROM findings WHERE session_id = :sid"), {"sid": session_id})
        db.execute(text("DELETE FROM raw_configs WHERE session_id = :sid"), {"sid": session_id})
        result = db.execute(text("DELETE FROM sessions WHERE id = :sid"), {"sid": session_id})
        db.commit()
        return result.rowcount > 0
