"""
Unit tests for Member 6 SQLite Database module.
Tests table creation, scan persistence, retrieval, status updates, deletions, and comparisons.
"""

import os
import pytest
from database import (
    init_db,
    save_scan,
    get_scan,
    get_all_scans,
    update_recommendation,
    delete_scan,
    compare_scans
)


@pytest.fixture(autouse=True)
def setup_test_db():
    """Ensure database schema is initialized before each test."""
    init_db()


def test_save_and_retrieve_scan():
    """Test full scan persistence and retrieval."""
    scan_payload = {
        "scan_id": "TEST-SCAN-001",
        "target": "192.168.1.0/24",
        "scan_time": "2026-11-03T10:00:00",
        "scan_mode": "simulated",
        "devices": [
            {
                "ip": "192.168.1.10",
                "hostname": "pos-terminal",
                "mac": "00:11:22:33:44:55",
                "status": "online",
                "open_ports": [
                    {"port": 80, "protocol": "tcp", "service": "http", "version": "Apache"}
                ]
            }
        ],
        "findings": [
            {
                "id": "FIND-TEST-1",
                "title": "HTTP Cleartext",
                "device_ip": "192.168.1.10",
                "hostname": "pos-terminal",
                "port": 80,
                "protocol": "tcp",
                "service": "http",
                "severity": "Medium",
                "evidence": "Port 80 open",
                "explanation": "Cleartext HTTP",
                "solution": "Enable HTTPS",
                "verification": "Check port 443"
            }
        ],
        "recommendations": [
            {
                "finding_id": "FIND-TEST-1",
                "device_ip": "192.168.1.10",
                "title": "Enable HTTPS",
                "priority": "Medium",
                "category": "Web",
                "action": "Enable TLS",
                "impact": "Protects data",
                "status": "Pending",
                "notes": ""
            }
        ],
        "risk_score": 92
    }

    s_id = save_scan(scan_payload)
    assert s_id == "TEST-SCAN-001"

    retrieved = get_scan("TEST-SCAN-001")
    assert retrieved is not None
    assert retrieved["scan_id"] == "TEST-SCAN-001"
    assert retrieved["risk_score"] == 92
    assert len(retrieved["devices"]) == 1
    assert len(retrieved["findings"]) == 1
    assert len(retrieved["recommendations"]) == 1


def test_update_recommendation_status():
    """Test updating a recommendation to Resolved with notes."""
    update_recommendation("FIND-TEST-1", "Resolved", "Cert installed and verified.")
    retrieved = get_scan("TEST-SCAN-001")
    assert retrieved is not None
    rec = retrieved["recommendations"][0]
    assert rec["status"] == "Resolved"
    assert "Cert installed" in rec["notes"]


def test_compare_scans():
    """Test comparing two scans in database."""
    scan_b = {
        "scan_id": "TEST-SCAN-002",
        "target": "192.168.1.0/24",
        "scan_time": "2026-11-03T11:00:00",
        "scan_mode": "simulated",
        "devices": [
            {
                "ip": "192.168.1.10",
                "hostname": "pos-terminal",
                "mac": "00:11:22:33:44:55",
                "status": "online",
                "open_ports": [
                    {"port": 443, "protocol": "tcp", "service": "https", "version": "Apache TLS"}
                ]
            }
        ],
        "findings": [],  # Vulnerability resolved!
        "recommendations": [],
        "risk_score": 100
    }
    save_scan(scan_b)

    diff = compare_scans("TEST-SCAN-001", "TEST-SCAN-002")
    assert diff["score_diff"] == 8  # 100 - 92 = +8
    assert len(diff["resolved_risks"]) == 1
    assert len(diff["new_risks"]) == 0


def test_delete_scan():
    """Test deleting a scan cascades properly."""
    delete_scan("TEST-SCAN-001")
    delete_scan("TEST-SCAN-002")
    assert get_scan("TEST-SCAN-001") is None
    assert get_scan("TEST-SCAN-002") is None
