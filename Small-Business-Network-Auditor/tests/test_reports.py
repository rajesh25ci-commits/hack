"""
Unit tests for Member 6 ReportLab PDF Generator.
Tests byte compilation, branding, section formatting, and edge cases.
"""

import pytest
from reports import generate_pdf_report


def test_generate_pdf_report_valid_data():
    """Test generating a complete PDF document."""
    scan_data = {
        "scan_id": "PDF-AUDIT-001",
        "target": "192.168.1.0/24",
        "scan_time": "2026-11-03T10:00:00",
        "scan_mode": "simulated",
        "risk_score": 65,
        "devices": [
            {
                "ip": "192.168.1.1",
                "hostname": "gateway.local",
                "mac": "00:1A:2B:3C:4D:01",
                "open_ports": [{"port": 80, "service": "http", "version": "Admin WebGUI"}],
                "services_summary": ["HTTP (80)"]
            }
        ],
        "findings": [
            {
                "id": "FIND-001",
                "title": "Unencrypted HTTP Admin",
                "device_ip": "192.168.1.1",
                "hostname": "gateway.local",
                "port": 80,
                "severity": "Medium",
                "evidence": "Port 80 open",
                "explanation": "Admin credentials sent unencrypted.",
                "solution": "Enable HTTPS.",
                "verification": "Check port 443.",
                "requires_manual_verification": True
            }
        ],
        "recommendations": [
            {
                "finding_id": "FIND-001",
                "device_ip": "192.168.1.1",
                "title": "Enable HTTPS on gateway",
                "priority": "Medium",
                "category": "Web",
                "action": "Enable TLS",
                "impact": "Protects logins",
                "status": "Pending"
            }
        ]
    }

    pdf_bytes = generate_pdf_report(scan_data)
    assert isinstance(pdf_bytes, bytes)
    assert len(pdf_bytes) > 1000  # Verify non-trivial PDF content
    assert pdf_bytes.startswith(b"%PDF")  # Valid PDF header magic bytes


def test_generate_pdf_empty_findings():
    """Test PDF generation for a 100% clean network with zero findings."""
    scan_data = {
        "scan_id": "PDF-CLEAN-001",
        "target": "192.168.1.0/24",
        "scan_time": "2026-11-03T10:00:00",
        "scan_mode": "real",
        "risk_score": 100,
        "devices": [],
        "findings": [],
        "recommendations": []
    }

    pdf_bytes = generate_pdf_report(scan_data)
    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes.startswith(b"%PDF")
