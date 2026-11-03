"""
Unit tests for Member 3 Security Rule Engine and Member 4 AI Assistant.
Tests detection of Telnet, FTP, SMB, databases, VNC, HTTP, AI explanations, and fallback.
"""

import pytest
from security_analysis import (
    analyze_network_security,
    generate_ai_finding_explanation,
    ask_ai_security_assistant
)


def test_empty_devices_analysis():
    """Test security analysis with empty devices list."""
    findings, recs = analyze_network_security([])
    assert findings == []
    assert recs == []


def test_telnet_detection():
    """Test rule engine flags Telnet as Critical."""
    sample_device = [{
        "ip": "192.168.1.15",
        "hostname": "legacy-win7",
        "open_ports": [
            {"port": 23, "protocol": "tcp", "service": "telnet", "version": "Microsoft Telnet"}
        ]
    }]

    findings, recs = analyze_network_security(sample_device)
    assert len(findings) == 1
    assert findings[0]["severity"] == "Critical"
    assert "Telnet" in findings[0]["title"]
    assert findings[0]["port"] == 23
    assert len(recs) == 1
    assert recs[0]["priority"] == "Critical"


def test_ftp_and_smb_detection():
    """Test detection of unencrypted FTP and exposed SMB."""
    sample_device = [{
        "ip": "192.168.1.25",
        "hostname": "nas-storage",
        "open_ports": [
            {"port": 21, "protocol": "tcp", "service": "ftp", "version": "ProFTPD 1.3.5"},
            {"port": 445, "protocol": "tcp", "service": "microsoft-ds", "version": "Samba"}
        ]
    }]

    findings, recs = analyze_network_security(sample_device)
    severities = [f["severity"] for f in findings]
    titles = [f["title"] for f in findings]

    assert "High" in severities
    assert any("FTP" in t for t in titles)
    assert any("SMB" in t for t in titles)


def test_exposed_database_detection():
    """Test detection of database port on network."""
    sample_device = [{
        "ip": "192.168.1.110",
        "hostname": "db-server",
        "open_ports": [
            {"port": 3306, "protocol": "tcp", "service": "mysql", "version": "MySQL 5.7"}
        ]
    }]

    findings, recs = analyze_network_security(sample_device)
    assert any("MySQL" in f["title"] for f in findings)


def test_ai_finding_explanation_fallback():
    """Test structured 5-part explanation generation in rule-based fallback mode."""
    finding = {
        "id": "FIND-001",
        "title": "Critical Legacy Telnet Service Exposed",
        "device_ip": "192.168.1.15",
        "port": 23,
        "service": "telnet",
        "severity": "Critical",
        "evidence": "Port 23/tcp detected OPEN",
        "explanation": "Telnet sends plaintext passwords.",
        "solution": "Disable Telnet and use SSH.",
        "verification": "Test port 23 is closed."
    }

    result = generate_ai_finding_explanation(finding)
    assert "what" in result
    assert "why" in result
    assert "impact" in result
    assert "fix" in result
    assert "verify" in result
    assert len(result["what"]) > 0
    assert len(result["fix"]) > 0


def test_ask_ai_assistant_fallback():
    """Test AI assistant chat response on security questions without API key."""
    resp = ask_ai_security_assistant("Why is Telnet dangerous?")
    assert "Telnet" in resp
    assert ("plaintext" in resp.lower() or "unencrypted" in resp.lower())
