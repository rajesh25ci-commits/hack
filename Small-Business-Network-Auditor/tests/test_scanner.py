"""
Unit tests for Network Scanner (Device Discovery and Port Scanning).
Covers validation, simulated mode, IP/CIDR validation, socket timeouts, and error handling.
"""

import pytest
from network_scanner import (
    validate_target_subnet,
    get_local_ip_and_subnet,
    generate_simulated_devices,
    scan_device_ports,
    is_nmap_available
)


def test_valid_private_ip():
    """Test single valid private IPv4 validation."""
    valid, target, err = validate_target_subnet("192.168.1.50")
    assert valid is True
    assert target == "192.168.1.50/32"
    assert err == ""


def test_valid_private_cidr():
    """Test valid /24 private CIDR."""
    valid, target, err = validate_target_subnet("10.0.0.0/24")
    assert valid is True
    assert target == "10.0.0.0/24"
    assert err == ""


def test_loopback_ip():
    """Test loopback address is permitted."""
    valid, target, err = validate_target_subnet("127.0.0.1")
    assert valid is True
    assert target == "127.0.0.1/32"


def test_public_ip_rejected():
    """Test that public IPs are strictly blocked by defensive rules."""
    valid, target, err = validate_target_subnet("8.8.8.8")
    assert valid is False
    assert "Safety restriction violation" in err


def test_invalid_cidr_format():
    """Test malformed IP or CIDR strings."""
    valid, target, err = validate_target_subnet("invalid-ip-string")
    assert valid is False
    assert "Invalid IP/CIDR" in err


def test_subnet_too_large():
    """Test that oversized subnets (e.g., /16 = 65,536 hosts) are rejected to prevent denial of service."""
    valid, target, err = validate_target_subnet("10.0.0.0/16")
    assert valid is False
    assert "Subnet too large" in err


def test_empty_input():
    """Test empty string validation."""
    valid, target, err = validate_target_subnet("")
    assert valid is False
    assert "cannot be empty" in err


def test_simulated_device_generation():
    """Test generation of realistic small business devices."""
    devices = generate_simulated_devices("192.168.1.0/24")
    assert len(devices) == 6
    for d in devices:
        assert "ip" in d
        assert "open_ports" in d
        assert d.get("scan_mode") == "simulated"
        assert len(d["open_ports"]) > 0

    # Verify specific SMB devices exist
    ips = [d["ip"] for d in devices]
    assert "192.168.1.1" in ips
    assert "192.168.1.15" in ips


def test_scan_device_ports_fallback():
    """Test scanning loopback on high closed port to ensure socket scanner gracefully handles closed ports."""
    # Probing an arbitrary unassigned port on localhost
    res = scan_device_ports("127.0.0.1", [64532], prefer_nmap=False, timeout=1)
    assert isinstance(res, list)
    # Closed port should not be reported as open
    assert len(res) == 0


def test_local_ip_detection():
    """Test that local IP detection returns a non-empty string."""
    local_ip, subnet = get_local_ip_and_subnet()
    assert isinstance(local_ip, str)
    assert len(local_ip) > 0
    assert "/" in subnet
