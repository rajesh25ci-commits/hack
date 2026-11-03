"""
NETGUARD - Unit Tests for Gamification & Charts
Verifies XP awards, duplicate prevention, profile calculations, and chart helpers.
"""

import pytest
from database import award_xp, get_total_xp, get_gamification_profile, get_db_connection
from dashboard.charts import (
    create_network_topology_graph,
    create_security_gauge,
    create_vulnerability_donut,
    create_open_ports_bar,
    create_security_trend_chart
)


def test_award_xp_and_duplicate_prevention():
    """Verify XP is awarded and duplicates with same event_type & key are blocked."""
    event_key = "TEST-EVENT-001"
    xp_first = award_xp("TEST_SCAN", event_key, 100, "First test scan")
    assert xp_first == 100

    # Duplicate call should award 0 XP
    xp_second = award_xp("TEST_SCAN", event_key, 100, "Duplicate scan attempt")
    assert xp_second == 0


def test_gamification_profile_structure():
    """Verify gamification profile calculation returns ranks, levels, and missions."""
    profile = get_gamification_profile()
    assert "rank" in profile
    assert "level" in profile
    assert "total_xp" in profile
    assert "missions" in profile
    assert "unlocked_achievements" in profile
    assert len(profile["missions"]) == 6
    assert profile["level"] >= 1


def test_charts_empty_and_populated_data():
    """Verify all cyber chart helpers execute without exceptions."""
    # Test topology graph with empty and populated
    fig_empty = create_network_topology_graph([], [])
    assert fig_empty is not None

    sample_devices = [
        {"ip": "192.168.1.1", "hostname": "gateway", "mac": "00:11:22:33:44:55", "open_ports": [{"port": 80, "service": "http"}]},
        {"ip": "192.168.1.50", "hostname": "pos-register", "mac": "AA:BB:CC:DD:EE:FF", "open_ports": [{"port": 23, "service": "telnet"}]}
    ]
    sample_findings = [
        {"ip": "192.168.1.50", "severity": "Critical", "title": "Telnet Exposed"}
    ]
    fig_topo = create_network_topology_graph(sample_devices, sample_findings, "192.168.1.0/24")
    assert fig_topo is not None

    # Test gauge
    fig_gauge = create_security_gauge(85)
    assert fig_gauge is not None

    # Test donut
    fig_donut = create_vulnerability_donut(sample_findings)
    assert fig_donut is not None

    # Test open ports
    fig_ports = create_open_ports_bar(sample_devices)
    assert fig_ports is not None

    # Test security trend
    fig_trend = create_security_trend_chart([])
    assert fig_trend is not None
