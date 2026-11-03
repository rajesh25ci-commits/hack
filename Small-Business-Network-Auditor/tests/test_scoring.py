"""
Unit tests for Member 3 Risk Scoring Module.
Tests transparent deductions, caps, score categorization, and edge cases.
"""

import pytest
from security_analysis import calculate_security_score


def test_perfect_score_zero_findings():
    """Test clean network with zero findings receives 100/100."""
    res = calculate_security_score([])
    assert res["score"] == 100
    assert res["category"] == "Excellent"
    assert res["breakdown"]["Critical"]["count"] == 0


def test_critical_deduction():
    """Test critical findings deduction."""
    findings = [
        {"severity": "Critical", "title": "Telnet"}
    ]
    res = calculate_security_score(findings)
    assert res["score"] == 75  # 100 - 25 = 75
    assert res["category"] == "Good"


def test_score_floor_and_caps():
    """Test that score does not drop below floor even with massive findings count."""
    findings = [{"severity": "Critical", "title": f"Crit {i}"} for i in range(10)]
    findings += [{"severity": "High", "title": f"High {i}"} for i in range(10)]
    res = calculate_security_score(findings)
    assert res["score"] >= 5
    assert res["category"] == "Poor"


def test_medium_and_low_deductions():
    """Test medium and low deductions."""
    findings = [
        {"severity": "Medium", "title": "HTTP Web Admin"},  # -8
        {"severity": "Low", "title": "Multiple Ports"}       # -3
    ]
    res = calculate_security_score(findings)
    assert res["score"] == 89  # 100 - 8 - 3 = 89
    assert res["category"] == "Good"
