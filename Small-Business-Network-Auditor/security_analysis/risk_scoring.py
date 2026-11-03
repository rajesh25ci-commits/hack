"""
NETGUARD - Member 3: Risk Scoring Module
Computes transparent, weighted 0-100 security risk scores with deduction breakdown,
tier categorization, and defensive explanations.
"""

from typing import Dict, List
from config import RISK_DEDUCTIONS, SCORE_TIERS


def calculate_security_score(findings: List[Dict], total_devices: int = 1) -> Dict:
    """
    Computes an indicative network security score from 0 to 100.
    Applies capped deductions per severity to avoid double-penalizing similar issues.
    """
    if not findings:
        return {
            "score": 100,
            "category": "Excellent",
            "badge": SCORE_TIERS["Excellent"]["badge"],
            "color": SCORE_TIERS["Excellent"]["color"],
            "description": SCORE_TIERS["Excellent"]["desc"],
            "breakdown": {
                "Critical": {"count": 0, "deduction": 0},
                "High": {"count": 0, "deduction": 0},
                "Medium": {"count": 0, "deduction": 0},
                "Low": {"count": 0, "deduction": 0}
            },
            "summary_explanation": (
                "No critical, high, or medium security risks were detected across discovered hosts. "
                "Network baseline exhibits strong defensive configuration."
            ),
            "disclaimer": (
                "Notice: This score is an automated indicative security metric based on port and service "
                "evidence. It serves as an actionable hygiene guide and does not constitute a certified compliance audit."
            )
        }

    # Count findings by severity
    counts = {
        "Critical": sum(1 for f in findings if f.get("severity") == "Critical"),
        "High": sum(1 for f in findings if f.get("severity") == "High"),
        "Medium": sum(1 for f in findings if f.get("severity") == "Medium"),
        "Low": sum(1 for f in findings if f.get("severity") == "Low"),
    }

    # Calculate weighted deductions with reasonable caps to prevent negative overflow
    # Critical: -25 each (max 60 pts deduction)
    crit_ded = min(60, counts["Critical"] * RISK_DEDUCTIONS["Critical"])
    # High: -15 each (max 45 pts deduction)
    high_ded = min(45, counts["High"] * RISK_DEDUCTIONS["High"])
    # Medium: -8 each (max 30 pts deduction)
    med_ded = min(30, counts["Medium"] * RISK_DEDUCTIONS["Medium"])
    # Low: -3 each (max 15 pts deduction)
    low_ded = min(15, counts["Low"] * RISK_DEDUCTIONS["Low"])

    total_deduction = crit_ded + high_ded + med_ded + low_ded
    raw_score = 100 - total_deduction
    final_score = max(5, min(100, raw_score))  # Floor at 5, ceiling at 100

    # Determine category
    category = "Poor"
    for cat_name, tier in SCORE_TIERS.items():
        if tier["min"] <= final_score <= tier["max"]:
            category = cat_name
            break

    tier_info = SCORE_TIERS[category]

    # Generate explanatory summary
    reasons = []
    if counts["Critical"] > 0:
        reasons.append(f"{counts['Critical']} critical issue(s) (e.g. unencrypted Telnet or exposed key-value cache)")
    if counts["High"] > 0:
        reasons.append(f"{counts['High']} high-risk exposure(s) (e.g. cleartext FTP, SMB, or database ports)")
    if counts["Medium"] > 0:
        reasons.append(f"{counts['Medium']} medium warning(s) (e.g. unencrypted HTTP admin portals)")
    if counts["Low"] > 0:
        reasons.append(f"{counts['Low']} low-priority finding(s)")

    if reasons:
        explanation = f"Score adjusted to {final_score}/100 due to: " + "; ".join(reasons) + "."
    else:
        explanation = f"Clean security posture: {final_score}/100."

    return {
        "score": final_score,
        "category": category,
        "badge": tier_info["badge"],
        "color": tier_info["color"],
        "description": tier_info["desc"],
        "breakdown": {
            "Critical": {"count": counts["Critical"], "deduction": crit_ded},
            "High": {"count": counts["High"], "deduction": high_ded},
            "Medium": {"count": counts["Medium"], "deduction": med_ded},
            "Low": {"count": counts["Low"], "deduction": low_ded}
        },
        "summary_explanation": explanation,
        "disclaimer": (
            "Notice: This score is an automated indicative security metric based on port and service "
            "evidence. It serves as an actionable hygiene guide and does not constitute a certified compliance audit."
        )
    }
