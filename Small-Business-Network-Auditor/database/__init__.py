"""
Database Package for NETGUARD
SQLite storage for scans, devices, ports, findings, recommendations, and gamification events.
"""

from .database import (
    init_db,
    save_scan,
    get_scan,
    get_all_scans,
    get_latest_scan,
    update_recommendation,
    delete_scan,
    compare_scans,
    award_xp,
    get_total_xp,
    get_unlocked_achievements,
    get_gamification_profile,
    get_db_connection
)

__all__ = [
    "init_db",
    "save_scan",
    "get_scan",
    "get_all_scans",
    "get_latest_scan",
    "update_recommendation",
    "delete_scan",
    "compare_scans",
    "award_xp",
    "get_total_xp",
    "get_unlocked_achievements",
    "get_gamification_profile",
    "get_db_connection"
]
