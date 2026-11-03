"""
NETGUARD - Member 6: SQLite Database Module
Manages persistent relational storage for scans, devices, open ports,
security findings, remediation recommendations, scan comparisons,
and the gamified XP, mission, and achievement system.
"""

import sqlite3
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from config import (
    DB_PATH,
    COMMANDER_RANKS,
    ACHIEVEMENTS_LIST,
    MISSIONS_LIST
)


def get_db_connection() -> sqlite3.Connection:
    """Creates a sqlite3 connection with dict-like row access."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Initializes the database schema with necessary tables and indexes."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Scans Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT UNIQUE NOT NULL,
        target TEXT NOT NULL,
        scan_time TEXT NOT NULL,
        scan_mode TEXT NOT NULL DEFAULT 'real',
        total_devices INTEGER NOT NULL DEFAULT 0,
        total_open_ports INTEGER NOT NULL DEFAULT 0,
        total_findings INTEGER NOT NULL DEFAULT 0,
        risk_score INTEGER NOT NULL DEFAULT 100,
        status TEXT NOT NULL DEFAULT 'completed'
    );
    """)

    # 2. Devices Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        ip TEXT NOT NULL,
        hostname TEXT,
        mac TEXT,
        status TEXT NOT NULL DEFAULT 'online',
        scan_mode TEXT NOT NULL DEFAULT 'real',
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
    );
    """)

    # 3. Ports Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS ports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER NOT NULL,
        scan_id TEXT NOT NULL,
        port INTEGER NOT NULL,
        protocol TEXT NOT NULL DEFAULT 'tcp',
        service TEXT,
        version TEXT,
        FOREIGN KEY (device_id) REFERENCES devices(id) ON DELETE CASCADE,
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
    );
    """)

    # 4. Security Findings Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS security_findings (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        device_ip TEXT NOT NULL,
        hostname TEXT,
        port TEXT,
        protocol TEXT NOT NULL DEFAULT 'tcp',
        service TEXT,
        severity TEXT NOT NULL,
        title TEXT NOT NULL,
        evidence TEXT,
        explanation TEXT,
        solution TEXT,
        verification TEXT,
        requires_manual_verification INTEGER NOT NULL DEFAULT 0,
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
    );
    """)

    # 5. Recommendations Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS recommendations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        finding_id TEXT NOT NULL,
        scan_id TEXT NOT NULL,
        device_ip TEXT NOT NULL,
        title TEXT NOT NULL,
        priority TEXT NOT NULL,
        category TEXT,
        action TEXT NOT NULL,
        impact TEXT,
        status TEXT NOT NULL DEFAULT 'Pending',
        notes TEXT DEFAULT '',
        FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
    );
    """)

    # 6. Gamification XP Events Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS gamification_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        event_key TEXT NOT NULL,
        xp INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(event_type, event_key)
    );
    """)

    # 7. Unlocked Achievements Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS achievements_unlocked (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        achievement_id TEXT UNIQUE NOT NULL,
        unlocked_at TEXT NOT NULL
    );
    """)

    # Indexes for fast historical lookups
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_time ON scans(scan_time DESC);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_devices_scan ON devices(scan_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON security_findings(scan_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_recs_finding ON recommendations(finding_id);")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_xp_events ON gamification_events(event_type);")

    conn.commit()
    conn.close()


def save_scan(scan_data: Dict) -> str:
    """
    Saves a complete scan dictionary into the SQLite database.
    Awards XP for scan completion and unlocks discovery achievements.
    Returns the scan_id.
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    scan_id = scan_data.get("scan_id")
    if not scan_id:
        scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"

    target = scan_data.get("target", "127.0.0.1")
    scan_time = scan_data.get("scan_time", datetime.now().isoformat())
    scan_mode = scan_data.get("scan_mode", "real")
    devices = scan_data.get("devices", [])
    findings = scan_data.get("findings", [])
    recommendations = scan_data.get("recommendations", [])
    risk_score = scan_data.get("risk_score", 100)
    status = scan_data.get("status", "completed")

    total_ports = sum(len(d.get("open_ports", [])) for d in devices)

    # Insert Scan Header
    cursor.execute("""
        INSERT OR REPLACE INTO scans 
        (scan_id, target, scan_time, scan_mode, total_devices, total_open_ports, total_findings, risk_score, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id, target, scan_time, scan_mode,
        len(devices), total_ports, len(findings), risk_score, status
    ))

    # Insert Devices and Ports
    for dev in devices:
        ip = dev.get("ip")
        hostname = dev.get("hostname", "")
        mac = dev.get("mac", "")
        dev_status = dev.get("status", "online")
        dev_mode = dev.get("scan_mode", scan_mode)

        cursor.execute("""
            INSERT INTO devices (scan_id, ip, hostname, mac, status, scan_mode)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, ip, hostname, mac, dev_status, dev_mode))
        device_db_id = cursor.lastrowid

        for p in dev.get("open_ports", []):
            cursor.execute("""
                INSERT INTO ports (device_id, scan_id, port, protocol, service, version)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                device_db_id, scan_id, p.get("port"),
                p.get("protocol", "tcp"), p.get("service", ""),
                p.get("version", "")
            ))

    # Insert Findings
    for f in findings:
        cursor.execute("""
            INSERT INTO security_findings 
            (finding_id, scan_id, device_ip, hostname, port, protocol, service, severity, title, evidence, explanation, solution, verification, requires_manual_verification)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f.get("id", ""), scan_id, f.get("device_ip", ""),
            f.get("hostname", ""), str(f.get("port", "")),
            f.get("protocol", "tcp"), f.get("service", ""),
            f.get("severity", "Low"), f.get("title", ""),
            f.get("evidence", ""), f.get("explanation", ""),
            f.get("solution", ""), f.get("verification", ""),
            1 if f.get("requires_manual_verification") else 0
        ))

    # Insert Recommendations
    for r in recommendations:
        cursor.execute("""
            INSERT INTO recommendations
            (finding_id, scan_id, device_ip, title, priority, category, action, impact, status, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            r.get("finding_id", ""), scan_id, r.get("device_ip", ""),
            r.get("title", ""), r.get("priority", "Medium"),
            r.get("category", ""), r.get("action", ""),
            r.get("impact", ""), r.get("status", "Pending"),
            r.get("notes", "")
        ))

    conn.commit()
    conn.close()

    # Gamification: Award XP for completing an audit
    award_xp("SCAN_COMPLETED", scan_id, 250)
    if len(devices) >= 3:
        award_xp("ACHIEVEMENT", "network_explorer", 200)
    if len(findings) > 0:
        award_xp("ACHIEVEMENT", "threat_hunter", 200)
    if not any(f.get("severity") == "Critical" for f in findings) and len(devices) > 0:
        award_xp("ACHIEVEMENT", "zero_critical", 300)

    return scan_id


def get_scan(scan_id: str) -> Optional[Dict]:
    """Retrieves full scan data by scan_id."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,))
    scan_row = cursor.fetchone()
    if not scan_row:
        conn.close()
        return None

    scan_dict = dict(scan_row)

    # Retrieve devices
    cursor.execute("SELECT * FROM devices WHERE scan_id = ?", (scan_id,))
    devices = []
    for d_row in cursor.fetchall():
        d_dict = dict(d_row)
        # Retrieve ports for device
        cursor.execute("SELECT port, protocol, service, version FROM ports WHERE device_id = ?", (d_dict["id"],))
        d_dict["open_ports"] = [dict(p) for p in cursor.fetchall()]
        d_dict["services_summary"] = [f"{p['service']} ({p['port']})" for p in d_dict["open_ports"]]
        devices.append(d_dict)

    # Retrieve findings
    cursor.execute("SELECT * FROM security_findings WHERE scan_id = ?", (scan_id,))
    findings = []
    for f_row in cursor.fetchall():
        f = dict(f_row)
        f["id"] = f["finding_id"]
        f["requires_manual_verification"] = bool(f["requires_manual_verification"])
        findings.append(f)

    # Retrieve recommendations
    cursor.execute("SELECT * FROM recommendations WHERE scan_id = ?", (scan_id,))
    recommendations = [dict(r) for r in cursor.fetchall()]

    conn.close()

    scan_dict["devices"] = devices
    scan_dict["findings"] = findings
    scan_dict["recommendations"] = recommendations
    return scan_dict


def get_all_scans() -> List[Dict]:
    """Returns list of summary scan records sorted by time descending."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY scan_time DESC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_latest_scan() -> Optional[Dict]:
    """Returns the most recent scan in full, or None."""
    scans = get_all_scans()
    if not scans:
        return None
    return get_scan(scans[0]["scan_id"])


def update_recommendation(finding_id: str, status: str, notes: Optional[str] = None):
    """Updates remediation status and user notes for a finding."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    if notes is not None:
        cursor.execute("""
            UPDATE recommendations 
            SET status = ?, notes = ? 
            WHERE finding_id = ?
        """, (status, notes, finding_id))
    else:
        cursor.execute("""
            UPDATE recommendations 
            SET status = ? 
            WHERE finding_id = ?
        """, (status, finding_id))

    conn.commit()
    conn.close()

    # Award XP if marked as Resolved
    if status == "Resolved":
        award_xp("REMEDIATION_RESOLVED", finding_id, 150)
        award_xp("ACHIEVEMENT", "firewall_guardian", 250)


def delete_scan(scan_id: str):
    """Deletes a scan and cascades removal of associated devices, ports, and findings."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    conn.commit()
    conn.close()


def compare_scans(scan_id_a: str, scan_id_b: str) -> Dict:
    """
    Compares two scans (Scan A = baseline/previous, Scan B = latest/current).
    Calculates score change, new findings, resolved findings, and port/device changes.
    """
    scan_a = get_scan(scan_id_a)
    scan_b = get_scan(scan_id_b)

    if not scan_a or not scan_b:
        raise ValueError("One or both scans could not be found in the database.")

    score_diff = scan_b["risk_score"] - scan_a["risk_score"]
    device_diff = len(scan_b["devices"]) - len(scan_a["devices"])
    ports_diff = scan_b["total_open_ports"] - scan_a["total_open_ports"]

    # Match findings by title + device_ip
    def finding_key(f):
        return (f.get("title"), f.get("device_ip"), str(f.get("port")))

    keys_a = {finding_key(f): f for f in scan_a["findings"]}
    keys_b = {finding_key(f): f for f in scan_b["findings"]}

    new_risks = [f for k, f in keys_b.items() if k not in keys_a]
    resolved_risks = [f for k, f in keys_a.items() if k not in keys_b]

    return {
        "scan_a": scan_a,
        "scan_b": scan_b,
        "score_diff": score_diff,
        "device_diff": device_diff,
        "ports_diff": ports_diff,
        "new_risks": new_risks,
        "resolved_risks": resolved_risks
    }


# ==========================================
# GAMIFICATION ENGINE (XP, LEVELS, MISSIONS)
# ==========================================

def award_xp(event_type: str, event_key: str, xp_amount: int, description: Optional[str] = None) -> int:
    """
    Awards XP points for a specific distinct action.
    Uses database UNIQUE(event_type, event_key) to prevent double-awarding XP for the same event.
    Returns the XP amount awarded (0 if already awarded).
    """
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO gamification_events (event_type, event_key, xp, created_at)
            VALUES (?, ?, ?, ?)
        """, (event_type, event_key, xp_amount, datetime.now().isoformat()))
        conn.commit()
        awarded = xp_amount
    except sqlite3.IntegrityError:
        awarded = 0
    finally:
        conn.close()

    return awarded


def get_total_xp() -> int:
    """Calculates sum of all earned XP points."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COALESCE(SUM(xp), 0) FROM gamification_events;")
    total = cursor.fetchone()[0]
    conn.close()
    return int(total)


def get_unlocked_achievements() -> List[str]:
    """Returns list of unlocked achievement IDs."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT event_key FROM gamification_events WHERE event_type = 'ACHIEVEMENT';")
    unlocked = [row[0] for row in cursor.fetchall()]
    conn.close()
    return unlocked


def get_gamification_profile() -> Dict:
    """
    Constructs the complete live player profile:
    - Level, rank title, current XP, progress percentage to next rank
    - Status of all 6 tactical missions
    - Status of all collectible achievement badges
    """
    total_xp = get_total_xp()

    # Determine Commander Rank and Level
    current_rank = COMMANDER_RANKS[0]
    for r in COMMANDER_RANKS:
        if total_xp >= r["min_xp"]:
            current_rank = r
        else:
            break

    # Calculate progress toward next level
    min_xp = current_rank["min_xp"]
    max_xp = current_rank["max_xp"]
    if max_xp >= 99999:
        pct = 1.0
        needed = 0
    else:
        span = max_xp - min_xp
        curr_in_span = max(0, total_xp - min_xp)
        pct = min(1.0, max(0.0, curr_in_span / span)) if span > 0 else 1.0
        needed = max(0, max_xp - total_xp)

    # Check Real DB Stats for Mission Statuses
    scans = get_all_scans()
    total_scans = len(scans)
    latest_scan = get_latest_scan()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM devices;")
    total_devices = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM security_findings;")
    total_findings = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM recommendations WHERE status = 'Resolved';")
    resolved_recs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM gamification_events WHERE event_type = 'REPORT_GENERATED';")
    reports_gen = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM gamification_events WHERE event_type = 'AI_CONSULTATION';")
    ai_queries = cursor.fetchone()[0]

    conn.close()

    # Unlocked achievements set
    unlocked_ach_ids = set(get_unlocked_achievements())
    # Add first recon if scans exist
    if total_scans > 0:
        unlocked_ach_ids.add("first_recon")

    # Evaluate Missions
    missions_state = []
    for m in MISSIONS_LIST:
        m_id = m["id"]
        status = "Available"
        progress_val = 0.0

        if m_id == "mission_recon":
            if total_scans > 0:
                status = "Completed"
                progress_val = 1.0
            else:
                status = "In Progress"
                progress_val = 0.2
        elif m_id == "mission_ports":
            if total_scans > 0:
                status = "Completed"
                progress_val = 1.0
            else:
                status = "Available"
        elif m_id == "mission_threats":
            if total_findings > 0:
                status = "Completed"
                progress_val = 1.0
            elif total_scans > 0:
                status = "In Progress"
                progress_val = 0.5
        elif m_id == "mission_remediate":
            if resolved_recs > 0:
                status = "Completed"
                progress_val = 1.0
            elif total_findings > 0:
                status = "In Progress"
                progress_val = 0.3
        elif m_id == "mission_report":
            if reports_gen > 0:
                status = "Completed"
                progress_val = 1.0
            elif total_scans > 0:
                status = "Available"
                progress_val = 0.5
        elif m_id == "mission_ai":
            if ai_queries > 0:
                status = "Completed"
                progress_val = 1.0
            else:
                status = "Available"

        m_copy = dict(m)
        m_copy["status"] = status
        m_copy["progress"] = progress_val
        missions_state.append(m_copy)

    # Evaluate Achievements List with Unlocked state
    achievements_state = []
    for ach in ACHIEVEMENTS_LIST:
        a_copy = dict(ach)
        is_unlocked = ach["id"] in unlocked_ach_ids
        a_copy["unlocked"] = is_unlocked
        achievements_state.append(a_copy)

    return {
        "level": current_rank["level"],
        "rank": current_rank["name"],
        "rank_name": current_rank["name"],
        "badge": current_rank["badge"],
        "color": current_rank["color"],
        "total_xp": total_xp,
        "min_xp": min_xp,
        "max_xp": max_xp,
        "current_tier_xp": curr_in_span,
        "needed_tier_xp": span if span > 0 else 100,
        "progress_pct": pct * 100 if pct <= 1.0 else pct,
        "xp_needed": needed,
        "total_scans": total_scans,
        "total_devices": total_devices,
        "total_findings": total_findings,
        "resolved_recs": resolved_recs,
        "stats": {
            "total_scans": total_scans,
            "total_devices": total_devices,
            "total_findings": total_findings,
            "resolved_count": resolved_recs
        },
        "missions": missions_state,
        "achievements": achievements_state,
        "unlocked_achievements": {ach_id: "Unlocked" for ach_id in unlocked_ach_ids},
        "unlocked_count": len([a for a in achievements_state if a["unlocked"]]),
        "total_achievements": len(achievements_state)
    }
