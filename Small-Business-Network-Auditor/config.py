"""
NETGUARD Configuration Module
Centralized settings for network validation, ports, scoring, database, gamification, and UI theme.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

BASE_DIR = Path(__file__).resolve().parent

# Branding & App Metadata
APP_NAME = "NETGUARD"
APP_SUBTITLE = "Cybersecurity Defense Command Center"
APP_TAGLINE = "Your Network. Your Mission. Your Defense."
APP_VERSION = "2.0.0-CYBER-OPS"

# Database Configuration
DEFAULT_DB_PATH = BASE_DIR / "data" / "netguard.db"
DB_PATH = Path(os.getenv("NETGUARD_DB_PATH", str(DEFAULT_DB_PATH)))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

# AI Security Assistant Configuration
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "").strip()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "").strip()

# Scan & Networking Constraints (Defensive & Safe Only)
DEFAULT_SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT_SECONDS", "30"))
MAX_HOSTS_PER_SCAN = 256  # Limit to /24 to prevent denial of service or network congestion
SOCKET_CONNECT_TIMEOUT = 1.0  # seconds per port probe

# Private / Local Network Range Enforcement (RFC 1918 + Loopback)
PERMITTED_PRIVATE_RANGES = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "127.0.0.0/8",
    "169.254.0.0/16"  # Link-local
]

# Port Scan Presets
PORT_PRESETS = {
    "Quick Top 20 (Essential SMB Services)": [
        21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443, 8888
    ],
    "Standard Top 60 (Standard Business Network Audit)": [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139,
        143, 161, 162, 389, 443, 445, 465, 500, 514, 587, 631, 636, 873, 993, 995,
        1080, 1433, 1521, 1723, 2049, 3000, 3128, 3306, 3389, 4000, 5000, 5432, 5900,
        6379, 7001, 8000, 8080, 8081, 8443, 8888, 9000, 9090, 9200, 9443, 27017
    ],
    "High-Risk Insecure Protocols Only": [
        21, 23, 25, 69, 80, 110, 135, 139, 445, 512, 513, 514, 1433, 3306, 3389, 5900, 6379, 27017
    ]
}

# Known Service Signatures and Baseline Security Implications
KNOWN_SERVICES = {
    21: {"name": "FTP", "desc": "File Transfer Protocol (Cleartext authentication and file data)", "default_risk": "High"},
    22: {"name": "SSH", "desc": "Secure Shell (Encrypted remote command line)", "default_risk": "Low"},
    23: {"name": "Telnet", "desc": "Unencrypted Telnet terminal service (Critical legacy risk)", "default_risk": "Critical"},
    25: {"name": "SMTP", "desc": "Simple Mail Transfer Protocol (Email transmission)", "default_risk": "Medium"},
    53: {"name": "DNS", "desc": "Domain Name System", "default_risk": "Low"},
    69: {"name": "TFTP", "desc": "Trivial File Transfer Protocol (No authentication)", "default_risk": "Critical"},
    80: {"name": "HTTP", "desc": "Hypertext Transfer Protocol (Cleartext web management interface)", "default_risk": "Medium"},
    88: {"name": "Kerberos", "desc": "Network authentication service", "default_risk": "Low"},
    110: {"name": "POP3", "desc": "Post Office Protocol (Unencrypted mail retrieval)", "default_risk": "High"},
    135: {"name": "MSRPC", "desc": "Microsoft RPC Endpoint Mapper", "default_risk": "Medium"},
    139: {"name": "NetBIOS", "desc": "NetBIOS Session Service (Legacy Windows sharing)", "default_risk": "High"},
    143: {"name": "IMAP", "desc": "Internet Message Access Protocol (Unencrypted mail)", "default_risk": "Medium"},
    161: {"name": "SNMP", "desc": "Simple Network Management Protocol (Community strings)", "default_risk": "High"},
    389: {"name": "LDAP", "desc": "Lightweight Directory Access Protocol", "default_risk": "Medium"},
    443: {"name": "HTTPS", "desc": "HTTP over TLS/SSL (Encrypted web interface)", "default_risk": "Low"},
    445: {"name": "SMB", "desc": "Server Message Block (Direct Windows File Sharing)", "default_risk": "High"},
    465: {"name": "SMTPS", "desc": "Secure SMTP over SSL", "default_risk": "Low"},
    587: {"name": "SMTP-Submission", "desc": "Authenticated Mail Submission", "default_risk": "Low"},
    631: {"name": "IPP", "desc": "Internet Printing Protocol (Network Printers)", "default_risk": "Low"},
    993: {"name": "IMAPS", "desc": "Encrypted IMAP over TLS", "default_risk": "Low"},
    995: {"name": "POP3S", "desc": "Encrypted POP3 over TLS", "default_risk": "Low"},
    1433: {"name": "MSSQL", "desc": "Microsoft SQL Server Database Engine", "default_risk": "High"},
    1521: {"name": "Oracle-DB", "desc": "Oracle Database Listener", "default_risk": "High"},
    2049: {"name": "NFS", "desc": "Network File System (Unauthenticated mount risks)", "default_risk": "High"},
    3306: {"name": "MySQL", "desc": "MySQL / MariaDB Database Server", "default_risk": "High"},
    3389: {"name": "RDP", "desc": "Remote Desktop Protocol (Windows Remote Desktop)", "default_risk": "High"},
    5432: {"name": "PostgreSQL", "desc": "PostgreSQL Database Server", "default_risk": "High"},
    5900: {"name": "VNC", "desc": "Virtual Network Computing Remote Framebuffer", "default_risk": "High"},
    6379: {"name": "Redis", "desc": "Redis In-Memory Key-Value Store (Often unauthenticated)", "default_risk": "Critical"},
    8080: {"name": "HTTP-Proxy/Admin", "desc": "Alternative HTTP / Web Administration Console", "default_risk": "Medium"},
    8443: {"name": "HTTPS-Alt", "desc": "Alternative HTTPS / Secure Web Console", "default_risk": "Low"},
    27017: {"name": "MongoDB", "desc": "MongoDB NoSQL Database Server", "default_risk": "High"}
}

# Risk Scoring Weight Deductions
RISK_DEDUCTIONS = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 3,
    "Informational": 0
}

# Score Tier Badges
SCORE_TIERS = {
    "Excellent": {"min": 90, "max": 100, "color": "#00F5A0", "badge": "OPTIMAL DEFENSE", "desc": "Strong network security posture with minimal exposed attack surface."},
    "Good": {"min": 75, "max": 89, "color": "#00D9FF", "badge": "FORTIFIED", "desc": "Satisfactory defense with minor warnings or standard services requiring monitoring."},
    "Needs Improvement": {"min": 50, "max": 74, "color": "#FFB020", "badge": "VULNERABLE", "desc": "Several unencrypted or exposed administrative services detected."},
    "Poor": {"min": 0, "max": 49, "color": "#FF4560", "badge": "CRITICAL RISK", "desc": "Severe vulnerabilities (such as Telnet or exposed databases) present high risk."}
}

# Premium Cyber-Command Theme Colors
COLORS = {
    "bg_main": "#070B14",
    "bg_secondary": "#0D1422",
    "card_bg": "#111C2E",
    "elevated_card": "#17243A",
    "neon_green": "#00F5A0",
    "electric_cyan": "#00D9FF",
    "cyan": "#00D9FF",
    "purple_accent": "#8B5CF6",
    "warning_orange": "#FFB020",
    "warning": "#FFB020",
    "critical_red": "#FF4560",
    "critical": "#FF4560",
    "text_main": "#F3F7FF",
    "text_secondary": "#91A3B8",
    "text_muted": "#91A3B8",
    "border": "#1E2E4A"
}

# Alias for charts and UI components
CYBER_PALETTE = COLORS

# Gamification Ranks & Level Boundaries
COMMANDER_RANKS = [
    {"level": 1, "name": "Cyber Recruit", "min_xp": 0, "max_xp": 300, "badge": "🔰", "color": "#91A3B8"},
    {"level": 2, "name": "Network Scout", "min_xp": 300, "max_xp": 700, "badge": "🛰️", "color": "#00D9FF"},
    {"level": 3, "name": "Security Sentinel", "min_xp": 700, "max_xp": 1200, "badge": "🛡️", "color": "#8B5CF6"},
    {"level": 4, "name": "Threat Hunter", "min_xp": 1200, "max_xp": 1800, "badge": "⚡", "color": "#FFB020"},
    {"level": 5, "name": "Cyber Guardian", "min_xp": 1800, "max_xp": 2500, "badge": "⚔️", "color": "#00F5A0"},
    {"level": 6, "name": "Defense Commander", "min_xp": 2500, "max_xp": 99999, "badge": "👑", "color": "#00F5A0"}
]

# Collectible Achievements
ACHIEVEMENTS_LIST = [
    {
        "id": "first_recon",
        "title": "First Recon",
        "icon": "🛰️",
        "desc": "Initiate and complete your first authorized network audit.",
        "xp": 150,
        "category": "Discovery"
    },
    {
        "id": "network_explorer",
        "title": "Grid Explorer",
        "icon": "📡",
        "desc": "Detect and map 3 or more network assets.",
        "xp": 200,
        "category": "Discovery"
    },
    {
        "id": "threat_hunter",
        "title": "Threat Hunter",
        "icon": "🎯",
        "desc": "Identify and classify potential security exposures across the grid.",
        "xp": 200,
        "category": "Analysis"
    },
    {
        "id": "port_matrix",
        "title": "Matrix Auditor",
        "icon": "🔌",
        "desc": "Inspect open ports and identify protocol banners.",
        "xp": 150,
        "category": "Analysis"
    },
    {
        "id": "firewall_guardian",
        "title": "Firewall Guardian",
        "icon": "🛡️",
        "desc": "Apply and confirm resolution of a detected vulnerability.",
        "xp": 250,
        "category": "Remediation"
    },
    {
        "id": "ai_oracle",
        "title": "AI Neural Sync",
        "icon": "🧠",
        "desc": "Consult NetGuard AI Core for defense briefings.",
        "xp": 100,
        "category": "Intelligence"
    },
    {
        "id": "zero_critical",
        "title": "Iron Citadel",
        "icon": "💎",
        "desc": "Attain a network security posture with 0 Critical exposures.",
        "xp": 300,
        "category": "Defense"
    },
    {
        "id": "audit_master",
        "title": "Audit Master",
        "icon": "📜",
        "desc": "Compile and generate an executive ReportLab PDF audit package.",
        "xp": 150,
        "category": "Reporting"
    }
]

# Interactive Defense Missions
MISSIONS_LIST = [
    {
        "id": "mission_recon",
        "number": "01",
        "title": "Operation Grid Recon",
        "subtitle": "Discover Your Network Assets",
        "desc": "Run an authorized scan on your local private subnet or launch the simulated retail demo.",
        "xp": 250,
        "target_page": "Network Scanner",
        "icon": "🛰️"
    },
    {
        "id": "mission_ports",
        "number": "02",
        "title": "Service Matrix Intercept",
        "subtitle": "Identify Listening Ports & Protocols",
        "desc": "Inspect active TCP services, identify unencrypted protocols (Telnet, FTP), and detect exposures.",
        "xp": 150,
        "target_page": "Open Port Matrix",
        "icon": "🔌"
    },
    {
        "id": "mission_threats",
        "number": "03",
        "title": "Threat Surface Analysis",
        "subtitle": "Analyze Vulnerabilities & Evidence",
        "desc": "Examine deterministic security findings, affected hosts, and evidence logs.",
        "xp": 200,
        "target_page": "Threat Analysis",
        "icon": "⚠️"
    },
    {
        "id": "mission_remediate",
        "number": "04",
        "title": "Citadel Hardening",
        "subtitle": "Remediate Detected Exposures",
        "desc": "Review recommended fixes, take defensive action, and mark items as resolved.",
        "xp": 250,
        "target_page": "Remediation Missions",
        "icon": "🛡️"
    },
    {
        "id": "mission_report",
        "number": "05",
        "title": "Executive Intelligence",
        "subtitle": "Generate Security Audit Report",
        "desc": "Compile a board-ready executive PDF report with complete vulnerability evidence.",
        "xp": 150,
        "target_page": "Executive PDF Reports",
        "icon": "📄"
    },
    {
        "id": "mission_ai",
        "number": "06",
        "title": "AI Neural Consultation",
        "subtitle": "Sync with NetGuard AI Core",
        "desc": "Ask the AI Security Assistant for plain-English threat explanations and guidance.",
        "xp": 100,
        "target_page": "AI Cyber Assistant",
        "icon": "🧠"
    }
]
