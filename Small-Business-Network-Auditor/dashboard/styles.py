"""
NETGUARD - UI Styling and Component Templates
Implements the futuristic dark cybersecurity command center design system:
- High-contrast cyber palette (#070B14, #111C2E, #00D9FF, #00F5A0, #8B5CF6, #FFB020, #FF4560)
- Glowing neon borders, subtle grid pattern, radar sweep keyframes
- Commander profile widgets, XP progress bars, and achievement cards
"""

import textwrap
import streamlit as st
from config import CYBER_PALETTE, COMMANDER_RANKS


def apply_custom_theme():
    """Injects futuristic Cybersecurity Command Center CSS theme into Streamlit."""
    css_content = textwrap.dedent("""
    <style>
    /* Google Fonts */
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500;700;800&family=Orbitron:wght@600;800;900&display=swap');

    :root {
        --bg-main: #070B14;
        --bg-secondary: #0D1422;
        --card-bg: #111C2E;
        --elevated-card: #17243A;
        --neon-green: #00F5A0;
        --electric-cyan: #00D9FF;
        --purple-accent: #8B5CF6;
        --warning-orange: #FFB020;
        --critical-red: #FF4560;
        --text-pure: #F3F7FF;
        --text-secondary: #91A3B8;
        --surface-border: #1E2D4A;
        --cyan-glow: rgba(0, 217, 255, 0.18);
        --green-glow: rgba(0, 245, 160, 0.22);
    }

    /* Core Application Background with Subtle Cyber Grid */
    .stApp {
        background-color: var(--bg-main) !important;
        background-image: 
            radial-gradient(circle at 50% 0%, rgba(13, 20, 34, 0.8) 0%, transparent 75%),
            linear-gradient(rgba(0, 217, 255, 0.03) 1px, transparent 1px),
            linear-gradient(90deg, rgba(0, 217, 255, 0.03) 1px, transparent 1px) !important;
        background-size: 100% 100%, 32px 32px, 32px 32px !important;
        color: var(--text-pure) !important;
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, sans-serif !important;
    }

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {
        background-color: #090E1A !important;
        border-right: 1px solid var(--surface-border) !important;
    }

    section[data-testid="stSidebar"] .stRadio label {
        color: #E2E8F0 !important;
        font-weight: 500 !important;
        font-size: 0.92rem !important;
        padding: 7px 12px !important;
        border-radius: 8px !important;
        transition: all 0.2s ease !important;
    }

    section[data-testid="stSidebar"] .stRadio label:hover {
        background-color: rgba(0, 217, 255, 0.09) !important;
        color: var(--electric-cyan) !important;
    }

    /* Futuristic Cyber Card & Streamlit Bordered Container */
    .netguard-card, [data-testid="stVerticalBlockBorderWrapper"] {
        background: linear-gradient(155deg, rgba(17, 28, 46, 0.95), rgba(13, 20, 34, 0.92)) !important;
        backdrop-filter: blur(10px) !important;
        border: 1px solid var(--surface-border) !important;
        border-radius: 12px !important;
        padding: 18px 22px !important;
        margin-bottom: 16px !important;
        box-shadow: 0 4px 24px rgba(0, 0, 0, 0.5) !important;
        transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1) !important;
    }

    .netguard-card:hover, [data-testid="stVerticalBlockBorderWrapper"]:hover {
        border-color: rgba(0, 217, 255, 0.45) !important;
        box-shadow: 0 6px 30px rgba(0, 217, 255, 0.12) !important;
    }

    /* Metric Cards */
    .metric-container {
        display: flex;
        flex-direction: column;
        background: linear-gradient(135deg, #111C2E, #0D1422);
        border: 1px solid var(--surface-border);
        border-radius: 10px;
        padding: 16px;
        text-align: left;
        position: relative;
        overflow: hidden;
    }

    .metric-container::before {
        content: "";
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, var(--electric-cyan), var(--neon-green));
    }

    .metric-label {
        font-size: 0.76rem;
        color: var(--text-secondary);
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        margin-bottom: 4px;
    }

    .metric-value {
        font-size: 1.85rem;
        font-weight: 800;
        color: var(--text-pure);
        font-family: 'JetBrains Mono', monospace;
    }

    /* Badges & Tactical Pills */
    .badge-critical {
        background-color: rgba(255, 69, 96, 0.15);
        color: #FF4560;
        border: 1px solid rgba(255, 69, 96, 0.4);
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-high {
        background-color: rgba(255, 176, 32, 0.15);
        color: #FFB020;
        border: 1px solid rgba(255, 176, 32, 0.4);
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-medium {
        background-color: rgba(245, 158, 11, 0.15);
        color: #FBBF24;
        border: 1px solid rgba(245, 158, 11, 0.4);
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-low {
        background-color: rgba(0, 217, 255, 0.15);
        color: #00D9FF;
        border: 1px solid rgba(0, 217, 255, 0.4);
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-secure {
        background-color: rgba(0, 245, 160, 0.15);
        color: #00F5A0;
        border: 1px solid rgba(0, 245, 160, 0.4);
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-simulated {
        background-color: rgba(139, 92, 246, 0.15);
        color: #C084FC;
        border: 1px solid rgba(139, 92, 246, 0.4);
        padding: 3px 9px;
        border-radius: 6px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-block;
        font-family: 'JetBrains Mono', monospace;
    }

    .badge-commander {
        background: linear-gradient(135deg, rgba(139, 92, 246, 0.2), rgba(0, 217, 255, 0.2));
        color: #F3F7FF;
        border: 1px solid rgba(0, 217, 255, 0.5);
        padding: 3px 10px;
        border-radius: 20px;
        font-size: 0.75rem;
        font-weight: 700;
        display: inline-flex;
        align-items: center;
        gap: 6px;
    }

    /* Top Brand Header */
    .top-brand-bar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 12px 20px;
        background: linear-gradient(90deg, #090E1A, #111C2E);
        border: 1px solid var(--surface-border);
        border-radius: 12px;
        margin-bottom: 22px;
    }

    .brand-title-wrap {
        display: flex;
        align-items: center;
        gap: 12px;
    }

    /* Buttons */
    .stButton>button {
        background: linear-gradient(135deg, #0070F3, #00D9FF) !important;
        color: #FFFFFF !important;
        border: none !important;
        font-weight: 600 !important;
        border-radius: 8px !important;
        padding: 8px 18px !important;
        box-shadow: 0 4px 14px rgba(0, 112, 243, 0.35) !important;
        transition: all 0.2s ease !important;
    }

    .stButton>button:hover {
        opacity: 0.94 !important;
        transform: translateY(-1px) !important;
        box-shadow: 0 6px 22px rgba(0, 217, 255, 0.45) !important;
    }

    /* Inputs */
    .stTextInput>div>div>input {
        background-color: #0E1626 !important;
        color: #FFFFFF !important;
        border: 1px solid var(--surface-border) !important;
        border-radius: 8px !important;
        font-family: 'JetBrains Mono', monospace !important;
    }

    .stTextInput>div>div>input:focus {
        border-color: var(--electric-cyan) !important;
        box-shadow: 0 0 12px rgba(0, 217, 255, 0.3) !important;
    }

    /* Radar Scan Animation Keyframes */
    @keyframes radarSweep {
        0% { transform: rotate(0deg); }
        100% { transform: rotate(360deg); }
    }

    .radar-box {
        position: relative;
        width: 140px;
        height: 140px;
        margin: 0 auto;
        border-radius: 50%;
        border: 2px solid rgba(0, 217, 255, 0.4);
        background: radial-gradient(circle, rgba(0, 217, 255, 0.06) 0%, rgba(7, 11, 20, 0.95) 70%);
        overflow: hidden;
        box-shadow: 0 0 25px rgba(0, 217, 255, 0.15);
    }

    .radar-sweep-beam {
        position: absolute;
        top: 0; left: 0; width: 100%; height: 100%;
        background: conic-gradient(from 0deg, rgba(0, 245, 160, 0) 0deg, rgba(0, 217, 255, 0.4) 45deg, rgba(0, 245, 160, 0) 46deg);
        animation: radarSweep 2.4s linear infinite;
        transform-origin: center center;
    }

    .radar-crosshair {
        position: absolute;
        top: 50%; left: 0; right: 0;
        height: 1px;
        background: rgba(0, 217, 255, 0.2);
    }

    .radar-crosshair-v {
        position: absolute;
        top: 0; bottom: 0; left: 50%;
        width: 1px;
        background: rgba(0, 217, 255, 0.2);
    }

    /* XP Progress Bar */
    .xp-bar-bg {
        width: 100%;
        height: 7px;
        background: #17243A;
        border-radius: 10px;
        overflow: hidden;
        margin-top: 6px;
    }

    .xp-bar-fill {
        height: 100%;
        background: linear-gradient(90deg, #8B5CF6, #00D9FF, #00F5A0);
        border-radius: 10px;
        transition: width 0.5s ease-in-out;
    }

    /* Custom Scrollbars */
    ::-webkit-scrollbar {
        width: 8px;
        height: 8px;
    }
    ::-webkit-scrollbar-track {
        background: #070B14;
    }
    ::-webkit-scrollbar-thumb {
        background: #1E2D4A;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #2D4370;
    }
    </style>
    """)
    st.html(css_content)


def get_logo_html(size: int = 36) -> str:
    """Returns SVG vector shield logo for NETGUARD."""
    return textwrap.dedent(f"""<div style="display:inline-flex; align-items:center; gap:10px;">
<svg width="{size}" height="{size}" viewBox="0 0 48 48" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M24 4L6 12V22C6 33.05 13.68 43.34 24 46C34.32 43.34 42 33.05 42 22V12L24 4Z" fill="url(#shield_grad)" stroke="#00D9FF" stroke-width="2"/>
<path d="M24 14V34" stroke="#FFFFFF" stroke-width="2.5" stroke-linecap="round"/>
<path d="M16 24H32" stroke="#FFFFFF" stroke-width="2.5" stroke-linecap="round"/>
<circle cx="24" cy="24" r="4.5" fill="#00D9FF" stroke="#070B14" stroke-width="1.5"/>
<circle cx="16" cy="24" r="2.5" fill="#00F5A0"/>
<circle cx="32" cy="24" r="2.5" fill="#00F5A0"/>
<circle cx="24" cy="14" r="2.5" fill="#8B5CF6"/>
<circle cx="24" cy="34" r="2.5" fill="#0070F3"/>
<defs>
<linearGradient id="shield_grad" x1="6" y1="4" x2="42" y2="46" gradientUnits="userSpaceOnUse">
<stop stop-color="#111C2E"/>
<stop offset="1" stop-color="#070B14"/>
</linearGradient>
</defs>
</svg>
<span style="font-size:{int(size*0.62)}px; font-weight:800; color:#FFFFFF; letter-spacing:-0.5px;">NET<span style="color:#00D9FF;">GUARD</span></span>
</div>""")


def render_top_nav(active_scan=None, profile=None):
    """Renders top tactical status bar with Commander Rank, XP, and active scan badge."""
    from database import get_gamification_profile

    if profile is None:
        try:
            profile = get_gamification_profile()
        except Exception:
            profile = {
                "rank": "Cyber Recruit",
                "level": 1,
                "total_xp": 0,
                "progress_pct": 0
            }

    status_text = "Grid Idle (Ready to audit)"
    badge_type = "badge-secure"

    if active_scan:
        if active_scan.get("scan_mode") == "simulated":
            status_text = "Active: Demo Simulation Mode"
            badge_type = "badge-simulated"
        else:
            status_text = f"Subnet Active: {active_scan.get('target', 'Local')}"
            badge_type = "badge-low"

    logo_svg = get_logo_html(36)
    rank_title = profile.get("rank", "Cyber Recruit")
    level = profile.get("level", 1)
    xp = profile.get("total_xp", 0)

    top_nav_html = textwrap.dedent(f"""
    <div class="top-brand-bar">
        <div class="brand-title-wrap">
            {logo_svg}
            <span style="font-size: 0.85rem; color: #91A3B8; margin-left: 10px; border-left: 1px solid #1E2D4A; padding-left: 12px;">Small Business Network Auditor</span>
        </div>
        <div style="display: flex; align-items: center; gap: 14px;">
            <div class="badge-commander">
                <span>🛡️ Lvl {level}</span>
                <span style="color: #00D9FF; font-weight: 700;">{rank_title}</span>
                <span style="color: #91A3B8; font-size: 0.72rem;">({xp} XP)</span>
            </div>
            <span class="{badge_type}">{status_text}</span>
        </div>
    </div>
    """)
    st.html(top_nav_html)


def render_commander_sidebar_widget(profile: dict):
    """Renders the player Commander profile and live XP progress widget in the sidebar."""
    rank = profile.get("rank", "Cyber Recruit")
    level = profile.get("level", 1)
    total_xp = profile.get("total_xp", 0)
    current_tier_xp = profile.get("current_tier_xp", 0)
    needed_tier_xp = profile.get("needed_tier_xp", 100)
    progress_pct = profile.get("progress_pct", 0)

    widget_html = textwrap.dedent(f"""
    <div style="background: linear-gradient(135deg, #111C2E, #0D1422); border: 1px solid #1E2D4A; border-radius: 10px; padding: 12px 14px; margin-top: 12px; margin-bottom: 14px;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
            <span style="font-size: 0.72rem; color: #00D9FF; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;">Commander Dossier</span>
            <span style="font-size: 0.72rem; color: #00F5A0; font-weight: 700; font-family: monospace;">LVL {level}</span>
        </div>
        <div style="font-size: 0.95rem; font-weight: 800; color: #F3F7FF; margin-bottom: 2px;">
            {rank}
        </div>
        <div style="display: flex; justify-content: space-between; font-size: 0.72rem; color: #91A3B8; margin-top: 4px;">
            <span>{current_tier_xp} / {needed_tier_xp} XP</span>
            <span>{int(progress_pct)}%</span>
        </div>
        <div class="xp-bar-bg">
            <div class="xp-bar-fill" style="width: {min(100, max(4, progress_pct))}%;"></div>
        </div>
        <div style="font-size: 0.7rem; color: #64748B; margin-top: 6px; text-align: right;">
            Total: <b style="color: #F3F7FF;">{total_xp} XP</b>
        </div>
    </div>
    """)
    st.html(widget_html)
