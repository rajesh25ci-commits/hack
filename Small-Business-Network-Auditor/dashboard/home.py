"""
NETGUARD - Page 1: Landing / Command Center Home
Futuristic cyber defense homepage:
- Commander Profile status indicator
- Hero: "Your Network. Your Mission. Your Defense."
- Live interactive Network Topology Preview
- Quick Launch CTAs: Start Security Scan, View Dashboard, View Missions
- Tactical Metric Cards: Devices, Open Ports, Findings, Hygiene Score
"""

import textwrap
import streamlit as st
from config import APP_NAME, APP_SUBTITLE, APP_TAGLINE, APP_VERSION, CYBER_PALETTE
from database import get_latest_scan, get_gamification_profile
from dashboard.styles import get_logo_html
from dashboard.charts import create_network_topology_graph


def render_landing_page():
    """Renders the futuristic cybersecurity command center homepage."""
    profile = get_gamification_profile()
    active_scan = st.session_state.get("active_scan")
    if not active_scan:
        active_scan = get_latest_scan()
        if active_scan:
            st.session_state["active_scan"] = active_scan

    rank = profile.get("rank", "Cyber Recruit")
    level = profile.get("level", 1)
    total_xp = profile.get("total_xp", 0)

    devices = active_scan.get("devices", []) if active_scan else []
    findings = active_scan.get("findings", []) if active_scan else []
    score = active_scan.get("risk_score", 100) if active_scan else 100
    total_ports = sum(len(d.get("open_ports", [])) for d in devices)
    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")

    logo_svg = get_logo_html(52)

    # 1. Top Commander Status Bar & Hero Banner
    st.html(textwrap.dedent(f"""
    <div style="background: linear-gradient(135deg, rgba(17, 28, 46, 0.9), rgba(9, 14, 26, 0.95)); border: 1px solid #1E2D4A; border-radius: 14px; padding: 22px 28px; margin-bottom: 24px; box-shadow: 0 4px 30px rgba(0, 0, 0, 0.5);">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px;">
            <div style="display: flex; align-items: center; gap: 14px;">
                {logo_svg}
                <div>
                    <div style="font-size: 0.8rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.05em; text-transform: uppercase;">Command Operations Center</div>
                    <div style="font-size: 0.88rem; color: #91A3B8;">{APP_SUBTITLE} • v{APP_VERSION}</div>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 12px;">
                <div class="badge-commander" style="padding: 6px 14px; font-size: 0.82rem;">
                    <span>🛡️ Level {level:02d}</span>
                    <span style="color: #00D9FF; font-weight: 700;">{rank}</span>
                    <span style="color: #00F5A0; font-family: monospace;">({total_xp} XP)</span>
                </div>
            </div>
        </div>
    </div>
    """))

    # Hero Centerpiece
    st.html(textwrap.dedent("""
    <div style="text-align: center; padding: 20px 10px 10px 10px;">
        <span style="background: rgba(0, 217, 255, 0.12); color: #00D9FF; border: 1px solid rgba(0, 217, 255, 0.35); padding: 4px 14px; border-radius: 20px; font-size: 0.78rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;">
            Defensive Network Intelligence Platform
        </span>
        <h1 style="font-size: 3rem; font-weight: 900; margin: 16px 0 10px 0; color: #F3F7FF; letter-spacing: -0.03em;">
            Your Network. Your Mission. <span style="background: linear-gradient(90deg, #00D9FF, #00F5A0); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">Your Defense.</span>
        </h1>
        <p style="max-width: 740px; margin: 0 auto 24px auto; color: #91A3B8; font-size: 1.1rem; line-height: 1.6;">
            Discover connected devices, pinpoint unpatched vulnerabilities, audit dangerous open ports,
            and fortify your business against cyber threats with actionable plain-English intelligence.
        </p>
    </div>
    """))

    # CTA Action Buttons
    c_btn1, c_btn2, c_btn3 = st.columns([1, 1, 1])
    with c_btn1:
        if st.button("⚡ START SECURITY SCAN", use_container_width=True):
            st.session_state["current_page"] = "Network Scanner"
            st.rerun()
    with c_btn2:
        if st.button("📊 VIEW SECURITY DASHBOARD", use_container_width=True):
            st.session_state["current_page"] = "Dashboard"
            st.rerun()
    with c_btn3:
        if st.button("🏆 VIEW MISSIONS & TROPHIES", use_container_width=True):
            st.session_state["current_page"] = "Missions & Achievements"
            st.rerun()

    st.html("<div style='margin-bottom: 20px;'></div>")

    # Tactical Metric Cards (5 Metrics)
    col_m1, col_m2, col_m3, col_m4, col_m5 = st.columns(5)
    with col_m1:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Total Hosts</span>
            <span class="metric-value">{len(devices)}</span>
            <span style="font-size: 0.75rem; color: #00D9FF; margin-top: 4px;">Discovered Assets</span>
        </div>
        """))
    with col_m2:
        active_count = sum(1 for d in devices if d.get("status") == "up" or len(d.get("open_ports", [])) > 0)
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Active Nodes</span>
            <span class="metric-value">{active_count}</span>
            <span style="font-size: 0.75rem; color: #00F5A0; margin-top: 4px;">Live Responding</span>
        </div>
        """))
    with col_m3:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Open Ports</span>
            <span class="metric-value">{total_ports}</span>
            <span style="font-size: 0.75rem; color: #8B5CF6; margin-top: 4px;">Listening Services</span>
        </div>
        """))
    with col_m4:
        find_color = "#FF4560" if crit_count > 0 else "#00F5A0"
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Risk Findings</span>
            <span class="metric-value" style="color: {find_color};">{len(findings)}</span>
            <span style="font-size: 0.75rem; color: #FFB020; margin-top: 4px;">{crit_count} Critical Level</span>
        </div>
        """))
    with col_m5:
        score_color = "#00F5A0" if score >= 85 else ("#FFB020" if score >= 60 else "#FF4560")
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Hygiene Score</span>
            <span class="metric-value" style="color: {score_color};">{score}<span style="font-size: 1rem; color: #91A3B8;">/100</span></span>
            <span style="font-size: 0.75rem; color: #00D9FF; margin-top: 4px;">Security Posture</span>
        </div>
        """))

    st.html("<div style='margin-bottom: 24px;'></div>")

    # Interactive Network Topology Preview Panel
    with st.container(border=True):
        st.markdown("#### 🌐 Live Subnet Topology Radar")
        st.caption("Interactive visual map of nodes on your local network. Nodes are color-coded by vulnerability severity.")
        
        target_subnet = active_scan.get("target", "192.168.1.0/24") if active_scan else "192.168.1.0/24"
        fig_topo = create_network_topology_graph(devices, findings, target_subnet)
        st.plotly_chart(fig_topo, use_container_width=True)

    # Core Features 3x2 Grid
    st.html(textwrap.dedent("""
    <div style="margin-top: 32px; margin-bottom: 20px;">
        <h3 style="font-size: 1.4rem; font-weight: 800; color: #F3F7FF; text-align: center; margin-bottom: 8px;">
            Commercial-Grade Security Architecture
        </h3>
        <p style="font-size: 0.92rem; color: #91A3B8; text-align: center; max-width: 600px; margin: 0 auto 24px auto;">
            Engineered for retail stores, medical clinics, offices, and small enterprises without dedicated SOC teams.
        </p>
    </div>
    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 18px; margin-bottom: 28px;">
        <div class="netguard-card" style="margin-bottom: 0;">
            <div style="font-size: 1.8rem; margin-bottom: 8px;">🔍</div>
            <h4 style="color: #00D9FF; font-size: 1.05rem; margin-bottom: 6px;">Automated Host Discovery</h4>
            <p style="color: #91A3B8; font-size: 0.85rem; line-height: 1.5; margin: 0;">
                Rapidly identify all workstations, POS terminals, IoT devices, printers, and switches connected to your subnet.
            </p>
        </div>
        <div class="netguard-card" style="margin-bottom: 0;">
            <div style="font-size: 1.8rem; margin-bottom: 8px;">⚡</div>
            <h4 style="color: #00D9FF; font-size: 1.05rem; margin-bottom: 6px;">Non-Intrusive Port Auditing</h4>
            <p style="color: #91A3B8; font-size: 0.85rem; line-height: 1.5; margin: 0;">
                Inspect open ports and banners without causing downtime, network disruption, or bandwidth saturation.
            </p>
        </div>
        <div class="netguard-card" style="margin-bottom: 0;">
            <div style="font-size: 1.8rem; margin-bottom: 8px;">🧠</div>
            <h4 style="color: #00D9FF; font-size: 1.05rem; margin-bottom: 6px;">AI Security Advisory</h4>
            <p style="color: #91A3B8; font-size: 0.85rem; line-height: 1.5; margin: 0;">
                Translate raw port numbers and CVEs into business impact explanations with step-by-step verification instructions.
            </p>
        </div>
        <div class="netguard-card" style="margin-bottom: 0;">
            <div style="font-size: 1.8rem; margin-bottom: 8px;">🎯</div>
            <h4 style="color: #00D9FF; font-size: 1.05rem; margin-bottom: 6px;">Gamified Commander Missions</h4>
            <p style="color: #91A3B8; font-size: 0.85rem; line-height: 1.5; margin: 0;">
                Complete tactical security missions, unlock rare achievement badges, and level up as you harden your defense perimeter.
            </p>
        </div>
        <div class="netguard-card" style="margin-bottom: 0;">
            <div style="font-size: 1.8rem; margin-bottom: 8px;">📈</div>
            <h4 style="color: #00D9FF; font-size: 1.05rem; margin-bottom: 6px;">Historical Posture Delta</h4>
            <p style="color: #91A3B8; font-size: 0.85rem; line-height: 1.5; margin: 0;">
                Track security posture progression over time. Compare before & after scans to verify vulnerability remediation.
            </p>
        </div>
        <div class="netguard-card" style="margin-bottom: 0;">
            <div style="font-size: 1.8rem; margin-bottom: 8px;">📄</div>
            <h4 style="color: #00D9FF; font-size: 1.05rem; margin-bottom: 6px;">Executive Audit PDF Reports</h4>
            <p style="color: #91A3B8; font-size: 0.85rem; line-height: 1.5; margin: 0;">
                Generate professional PDF documentation with one click for cyber insurers, compliance auditors, and executive boards.
            </p>
        </div>
    </div>
    """))
