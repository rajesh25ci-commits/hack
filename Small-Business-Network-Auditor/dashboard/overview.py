"""
NETGUARD - Page 2: Dashboard / SOC Overview
Executive cybersecurity command center displaying:
- Subnet Header & Tactical Indicators
- Security Health Gauge & Risk Level Indicator
- Interactive 2D Network Topology Node-Link Graph
- Vulnerability Severity Donut & Open Ports Matrix
- Historical Security Posture Trend Line Chart
- Tactical Mission Progress Snapshot
- Recent Audits Quick-Switch Ledger
"""

import textwrap
import streamlit as st
from database import get_latest_scan, get_all_scans, get_scan, get_gamification_profile
from dashboard.charts import (
    create_network_topology_graph,
    create_security_gauge,
    create_vulnerability_donut,
    create_open_ports_bar,
    create_security_trend_chart
)
from config import CYBER_PALETTE


def render_overview_page():
    """Renders the executive SOC command center dashboard."""
    active_scan = st.session_state.get("active_scan")
    if not active_scan:
        active_scan = get_latest_scan()
        if active_scan:
            st.session_state["active_scan"] = active_scan

    # Empty State Check
    if not active_scan:
        st.html(textwrap.dedent("""
        <div class="netguard-card" style="text-align: center; padding: 60px 20px;">
            <div style="font-size: 3.2rem; margin-bottom: 14px;">📡</div>
            <h2 style="color: #F3F7FF; font-size: 1.6rem; font-weight: 800; margin-bottom: 8px;">
                No Network Audit Data Available
            </h2>
            <p style="color: #91A3B8; max-width: 540px; margin: 0 auto 24px auto; font-size: 0.95rem; line-height: 1.5;">
                Your security operations center is awaiting telemetry. Run an authorized scan on your local private subnet
                or launch the realistic small business simulation to explore audit findings.
            </p>
        </div>
        """))

        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            c_a, c_b = st.columns(2)
            with c_a:
                if st.button("🚀 Start Network Scan", use_container_width=True):
                    st.session_state["current_page"] = "Network Scanner"
                    st.rerun()
            with c_b:
                if st.button("🎮 Load Demo Network", use_container_width=True):
                    st.session_state["current_page"] = "Network Scanner"
                    st.session_state["auto_load_demo"] = True
                    st.rerun()
        return

    # Extract scan metadata
    scan_id = active_scan.get("scan_id", "N/A")
    target = active_scan.get("target", "N/A")
    scan_time = active_scan.get("scan_time", "N/A")[:19].replace("T", " ")
    scan_mode = active_scan.get("scan_mode", "real").capitalize()
    score = active_scan.get("risk_score", 100)
    devices = active_scan.get("devices", [])
    findings = active_scan.get("findings", [])
    total_ports = sum(len(d.get("open_ports", [])) for d in devices)

    crit_count = sum(1 for f in findings if f.get("severity") == "Critical")
    high_count = sum(1 for f in findings if f.get("severity") == "High")
    med_count = sum(1 for f in findings if f.get("severity") == "Medium")
    low_count = sum(1 for f in findings if f.get("severity") == "Low")

    # Mode Badge
    mode_badge = '<span class="badge-simulated">🎮 Demo Simulation</span>' if scan_mode.lower() == "simulated" else '<span class="badge-secure">⚡ Live Real Scan</span>'

    # Tactical Header Bar
    st.html(textwrap.dedent(f"""
    <div class="netguard-card" style="padding: 16px 22px; margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
            <div>
                <div style="display: flex; align-items: center; gap: 10px;">
                    <h2 style="font-size: 1.4rem; font-weight: 800; color: #F3F7FF; margin: 0;">
                        SOC Command Operations
                    </h2>
                    {mode_badge}
                </div>
                <div style="font-size: 0.85rem; color: #91A3B8; margin-top: 4px;">
                    Target: <b style="color: #00D9FF;">{target}</b> &nbsp;|&nbsp; 
                    Scan ID: <code style="color: #00F5A0;">{scan_id}</code> &nbsp;|&nbsp; 
                    Timestamp: <b>{scan_time}</b>
                </div>
            </div>
            <div>
                <a href="#recent-audits" style="color: #00D9FF; text-decoration: none; font-size: 0.82rem; font-weight: 600;">
                    ↓ Historical Audits
                </a>
            </div>
        </div>
    </div>
    """))

    # 4 Tactical KPI Metric Cards
    col_m1, col_m2, col_m3, col_m4 = st.columns(4)

    with col_m1:
        score_col = CYBER_PALETTE["neon_green"] if score >= 85 else (CYBER_PALETTE["warning"] if score >= 60 else CYBER_PALETTE["critical"])
        posture_label = 'Hardened Perimeter' if score >= 85 else ('Moderate Risk' if score >= 60 else 'Critical Exposure')
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Network Hygiene</span>
            <div style="display: flex; align-items: baseline; gap: 8px;">
                <span class="metric-value" style="color: {score_col};">{score}</span>
                <span style="color: #91A3B8; font-size: 0.9rem;">/100</span>
            </div>
            <span style="font-size: 0.75rem; color: {score_col}; margin-top: 4px; font-weight: 600;">{posture_label}</span>
        </div>
        """))

    with col_m2:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Discovered Hosts</span>
            <span class="metric-value">{len(devices)}</span>
            <span style="font-size: 0.75rem; color: #00D9FF; margin-top: 4px;">Subnet Nodes Detected</span>
        </div>
        """))

    with col_m3:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Listening Ports</span>
            <span class="metric-value">{total_ports}</span>
            <span style="font-size: 0.75rem; color: #8B5CF6; margin-top: 4px;">Open Network Services</span>
        </div>
        """))

    with col_m4:
        find_col = CYBER_PALETTE["critical"] if (crit_count + high_count) > 0 else CYBER_PALETTE["neon_green"]
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Vulnerabilities</span>
            <span class="metric-value" style="color: {find_col};">{len(findings)}</span>
            <span style="font-size: 0.75rem; color: #FF4560; margin-top: 4px; font-weight: 600;">
                {crit_count} Critical • {high_count} High
            </span>
        </div>
        """))

    st.html("<div style='margin-bottom: 20px;'></div>")

    # Visualizations Row 1: Interactive Network Topology Graph
    with st.container(border=True):
        st.markdown("#### 🌐 Subnet Topology & Asset Attack Surface")
        st.caption("Central Gateway router with connected endpoints. Nodes are color-coded by detected risk severity.")
        fig_topology = create_network_topology_graph(devices, findings, target)
        st.plotly_chart(fig_topology, use_container_width=True)

    # Visualizations Row 2: Security Health Gauge & Risk Severity Donut
    c_chart1, c_chart2 = st.columns([1, 1])
    with c_chart1:
        with st.container(border=True):
            st.markdown("#### 🛡️ Health Score Gauge")
            fig_gauge = create_security_gauge(score)
            st.plotly_chart(fig_gauge, use_container_width=True)

    with c_chart2:
        with st.container(border=True):
            st.markdown("#### ⚠️ Vulnerability Severity Breakdown")
            if findings:
                fig_donut = create_vulnerability_donut(findings)
                st.plotly_chart(fig_donut, use_container_width=True)
            else:
                st.info("No security risks identified. All surveyed endpoints adhere to standard defensive baseline.")

    # Visualizations Row 3: Open Ports Horizontal Bar & Historical Security Trend
    c_chart3, c_chart4 = st.columns([1, 1])
    with c_chart3:
        with st.container(border=True):
            st.markdown("#### 🔌 Exposed Services Frequency")
            fig_ports = create_open_ports_bar(devices)
            st.plotly_chart(fig_ports, use_container_width=True)

    with c_chart4:
        with st.container(border=True):
            st.markdown("#### 📈 Historical Posture Trend")
            all_scans = get_all_scans()
            fig_trend = create_security_trend_chart(all_scans)
            st.plotly_chart(fig_trend, use_container_width=True)

    # Gamified Tactical Mission Progress Snapshot
    profile = get_gamification_profile()
    missions = profile.get("missions", [])
    completed_missions = sum(1 for m in missions if m.get("status") == "Completed")
    mission_pct = int((completed_missions / len(missions)) * 100) if missions else 0

    with st.container(border=True):
        st.markdown("#### 🎯 Active Security Missions Progress")
        c_m1, c_m2 = st.columns([3, 1])
        with c_m1:
            st.html(textwrap.dedent(f"""
            <div style="margin-top: 6px;">
                <div style="display: flex; justify-content: space-between; font-size: 0.85rem; color: #91A3B8; margin-bottom: 6px;">
                    <span>Completed {completed_missions} of {len(missions)} Tactical Directives</span>
                    <span style="color: #00F5A0; font-weight: 700;">{mission_pct}% Complete</span>
                </div>
                <div class="xp-bar-bg" style="height: 10px;">
                    <div class="xp-bar-fill" style="width: {mission_pct}%;"></div>
                </div>
            </div>
            """))
        with c_m2:
            if st.button("🏆 Open Mission Center", use_container_width=True):
                st.session_state["current_page"] = "Missions & Achievements"
                st.rerun()

    # Recent Scans Table Section
    st.html('<div id="recent-audits"></div>')
    with st.container(border=True):
        st.markdown("#### 🕒 Audit History Archive")

        if all_scans:
            for s in all_scans[:6]:
                c1, c2, c3, c4, c5 = st.columns([2, 1.5, 1, 1, 1.2])
                with c1:
                    st.write(f"**{s['target']}** (`{s['scan_id']}`)")
                with c2:
                    st.caption(f"🕒 {s['scan_time'][:16].replace('T', ' ')}")
                with c3:
                    st.write(f"{s['total_devices']} hosts")
                with c4:
                    score_val = s['risk_score']
                    sc_color = "#00F5A0" if score_val >= 85 else ("#FFB020" if score_val >= 60 else "#FF4560")
                    st.markdown(f"<span style='color:{sc_color}; font-weight:700;'>{score_val}/100</span>", unsafe_allow_html=True)
                with c5:
                    if st.button("Load Audit", key=f"load_scan_{s['scan_id']}", use_container_width=True):
                        loaded = get_scan(s["scan_id"])
                        if loaded:
                            st.session_state["active_scan"] = loaded
                            st.rerun()
        else:
            st.caption("No historical scans found.")
