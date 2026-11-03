"""
NETGUARD - Page 5: Open Port Analysis
Detailed technical breakdown of all open TCP ports across the network,
contextual risk classifications, and defensive protocol guidance.
"""

import textwrap
import streamlit as st
from config import KNOWN_SERVICES, CYBER_PALETTE
from database import get_latest_scan, award_xp


def render_port_analysis_page():
    """Renders the comprehensive open port explorer."""
    active_scan = st.session_state.get("active_scan")
    if not active_scan:
        active_scan = get_latest_scan()
        if active_scan:
            st.session_state["active_scan"] = active_scan

    if not active_scan:
        st.info("No audit active. Please run a scan from the Network Scanner page first.")
        return

    devices = active_scan.get("devices", [])
    scan_id = active_scan.get("scan_id", "N/A")

    if devices:
        award_xp("PORTS_INSPECTED", scan_id, 30, "Inspected listening service matrix")

    st.html(textwrap.dedent("""
    <div class="netguard-card" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.08em; text-transform: uppercase;">
                    MISSION 02: SERVICE MATRIX INSPECTION
                </div>
                <h2 style="color: #F3F7FF; font-size: 1.55rem; font-weight: 800; margin: 2px 0 0 0;">
                    Open Port Analysis & Service Matrix
                </h2>
                <p style="color: #91A3B8; font-size: 0.88rem; margin-top: 4px; margin-bottom: 0;">
                    Granular breakdown of listening TCP sockets. NetGuard distinguishes legitimate business services from high-risk legacy protocols.
                </p>
            </div>
            <div>
                <span class="badge-commander">Service Matrix v2.0</span>
            </div>
        </div>
    </div>
    """))

    # Flatten all ports across all devices
    all_ports_list = []
    for d in devices:
        for p in d.get("open_ports", []):
            p_num = p["port"]
            known = KNOWN_SERVICES.get(p_num, {})
            risk = known.get("default_risk", "Low")
            if p_num == 80:
                has_443 = any(x["port"] == 443 for x in d.get("open_ports", []))
                risk = "Low" if has_443 else "Medium"

            all_ports_list.append({
                "ip": d["ip"],
                "hostname": d.get("hostname", "Unknown"),
                "port": p_num,
                "protocol": p.get("protocol", "tcp").upper(),
                "service": p.get("service", known.get("name", "Unknown")),
                "version": p.get("version") or "Standard Service Listener",
                "risk": risk,
                "desc": known.get("desc", "Standard TCP network communication endpoint.")
            })

    if not all_ports_list:
        st.success("Zero open ports detected on audited targets. Attack surface is completely minimal.")
        return

    # Metrics
    crit_p = sum(1 for p in all_ports_list if p["risk"] == "Critical")
    high_p = sum(1 for p in all_ports_list if p["risk"] == "High")
    med_p = sum(1 for p in all_ports_list if p["risk"] == "Medium")
    low_p = sum(1 for p in all_ports_list if p["risk"] == "Low")

    col_m1, col_m2, col_m3, col_m4 = st.columns(4)
    with col_m1:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Total Open Ports</span>
            <span class="metric-value">{len(all_ports_list)}</span>
            <span style="font-size: 0.75rem; color: #00D9FF; margin-top: 4px;">Detected Sockets</span>
        </div>
        """))
    with col_m2:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Critical Exposure</span>
            <span class="metric-value" style="color: #FF4560;">{crit_p}</span>
            <span style="font-size: 0.75rem; color: #FF4560; margin-top: 4px;">Telnet, Cleartext, SMB</span>
        </div>
        """))
    with col_m3:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">High-Risk Exposure</span>
            <span class="metric-value" style="color: #FFB020;">{high_p}</span>
            <span style="font-size: 0.75rem; color: #FFB020; margin-top: 4px;">RDP, DB Ports</span>
        </div>
        """))
    with col_m4:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Benign / Secure</span>
            <span class="metric-value" style="color: #00F5A0;">{low_p}</span>
            <span style="font-size: 0.75rem; color: #00F5A0; margin-top: 4px;">Encrypted Services</span>
        </div>
        """))

    st.html("<div style='margin-bottom: 20px;'></div>")

    # Search & Filter
    c_s1, c_s2 = st.columns([2, 1])
    with c_s1:
        port_search = st.text_input("Filter by Port Number, Service, or Host IP", "")
    with c_s2:
        risk_filter = st.selectbox(
            "Filter Risk Classification",
            options=["All Classifications", "Critical", "High", "Medium", "Low"]
        )

    filtered_ports = []
    for item in all_ports_list:
        if port_search:
            q = port_search.lower()
            if (q not in str(item["port"]) and
                q not in item["service"].lower() and
                q not in item["ip"].lower() and
                q not in item["hostname"].lower()):
                continue

        if risk_filter != "All Classifications" and item["risk"] != risk_filter:
            continue

        filtered_ports.append(item)

    st.markdown(f"**Showing {len(filtered_ports)} listening port instances**")
    st.html("<div style='margin-bottom: 16px;'></div>")

    # Render Port Cards
    for p in filtered_ports:
        r_class = p["risk"]
        if r_class == "Critical":
            r_badge = '<span class="badge-critical">CRITICAL PROTOCOL</span>'
            r_border = CYBER_PALETTE["critical"]
        elif r_class == "High":
            r_badge = '<span class="badge-high">HIGH RISK</span>'
            r_border = CYBER_PALETTE["warning"]
        elif r_class == "Medium":
            r_badge = '<span class="badge-medium">MEDIUM RISK</span>'
            r_border = "#F59E0B"
        else:
            r_badge = '<span class="badge-secure">OPERATIONAL / SECURE</span>'
            r_border = CYBER_PALETTE["neon_green"]

        st.html(textwrap.dedent(f"""
        <div style="background: #111C2E; border: 1px solid #1E2D4A; border-left: 4px solid {r_border}; border-radius: 8px; padding: 14px 18px; margin-bottom: 14px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                <div>
                    <span style="font-size: 1.15rem; font-weight: 700; color: #F3F7FF; font-family: monospace;">Port {p['port']}/{p['protocol']}</span>
                    <span style="color: #00D9FF; font-weight: 700; margin-left: 10px;">{p['service'].upper()}</span>
                    <span style="color: #91A3B8; font-size: 0.85rem; margin-left: 8px;">on {p['ip']} ({p['hostname']})</span>
                </div>
                <div>
                    {r_badge}
                </div>
            </div>
            <div style="color: #CBD5E1; font-size: 0.85rem; margin-bottom: 6px;">
                <b>Service Details:</b> {p['desc']}
            </div>
            <div style="font-size: 0.78rem; color: #64748B; font-family: monospace;">
                Detected Banner: {p['version']}
            </div>
        </div>
        """))
