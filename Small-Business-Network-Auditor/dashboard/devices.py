"""
NETGUARD - Page 4: Device Discovery
Interactive inventory of discovered network assets with search,
filtering, sorting, granular device inspection, and XP rewards.
"""

import textwrap
import streamlit as st
import ipaddress
from database import get_latest_scan, award_xp
from config import CYBER_PALETTE


def render_devices_page():
    """Renders the device discovery asset inventory."""
    active_scan = st.session_state.get("active_scan")
    if not active_scan:
        active_scan = get_latest_scan()
        if active_scan:
            st.session_state["active_scan"] = active_scan

    if not active_scan:
        st.info("No audit active. Please run a scan from the Network Scanner page first.")
        if st.button("Go to Scanner"):
            st.session_state["current_page"] = "Network Scanner"
            st.rerun()
        return

    devices = active_scan.get("devices", [])
    findings = active_scan.get("findings", [])
    scan_id = active_scan.get("scan_id", "N/A")

    # Award XP for reviewing device inventory (prevent duplicates)
    if devices:
        award_xp("DEVICE_MATRIX_REVIEWED", scan_id, 30, f"Reviewed {len(devices)} discovered hosts")

    st.html(textwrap.dedent("""
    <div class="netguard-card" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.08em; text-transform: uppercase;">
                    MISSION 01: ASSET MATRIX RECONNAISSANCE
                </div>
                <h2 style="color: #F3F7FF; font-size: 1.55rem; font-weight: 800; margin: 2px 0 0 0;">
                    Network Asset Discovery Inventory
                </h2>
                <p style="color: #91A3B8; font-size: 0.88rem; margin-top: 4px; margin-bottom: 0;">
                    Complete inventory of all responding endpoints across your audited subnet with MAC physical addresses and listening services.
                </p>
            </div>
            <div>
                <span class="badge-commander">Inventory Asset Matrix</span>
            </div>
        </div>
    </div>
    """))

    # Search & Filter Controls
    c_srch, c_fltr, c_sort = st.columns([2, 1, 1])

    with c_srch:
        search_query = st.text_input("🔍 Search devices by IP, Hostname, or Service", "")

    with c_fltr:
        risk_filter = st.selectbox(
            "Filter by Risk",
            options=["All Devices", "Critical Only", "High Only", "Medium / Low Only", "Secure Only"]
        )

    with c_sort:
        sort_by = st.selectbox(
            "Sort By",
            options=["IP Address", "Open Ports (Descending)", "Hostname"]
        )

    # Compute risk per device
    device_risk_map = {}
    for dev in devices:
        dev_ip = dev["ip"]
        dev_findings = [f for f in findings if f.get("device_ip") == dev_ip]
        if any(f.get("severity") == "Critical" for f in dev_findings):
            device_risk_map[dev_ip] = "Critical"
        elif any(f.get("severity") == "High" for f in dev_findings):
            device_risk_map[dev_ip] = "High"
        elif any(f.get("severity") == "Medium" for f in dev_findings):
            device_risk_map[dev_ip] = "Medium"
        elif any(f.get("severity") == "Low" for f in dev_findings):
            device_risk_map[dev_ip] = "Low"
        else:
            device_risk_map[dev_ip] = "Secure"

    # Filter devices
    filtered_devices = []
    for d in devices:
        ip = d.get("ip", "")
        hostname = d.get("hostname", "")
        services_str = " ".join(d.get("services_summary", []))
        risk = device_risk_map.get(ip, "Secure")

        if search_query:
            q = search_query.lower()
            if q not in ip.lower() and q not in hostname.lower() and q not in services_str.lower():
                continue

        if risk_filter == "Critical Only" and risk != "Critical":
            continue
        elif risk_filter == "High Only" and risk != "High":
            continue
        elif risk_filter == "Medium / Low Only" and risk not in ["Medium", "Low"]:
            continue
        elif risk_filter == "Secure Only" and risk != "Secure":
            continue

        filtered_devices.append(d)

    # Sort devices
    if sort_by == "IP Address":
        try:
            filtered_devices.sort(key=lambda d: ipaddress.IPv4Address(d["ip"]))
        except Exception:
            filtered_devices.sort(key=lambda d: d.get("ip", ""))
    elif sort_by == "Open Ports (Descending)":
        filtered_devices.sort(key=lambda d: len(d.get("open_ports", [])), reverse=True)
    elif sort_by == "Hostname":
        filtered_devices.sort(key=lambda d: d.get("hostname", ""))

    st.markdown(f"**Displaying {len(filtered_devices)} of {len(devices)} discovered hosts**")
    st.html("<div style='margin-bottom: 16px;'></div>")

    if not filtered_devices:
        st.warning("No devices matched your search or filter criteria.")
        return

    # Render Device Cards
    for d in filtered_devices:
        ip = d.get("ip")
        hostname = d.get("hostname", "Unknown Host")
        mac = d.get("mac") or "Unknown / Virtual Interface"
        status = d.get("status", "online").upper()
        open_ports = d.get("open_ports", [])
        risk = device_risk_map.get(ip, "Secure")

        if risk == "Critical":
            risk_badge = '<span class="badge-critical">CRITICAL RISK</span>'
            border_color = "rgba(255, 69, 96, 0.45)"
        elif risk == "High":
            risk_badge = '<span class="badge-high">HIGH RISK</span>'
            border_color = "rgba(255, 176, 32, 0.45)"
        elif risk == "Medium":
            risk_badge = '<span class="badge-medium">MEDIUM RISK</span>'
            border_color = "rgba(245, 158, 11, 0.45)"
        elif risk == "Low":
            risk_badge = '<span class="badge-low">LOW RISK</span>'
            border_color = "rgba(0, 217, 255, 0.45)"
        else:
            risk_badge = '<span class="badge-secure">SECURE BASELINE</span>'
            border_color = "rgba(0, 245, 160, 0.45)"

        with st.expander(f"🖥️ {ip} — {hostname} ({len(open_ports)} Open Ports) | {risk}", expanded=False):
            st.html(textwrap.dedent(f"""
            <div style="background: #0D1422; padding: 14px 18px; border-radius: 8px; border: 1px solid {border_color}; margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <div>
                        <span style="font-size: 1.15rem; font-weight: 700; color: #F3F7FF; font-family: monospace;">{ip}</span>
                        <span style="color: #91A3B8; margin-left: 8px;">({hostname})</span>
                    </div>
                    <div>
                        {risk_badge}
                    </div>
                </div>
                <div style="font-size: 0.85rem; color: #91A3B8;">
                    <b>MAC Address:</b> <span style="font-family: monospace; color: #00D9FF;">{mac}</span> &nbsp;|&nbsp; 
                    <b>Status:</b> <span style="color: #00F5A0; font-weight: 700;">{status}</span>
                </div>
            </div>
            """))

            # Ports sub-table
            if open_ports:
                st.markdown("##### Listening TCP Ports & Services")
                port_rows = []
                for p in open_ports:
                    port_rows.append({
                        "Port": f"{p['port']}/tcp",
                        "Service": p.get("service", "N/A"),
                        "Version / Banner Details": p.get("version") or "Standard Service Listener"
                    })
                st.table(port_rows)
            else:
                st.info("No open TCP ports detected within the audited preset.")

            # Associated Security Findings
            dev_findings = [f for f in findings if f.get("device_ip") == dev_ip or f.get("ip") == ip]
            if dev_findings:
                st.markdown("##### Security Findings on this Device")
                for f in dev_findings:
                    f_sev = f.get("severity", "Low")
                    sev_col = "#FF4560" if f_sev == "Critical" else ("#FFB020" if f_sev == "High" else "#00D9FF")
                    st.markdown(f"- <b style='color:{sev_col}'>[{f_sev}]</b> **{f.get('title')}** (Port {f.get('port')}): {f.get('explanation')}", unsafe_allow_html=True)
            else:
                st.success("No security findings recorded for this device.")
