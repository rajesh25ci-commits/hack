"""
NETGUARD - Page 3: Network Scanner Console
Interactive tactical scanner module:
- Target network input with CIDR helper pills & authorization confirmation
- Real & simulated scanning modes
- Animated radar scanning console and live status logs
- Discovered device cards with IP, Hostname, MAC, Open Ports & Services
- Automatic XP rewards for scan completion & device discovery
"""

import textwrap
import streamlit as st
from datetime import datetime
from config import PORT_PRESETS, CYBER_PALETTE
from network_scanner import (
    validate_target_subnet,
    get_local_ip_and_subnet,
    discover_devices,
    generate_simulated_devices,
    scan_network_ports,
    is_nmap_available
)
from security_analysis import (
    analyze_network_security,
    calculate_security_score
)
from database import save_scan, award_xp


def render_scanner_page():
    """Renders the tactical Network Scanner mission interface."""
    st.html(textwrap.dedent("""
    <div class="netguard-card" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.08em; text-transform: uppercase;">
                    MISSION 01: GRID RECON & SUBMISSION AUDIT
                </div>
                <h2 style="color: #F3F7FF; font-size: 1.55rem; font-weight: 800; margin: 2px 0 0 0;">
                    Target Network Scanner & Auditor
                </h2>
                <p style="color: #91A3B8; font-size: 0.88rem; margin-top: 4px; margin-bottom: 0;">
                    Deploy non-intrusive network probes across your authorized private subnet to discover active hosts and listening services.
                </p>
            </div>
            <div>
                <span class="badge-commander">Tactical Scanner v2.0</span>
            </div>
        </div>
    </div>
    """))

    # Local IP & Engine Info Box
    local_ip, suggested_subnet = get_local_ip_and_subnet()
    nmap_status = "Enhanced Nmap Engine" if is_nmap_available() else "Native Python Socket Engine"

    col_info1, col_info2, col_info3 = st.columns([1, 1, 1])
    with col_info1:
        st.html(textwrap.dedent(f"""
        <div class="metric-container" style="padding: 12px 16px;">
            <span class="metric-label">Active Host Interface</span>
            <div style="font-size: 1.15rem; font-weight: 700; color: #00D9FF; font-family: monospace;">{local_ip}</div>
            <span style="font-size: 0.72rem; color: #91A3B8;">Suggested CIDR: {suggested_subnet}</span>
        </div>
        """))

    with col_info2:
        st.html(textwrap.dedent(f"""
        <div class="metric-container" style="padding: 12px 16px;">
            <span class="metric-label">Probing Engine</span>
            <div style="font-size: 1.15rem; font-weight: 700; color: #00F5A0;">{nmap_status}</div>
            <span style="font-size: 0.72rem; color: #91A3B8;">RFC 1918 Private Scopes</span>
        </div>
        """))

    with col_info3:
        st.html(textwrap.dedent("""
        <div class="metric-container" style="padding: 12px 16px;">
            <span class="metric-label">Mission Reward</span>
            <div style="font-size: 1.15rem; font-weight: 700; color: #8B5CF6;">+100 Commander XP</div>
            <span style="font-size: 0.72rem; color: #00D9FF;">Per Unique Completed Audit</span>
        </div>
        """))

    st.html("<div style='margin-bottom: 20px;'></div>")

    # Scan Configuration Form
    with st.form("netguard_scan_form"):
        st.markdown("#### ⚡ Mission Parameters")

        col_t1, col_t2 = st.columns([2, 1])
        with col_t1:
            target_input = st.text_input(
                "Target IPv4 Address or CIDR Subnet",
                value=suggested_subnet if suggested_subnet != "127.0.0.1/32" else "127.0.0.1",
                help="Example: 192.168.1.0/24 or a single IP like 192.168.1.105 or 127.0.0.1"
            )

        with col_t2:
            scan_mode = st.selectbox(
                "Audit Mode",
                options=["Real Network Scan", "Simulated Demo Network (Retail POS/SMB)"],
                help="Select Simulated Demo if you wish to inspect realistic SMB vulnerabilities without scanning a live network."
            )

        preset_choice = st.selectbox(
            "Port Audit Profile",
            options=list(PORT_PRESETS.keys()),
            index=0,
            help="Select preset port range for the audit."
        )

        st.html("<div style='margin-bottom: 12px;'></div>")

        # Mandatory Authorization Checkbox
        st.html(textwrap.dedent("""
        <div style="background: rgba(255, 69, 96, 0.08); border: 1px solid rgba(255, 69, 96, 0.3); border-radius: 8px; padding: 12px 16px; margin-bottom: 12px;">
            <p style="color: #FF4560; font-size: 0.82rem; margin: 0; line-height: 1.4;">
                🛡️ <b>Defensive Rules of Engagement:</b> Network auditing generates diagnostic probe packets.
                You must strictly audit only private infrastructure owned by your business or for which you have explicit written authorization.
            </p>
        </div>
        """))

        auth_confirmed = st.checkbox(
            "I confirm that I own or am explicitly authorized by management to audit this private network range.",
            value=False
        )

        submitted = st.form_submit_button("⚡ DEPLOY NETWORK SCAN MISSION", use_container_width=True)

    # Check for auto-trigger from demo button
    if st.session_state.get("auto_load_demo", False):
        st.session_state["auto_load_demo"] = False
        submitted = True
        auth_confirmed = True
        scan_mode = "Simulated Demo Network (Retail POS/SMB)"
        target_input = "192.168.1.0/24"
        preset_choice = list(PORT_PRESETS.keys())[0]

    if submitted:
        if not auth_confirmed:
            st.error("Audit halted: You must check the authorization confirmation box before initiating a scan.")
            return

        is_demo = "Simulated Demo" in scan_mode

        # Validate Target Subnet
        if not is_demo:
            is_valid, normalized_target, error_msg = validate_target_subnet(target_input)
            if not is_valid:
                st.error(f"Target Validation Error: {error_msg}")
                return
            target_to_scan = normalized_target
        else:
            target_to_scan = target_input.strip() or "192.168.1.0/24"

        ports_to_scan = PORT_PRESETS[preset_choice]

        # Scan Visualizer Panel
        with st.container(border=True):
            st.markdown("##### 📡 Active Radar Sensor Sweep")
            st.html(textwrap.dedent("""
            <div style="text-align: center; padding: 14px 0 10px 0;">
                <div class="radar-box">
                    <div class="radar-crosshair"></div>
                    <div class="radar-crosshair-v"></div>
                    <div class="radar-sweep-beam"></div>
                </div>
            </div>
            """))

            progress_bar = st.progress(0.0)
            status_text = st.empty()

        def update_progress(val: float, msg: str):
            progress_bar.progress(val)
            status_text.markdown(f"**Console Log:** `{msg}`")

        try:
            update_progress(0.05, "Initializing defensive network audit...")

            if is_demo:
                update_progress(0.30, "Synthesizing realistic SMB network telemetry (POS Register, Core Gateway, NAS)...")
                devices = generate_simulated_devices(target=target_to_scan)
                update_progress(0.60, "Device telemetry synthesized with realistic banner signatures...")
            else:
                update_progress(0.15, f"Discovering online devices on subnet {target_to_scan}...")
                devices = discover_devices(target_to_scan, progress_callback=update_progress)

                if not devices:
                    update_progress(0.40, "No remote hosts responded to ICMP/probe. Probing target directly...")
                    devices = [{
                        "ip": target_to_scan.split("/")[0],
                        "hostname": "local-host",
                        "mac": None,
                        "status": "online",
                        "open_ports": [],
                        "services_summary": []
                    }]

                update_progress(0.50, f"Scanning {len(ports_to_scan)} TCP ports across {len(devices)} device(s)...")
                devices = scan_network_ports(devices, ports_to_scan, progress_callback=update_progress)

            # Security Analysis
            update_progress(0.80, "Running deterministic security rule engine on scan evidence...")
            findings, recommendations = analyze_network_security(devices)

            # Risk Scoring
            update_progress(0.90, "Calculating indicative risk score and category...")
            score_data = calculate_security_score(findings, total_devices=len(devices))

            # Assemble Common JSON Structure
            scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
            scan_payload = {
                "scan_id": scan_id,
                "target": target_to_scan,
                "scan_time": datetime.now().isoformat(),
                "scan_mode": "simulated" if is_demo else "real",
                "devices": devices,
                "findings": findings,
                "recommendations": recommendations,
                "risk_score": score_data["score"]
            }

            # Save in SQLite
            update_progress(0.96, "Persisting audit records into SQLite database...")
            save_scan(scan_payload)

            # Award XP for genuine scan completion
            awarded = award_xp("SCAN_COMPLETED", scan_id, 100, f"Completed security scan on {target_to_scan}")
            if awarded > 0:
                award_xp("DEVICES_DISCOVERED", scan_id, 50, f"Discovered {len(devices)} hosts")
                if findings:
                    award_xp("THREATS_IDENTIFIED", scan_id, 50, f"Identified {len(findings)} security findings")

            update_progress(1.0, "Security Audit Completed Successfully!")
            st.session_state["active_scan"] = scan_payload

            st.balloons()
            st.success(f"🎉 Audit Complete! {len(devices)} device(s) evaluated. Hygiene Score: {score_data['score']}/100. (+{awarded or 100} XP Earned)")

            # Immediate Discovered Devices Preview Grid
            st.markdown("### 🖥️ Discovered Network Assets")
            d_cols = st.columns(min(3, max(1, len(devices))))
            for idx, dev in enumerate(devices):
                target_d_col = d_cols[idx % len(d_cols)]
                open_ports = dev.get("open_ports", [])
                port_count = len(open_ports)
                risk_pill = '<span class="badge-critical">Critical Exposure</span>' if any(p.get("port") in [21, 23, 445, 3306] for p in open_ports) else '<span class="badge-secure">Secured</span>'

                with target_d_col:
                    with st.container(border=True):
                        st.html(textwrap.dedent(f"""
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-size: 0.75rem; color: #00D9FF; font-family: monospace;">{dev.get('ip')}</span>
                            {risk_pill}
                        </div>
                        <h4 style="font-size: 1rem; font-weight: 700; color: #F3F7FF; margin: 0 0 6px 0;">{dev.get('hostname', 'Host')}</h4>
                        <div style="font-size: 0.75rem; color: #91A3B8; margin-bottom: 8px;">MAC: <code>{dev.get('mac', 'N/A')}</code></div>
                        <div style="font-size: 0.8rem; color: #00F5A0; font-weight: 600;">{port_count} Open Ports</div>
                        """))

            c_act1, c_act2 = st.columns(2)
            with c_act1:
                if st.button("📊 View Executive Dashboard", use_container_width=True):
                    st.session_state["current_page"] = "Dashboard"
                    st.rerun()
            with c_act2:
                if st.button("🔍 Deep Device Analysis", use_container_width=True):
                    st.session_state["current_page"] = "Device Discovery"
                    st.rerun()

        except Exception as e:
            st.error(f"Audit failed due to error: {str(e)}")
            progress_bar.empty()
            status_text.empty()
