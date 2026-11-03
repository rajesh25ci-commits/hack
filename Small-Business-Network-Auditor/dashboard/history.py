"""
NETGUARD - Page 10: Scan History
Historical audit viewer backed by SQLite with posture progression trend chart,
search, scan loading, JSON export, and record deletion.
"""

import textwrap
import streamlit as st
import json
from database import get_all_scans, get_scan, delete_scan
from dashboard.charts import create_security_trend_chart
from config import CYBER_PALETTE


def render_history_page():
    """Renders the persistent SQLite scan history interface."""
    st.html(textwrap.dedent("""
    <div class="netguard-card" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.08em; text-transform: uppercase;">
                    AUDIT TELEMETRY ARCHIVE
                </div>
                <h2 style="color: #F3F7FF; font-size: 1.55rem; font-weight: 800; margin: 2px 0 0 0;">
                    Historical Audit Archive & Progression
                </h2>
                <p style="color: #91A3B8; font-size: 0.88rem; margin-top: 4px; margin-bottom: 0;">
                    Complete historical record of all diagnostic network assessments stored locally in SQLite.
                </p>
            </div>
            <div>
                <span class="badge-commander">SQLite Archive</span>
            </div>
        </div>
    </div>
    """))

    all_scans = get_all_scans()
    if not all_scans:
        st.info("No scans recorded in history. Run an audit on the Network Scanner page.")
        return

    # Posture Trend Chart over Historical Audits
    with st.container(border=True):
        st.markdown("#### 📈 Historical Network Posture Trend")
        st.caption("Chronological progression of network hygiene scores across your audits.")
        fig_trend = create_security_trend_chart(all_scans)
        st.plotly_chart(fig_trend, use_container_width=True)

    # Search Bar
    search_q = st.text_input("🔍 Search history by Target Network or Scan ID", "")

    filtered_scans = []
    for s in all_scans:
        if search_q:
            q = search_q.lower()
            if q not in s["target"].lower() and q not in s["scan_id"].lower():
                continue
        filtered_scans.append(s)

    st.markdown(f"**Found {len(filtered_scans)} historical audit(s)**")
    st.html("<div style='margin-bottom: 16px;'></div>")

    for s in filtered_scans:
        s_id = s["scan_id"]
        target = s["target"]
        time_str = s["scan_time"][:19].replace("T", " ")
        mode = s.get("scan_mode", "real").capitalize()
        devices_cnt = s["total_devices"]
        ports_cnt = s["total_open_ports"]
        findings_cnt = s["total_findings"]
        score = s["risk_score"]

        score_color = CYBER_PALETTE["neon_green"] if score >= 85 else (
            CYBER_PALETTE["warning"] if score >= 60 else CYBER_PALETTE["critical"]
        )
        mode_badge = '<span class="badge-simulated">Demo Mode</span>' if mode.lower() == "simulated" else '<span class="badge-secure">Live Real Scan</span>'

        with st.container():
            st.html(textwrap.dedent(f"""
            <div style="background: #111C2E; border: 1px solid #1E2D4A; border-radius: 10px; padding: 18px 22px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px;">
                    <div>
                        <span style="font-size: 0.8rem; color: #00D9FF; font-family: monospace;">{s_id}</span>
                        <h4 style="color: #F3F7FF; font-size: 1.2rem; font-weight: 800; margin: 2px 0;">{target}</h4>
                        <span style="color: #91A3B8; font-size: 0.82rem;">Audit Timestamp: {time_str}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 16px;">
                        <div style="text-align: right;">
                            <span style="font-size: 0.75rem; color: #91A3B8; text-transform: uppercase; font-weight: 600;">Hygiene Score</span>
                            <div style="font-size: 1.45rem; font-weight: 800; color: {score_color}; font-family: monospace;">{score}/100</div>
                        </div>
                        {mode_badge}
                    </div>
                </div>
                <div style="margin-top: 10px; font-size: 0.85rem; color: #CBD5E1; display: flex; gap: 20px;">
                    <span>🖥️ <b>{devices_cnt}</b> Hosts Discovered</span>
                    <span>🔌 <b>{ports_cnt}</b> Open Ports</span>
                    <span>⚠️ <b>{findings_cnt}</b> Findings</span>
                </div>
            </div>
            """))

            col_btn1, col_btn2, col_btn3 = st.columns([1, 1, 1])
            with col_btn1:
                if st.button("📂 Load into Dashboard", key=f"load_h_{s_id}", use_container_width=True):
                    full_scan = get_scan(s_id)
                    if full_scan:
                        st.session_state["active_scan"] = full_scan
                        st.session_state["current_page"] = "Dashboard"
                        st.rerun()

            with col_btn2:
                full_scan_data = get_scan(s_id)
                if full_scan_data:
                    json_str = json.dumps(full_scan_data, indent=2)
                    st.download_button(
                        label="📥 Export JSON",
                        data=json_str,
                        file_name=f"netguard_{s_id}.json",
                        mime="application/json",
                        key=f"dl_json_{s_id}",
                        use_container_width=True
                    )

            with col_btn3:
                if st.button("🗑️ Delete Record", key=f"del_h_{s_id}", use_container_width=True):
                    delete_scan(s_id)
                    if st.session_state.get("active_scan", {}).get("scan_id") == s_id:
                        st.session_state["active_scan"] = None
                    st.success(f"Audit {s_id} deleted.")
                    st.rerun()
