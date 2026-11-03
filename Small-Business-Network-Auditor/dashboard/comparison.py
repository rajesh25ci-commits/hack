"""
NETGUARD - Page 11: Before and After Comparison
Allows users to compare two audits to detect score progression,
remediated vulnerabilities, and newly appearing risks.
"""

import textwrap
import streamlit as st
import plotly.graph_objects as go
from database import get_all_scans, compare_scans
from config import CYBER_PALETTE


def render_comparison_page():
    """Renders the side-by-side audit comparison interface."""
    st.html(textwrap.dedent("""
    <div class="netguard-card" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.08em; text-transform: uppercase;">
                    HISTORICAL DELTA ANALYSIS
                </div>
                <h2 style="color: #F3F7FF; font-size: 1.55rem; font-weight: 800; margin: 2px 0 0 0;">
                    Before & After Audit Comparison
                </h2>
                <p style="color: #91A3B8; font-size: 0.88rem; margin-top: 4px; margin-bottom: 0;">
                    Measure remediation impact across time. Compare a baseline audit with follow-up scans to verify closed ports.
                </p>
            </div>
            <div>
                <span class="badge-commander">Comparative Delta</span>
            </div>
        </div>
    </div>
    """))

    all_scans = get_all_scans()
    if len(all_scans) < 2:
        st.info("At least two network audits are required in database history to perform a side-by-side comparison.")
        st.html(textwrap.dedent("""
        <div class="netguard-card">
            <b>How to use Before & After Comparison:</b><br/>
            1. Run an initial baseline scan (or run the Simulated Demo).<br/>
            2. Resolve or close ports, or run another audit.<br/>
            3. Return here to inspect the quantified improvement!
        </div>
        """))
        return

    # Selectors for Scan A (Baseline) and Scan B (Follow-up)
    scan_options = {
        f"{s['scan_id']} ({s['target']} - Score: {s['risk_score']}) [{s['scan_time'][:16]}]": s["scan_id"]
        for s in all_scans
    }

    c_sel1, c_sel2 = st.columns(2)
    with c_sel1:
        choice_a = st.selectbox(
            "Select Baseline Audit (Scan A - Earlier)",
            options=list(scan_options.keys()),
            index=min(1, len(scan_options) - 1)
        )
    with c_sel2:
        choice_b = st.selectbox(
            "Select Follow-Up Audit (Scan B - Current)",
            options=list(scan_options.keys()),
            index=0
        )

    scan_id_a = scan_options[choice_a]
    scan_id_b = scan_options[choice_b]

    if scan_id_a == scan_id_b:
        st.warning("Please select two distinct scans to compare changes.")
        return

    try:
        diff_data = compare_scans(scan_id_a, scan_id_b)
    except Exception as e:
        st.error(f"Comparison error: {str(e)}")
        return

    scan_a = diff_data["scan_a"]
    scan_b = diff_data["scan_b"]
    score_diff = diff_data["score_diff"]
    device_diff = diff_data["device_diff"]
    ports_diff = diff_data["ports_diff"]
    new_risks = diff_data["new_risks"]
    resolved_risks = diff_data["resolved_risks"]

    # Metric Delta Row
    col_d1, col_d2, col_d3, col_d4 = st.columns(4)

    with col_d1:
        s_col = CYBER_PALETTE["neon_green"] if score_diff > 0 else (CYBER_PALETTE["critical"] if score_diff < 0 else "#FFFFFF")
        delta_col = CYBER_PALETTE["neon_green"] if score_diff >= 0 else CYBER_PALETTE["critical"]
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Score Progression</span>
            <div style="font-size: 1.55rem; font-weight: 800; font-family: monospace; color: {s_col};">
                {scan_a['risk_score']} ➔ {scan_b['risk_score']}
            </div>
            <span style="font-size: 0.8rem; font-weight: 700; color: {delta_col};">
                {'+' if score_diff > 0 else ''}{score_diff} pts
            </span>
        </div>
        """))

    with col_d2:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Remediated Risks</span>
            <span class="metric-value" style="color: #00F5A0;">{len(resolved_risks)}</span>
            <span style="font-size: 0.75rem; color: #91A3B8;">Fixed Vulnerabilities</span>
        </div>
        """))

    with col_d3:
        new_col = CYBER_PALETTE["critical"] if len(new_risks) > 0 else CYBER_PALETTE["neon_green"]
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">New Exposures</span>
            <span class="metric-value" style="color: {new_col};">{len(new_risks)}</span>
            <span style="font-size: 0.75rem; color: #91A3B8;">Newly Detected Threats</span>
        </div>
        """))

    with col_d4:
        st.html(textwrap.dedent(f"""
        <div class="metric-container">
            <span class="metric-label">Open Ports Delta</span>
            <div style="font-size: 1.55rem; font-weight: 800; font-family: monospace; color: #F3F7FF;">
                {scan_a['total_open_ports']} ➔ {scan_b['total_open_ports']}
            </div>
            <span style="font-size: 0.75rem; color: #91A3B8;">
                {'+' if ports_diff > 0 else ''}{ports_diff} Net Ports
            </span>
        </div>
        """))

    st.html("<div style='margin-bottom: 20px;'></div>")

    # Plotly Side-by-Side Severity Comparison
    with st.container(border=True):
        st.markdown("#### 📊 Risk Severity Delta: Scan A vs Scan B")

        severities = ["Critical", "High", "Medium", "Low"]
        counts_a = [sum(1 for f in scan_a["findings"] if f.get("severity") == s) for s in severities]
        counts_b = [sum(1 for f in scan_b["findings"] if f.get("severity") == s) for s in severities]

        fig = go.Figure(data=[
            go.Bar(name='Scan A (Earlier Baseline)', x=severities, y=counts_a, marker_color='#8B5CF6'),
            go.Bar(name='Scan B (Follow-up Audit)', x=severities, y=counts_b, marker_color='#00D9FF')
        ])
        fig.update_layout(
            barmode='group',
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            legend=dict(font=dict(color="#E2E8F0")),
            xaxis=dict(color="#91A3B8"),
            yaxis=dict(showgrid=True, gridcolor="#17243A", color="#91A3B8"),
            margin=dict(l=10, r=10, t=20, b=10),
            height=260
        )
        st.plotly_chart(fig, use_container_width=True)

    # Detailed Delta Lists: Resolved Risks & New Risks
    c_res, c_new = st.columns(2)

    with c_res:
        with st.container(border=True):
            st.markdown(f"#### ✅ Remediated Weaknesses ({len(resolved_risks)})")
            if resolved_risks:
                for r in resolved_risks:
                    st.html(textwrap.dedent(f"""
                    <div style="background: rgba(0, 245, 160, 0.08); border-left: 3px solid #00F5A0; padding: 10px 14px; border-radius: 6px; margin-bottom: 8px;">
                        <b style="color: #00F5A0;">[FIXED] {r.get('title')}</b><br/>
                        <span style="font-size: 0.8rem; color: #91A3B8;">Host: {r.get('device_ip')} (Port {r.get('port')})</span>
                    </div>
                    """))
            else:
                st.caption("No previously active findings were closed between these audits.")

    with c_new:
        with st.container(border=True):
            st.markdown(f"#### ⚠️ Newly Emerging Exposures ({len(new_risks)})")
            if new_risks:
                for n in new_risks:
                    st.html(textwrap.dedent(f"""
                    <div style="background: rgba(255, 69, 96, 0.08); border-left: 3px solid #FF4560; padding: 10px 14px; border-radius: 6px; margin-bottom: 8px;">
                        <b style="color: #FF4560;">[NEW] {n.get('title')}</b><br/>
                        <span style="font-size: 0.8rem; color: #91A3B8;">Host: {n.get('device_ip')} (Port {n.get('port')})</span>
                    </div>
                    """))
            else:
                st.caption("Zero new vulnerabilities introduced since baseline scan.")
