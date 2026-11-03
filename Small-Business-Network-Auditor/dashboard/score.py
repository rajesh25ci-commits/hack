"""
NETGUARD - Page 9: Security Score
Transparent risk scoring calculation with interactive gauge,
mathematical deduction ledger, and defensive hygiene explanation.
"""

import textwrap
import streamlit as st
import plotly.graph_objects as go
from database import get_latest_scan
from security_analysis import calculate_security_score
from config import RISK_DEDUCTIONS, SCORE_TIERS, CYBER_PALETTE


def render_score_page():
    """Renders the transparent Security Score breakdown."""
    active_scan = st.session_state.get("active_scan")
    if not active_scan:
        active_scan = get_latest_scan()
        if active_scan:
            st.session_state["active_scan"] = active_scan

    if not active_scan:
        st.info("No audit active. Please run a scan from the Network Scanner page first.")
        return

    findings = active_scan.get("findings", [])
    devices = active_scan.get("devices", [])
    score_data = calculate_security_score(findings, total_devices=len(devices))
    score = score_data["score"]
    category = score_data["category"]
    color = score_data["color"]

    st.html(textwrap.dedent("""
    <div class="netguard-card" style="margin-bottom: 20px;">
        <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
            <div>
                <div style="font-size: 0.78rem; font-weight: 700; color: #00D9FF; letter-spacing: 0.08em; text-transform: uppercase;">
                    TRANSPARENT HYGIENE METRIC
                </div>
                <h2 style="color: #F3F7FF; font-size: 1.55rem; font-weight: 800; margin: 2px 0 0 0;">
                    Network Security Posture Score
                </h2>
                <p style="color: #91A3B8; font-size: 0.88rem; margin-top: 4px; margin-bottom: 0;">
                    A mathematical 0-to-100 hygiene index computed directly from confirmed open port exposures and vulnerabilities.
                </p>
            </div>
            <div>
                <span class="badge-commander">Deterministic Scoring</span>
            </div>
        </div>
    </div>
    """))

    c_g1, c_g2 = st.columns([1.2, 1])

    with c_g1:
        with st.container(border=True):
            # Interactive Plotly Gauge
            fig = go.Figure(go.Indicator(
                mode="gauge+number",
                value=score,
                title={'text': f"Calculated Posture: {category.upper()}", 'font': {'color': color, 'size': 16, 'family': 'Plus Jakarta Sans'}},
                number={'suffix': "/100", 'font': {'color': "#F3F7FF", 'size': 36, 'family': 'JetBrains Mono'}},
                gauge={
                    'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#2A3B58"},
                    'bar': {'color': color, 'thickness': 0.28},
                    'bgcolor': CYBER_PALETTE["card_bg"],
                    'borderwidth': 1,
                    'bordercolor': "#1F314D",
                    'steps': [
                        {'range': [0, 50], 'color': 'rgba(255, 69, 96, 0.35)'},
                        {'range': [50, 75], 'color': 'rgba(255, 176, 32, 0.35)'},
                        {'range': [75, 90], 'color': 'rgba(0, 217, 255, 0.30)'},
                        {'range': [90, 100], 'color': 'rgba(0, 245, 160, 0.35)'}
                    ]
                }
            ))
            fig.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=20, r=20, t=30, b=10),
                height=260
            )
            st.plotly_chart(fig, use_container_width=True)

    with c_g2:
        st.html(textwrap.dedent(f"""
        <div class="netguard-card" style="height: 290px; display: flex; flex-direction: column; justify-content: space-between;">
            <div>
                <span class="metric-label">Category Evaluation</span>
                <div style="font-size: 1.45rem; font-weight: 800; color: {color}; margin-bottom: 8px;">
                    {score_data.get('badge')}
                </div>
                <p style="color: #CBD5E1; font-size: 0.9rem; line-height: 1.5; margin-bottom: 12px;">
                    {score_data.get('description')}
                </p>
                <div style="font-size: 0.82rem; color: #91A3B8; background: #070B14; padding: 12px; border-radius: 8px; border: 1px solid #1E2D4A;">
                    {score_data.get('summary_explanation')}
                </div>
            </div>
            <div style="font-size: 0.72rem; color: #64748B; font-style: italic;">
                * {score_data.get('disclaimer')}
            </div>
        </div>
        """))

    st.html("<div style='margin-bottom: 16px;'></div>")

    # Deduction Ledger Table
    with st.container(border=True):
        st.markdown("#### 🧮 Point Deduction Breakdown & Formula")

        breakdown = score_data["breakdown"]
        crit_b = breakdown["Critical"]
        high_b = breakdown["High"]
        med_b = breakdown["Medium"]
        low_b = breakdown["Low"]

        ledger_rows = [
            {"Severity Tier": "Baseline Starting Score", "Weight per Issue": "-", "Detected Issues": "-", "Impact Points": "+100"},
            {"Severity Tier": "Critical Risks (Telnet, Unprotected DBs)", "Weight per Issue": f"-{RISK_DEDUCTIONS['Critical']} pts (Capped at -60)", "Detected Issues": crit_b["count"], "Impact Points": f"-{crit_b['deduction']}"},
            {"Severity Tier": "High Risks (Cleartext FTP, SMBv1, RDP, VNC)", "Weight per Issue": f"-{RISK_DEDUCTIONS['High']} pts (Capped at -45)", "Detected Issues": high_b["count"], "Impact Points": f"-{high_b['deduction']}"},
            {"Severity Tier": "Medium Warnings (Plain HTTP Admin)", "Weight per Issue": f"-{RISK_DEDUCTIONS['Medium']} pts (Capped at -30)", "Detected Issues": med_b["count"], "Impact Points": f"-{med_b['deduction']}"},
            {"Severity Tier": "Low Warnings (Excessive Open Ports)", "Weight per Issue": f"-{RISK_DEDUCTIONS['Low']} pts (Capped at -15)", "Detected Issues": low_b["count"], "Impact Points": f"-{low_b['deduction']}"},
            {"Severity Tier": "Final Calculated Security Score", "Weight per Issue": "-", "Detected Issues": len(findings), "Impact Points": f"{score}/100"}
        ]
        st.table(ledger_rows)

    # Score Categories Reference Table
    with st.container(border=True):
        st.markdown("#### 🛡️ Standard Hygiene Score Tiers")

        tier_cols = st.columns(4)
        for idx, (t_name, t_val) in enumerate(SCORE_TIERS.items()):
            with tier_cols[idx]:
                st.html(textwrap.dedent(f"""
                <div style="background: #0D1422; border: 1px solid #1E2D4A; border-top: 3px solid {t_val['color']}; border-radius: 8px; padding: 14px;">
                    <div style="font-weight: 700; color: {t_val['color']}; font-size: 0.95rem;">{t_val['badge']}</div>
                    <div style="font-size: 1.25rem; font-weight: 800; color: #F3F7FF; margin: 4px 0;">{t_val['min']} – {t_val['max']}</div>
                    <div style="font-size: 0.75rem; color: #91A3B8; line-height: 1.4;">{t_val['desc']}</div>
                </div>
                """))
